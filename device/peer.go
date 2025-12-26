/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// peer.go - WireGuard对等体(peer)的核心实现
// 该文件包含了WireGuard对等体的结构定义和相关操作方法
// 每个对等体代表一个远程的WireGuard端点，负责处理与该端点的所有通信

package device

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Peer 代表一个WireGuard对等体，包含了与远程端点通信所需的所有状态信息
type Peer struct {
	isRunning         atomic.Bool    // 原子布尔值，标识对等体是否正在运行
	keypairs          Keypairs       // 密钥对管理器，存储当前、上一个和下一个密钥对
	handshake         Handshake      // 握手状态信息，包含Noise协议相关数据
	device            *Device        // 指向所属设备的指针
	stopping          sync.WaitGroup // 等待组，用于优雅关闭正在运行的协程
	txBytes           atomic.Uint64  // 发送到对等体的字节数统计（原子操作）
	rxBytes           atomic.Uint64  // 从对等体接收的字节数统计（原子操作）
	lastHandshakeNano atomic.Int64   // 最后一次握手的纳秒时间戳（从Unix纪元开始）

	// 端点信息结构体，包含网络连接相关配置
	endpoint struct {
		sync.Mutex                   // 保护端点配置的互斥锁
		val            conn.Endpoint // 实际的网络端点对象
		clearSrcOnTx   bool          // 标志位：在下次发送数据包前是否需要清除源地址
		disableRoaming bool          // 禁用漫游功能，阻止端点地址的自动更新
	}

	// 定时器组，管理各种网络协议定时任务
	timers struct {
		retransmitHandshake     *Timer        // 握手重传定时器
		sendKeepalive           *Timer        // 发送保活消息定时器
		newHandshake            *Timer        // 发起新握手定时器
		zeroKeyMaterial         *Timer        // 密钥材料清零定时器
		persistentKeepalive     *Timer        // 持久保活定时器
		handshakeAttempts       atomic.Uint32 // 握手尝试次数计数器（原子操作）
		needAnotherKeepalive    atomic.Bool   // 是否需要发送另一个保活消息（原子操作）
		sentLastMinuteHandshake atomic.Bool   // 是否在最后一分钟发送了握手消息（原子操作）
	}

	// 状态管理结构体
	state struct {
		sync.Mutex // 防止并发启动/停止操作的互斥锁
	}

	// 数据包队列管理结构体
	queue struct {
		staged   chan *QueueOutboundElementsContainer // 暂存队列：等待握手完成的出站数据包
		outbound *autodrainingOutboundQueue           // 出站队列：按序发送UDP数据包
		inbound  *autodrainingInboundQueue            // 入站队列：按序写入TUN设备
	}

	cookieGenerator             CookieGenerator // Cookie生成器，用于DoS防护
	trieEntries                 list.List       // 前缀树条目列表，用于路由表查找
	persistentKeepaliveInterval atomic.Uint32   // 持久保活间隔时间（秒，原子操作）
}

// NewPeer 创建一个新的对等体实例
// 参数：
//   - pk: 对等体的公钥，用于标识和加密通信
//
// 返回：
//   - *Peer: 创建的对等体实例
//   - error: 创建过程中的错误信息
func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	// 检查设备是否已关闭
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// 锁定资源以确保并发安全
	device.staticIdentity.RLock() // 读锁保护静态身份信息
	defer device.staticIdentity.RUnlock()

	device.peers.Lock() // 写锁保护对等体映射表
	defer device.peers.Unlock()

	// 检查对等体数量是否超过限制
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// 创建新的对等体实例
	peer := new(Peer)

	// 初始化Cookie生成器，用于DoS防护
	peer.cookieGenerator.Init(pk)
	peer.device = device

	// 初始化数据包队列
	peer.queue.outbound = newAutodrainingOutboundQueue(device)                      // 创建自动排空的出站队列
	peer.queue.inbound = newAutodrainingInboundQueue(device)                        // 创建自动排空的入站队列
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, QueueStagedSize) // 创建暂存队列

	// 检查公钥是否已存在于映射表中
	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// 预计算Diffie-Hellman密钥交换
	handshake := &peer.handshake
	handshake.mutex.Lock()
	// 计算本地私钥与对等体公钥的共享密钥
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk // 存储对等体的静态公钥
	handshake.mutex.Unlock()

	// 重置端点配置到初始状态
	peer.endpoint.Lock()
	peer.endpoint.val = nil              // 清空端点地址
	peer.endpoint.disableRoaming = false // 启用漫游功能
	peer.endpoint.clearSrcOnTx = false   // 不需要清除源地址
	peer.endpoint.Unlock()

	// 初始化定时器系统
	peer.timersInit()

	// 将新对等体添加到设备的映射表中
	device.peers.keyMap[pk] = peer

	return peer, nil
}

// SendBuffers 向对等体发送数据包缓冲区
// 参数：
//   - buffers: 要发送的数据包缓冲区数组
//
// 返回：
//   - error: 发送过程中的错误信息
func (peer *Peer) SendBuffers(buffers [][]byte) error {
	// 获取网络接口的读锁，防止并发修改
	peer.device.net.RLock()
	defer peer.device.net.RUnlock()

	// 检查设备是否已关闭
	if peer.device.isClosed() {
		return nil
	}

	// 获取端点信息
	peer.endpoint.Lock()
	endpoint := peer.endpoint.val
	if endpoint == nil {
		peer.endpoint.Unlock()
		return errors.New("no known endpoint for peer")
	}

	// 如果需要清除源地址，则执行清除操作
	// 这通常用于处理网络接口变更或NAT穿越场景
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	// 通过底层网络绑定发送数据包
	err := peer.device.net.bind.Send(buffers, endpoint)
	if err == nil {
		// 统计发送的总字节数
		var totalLen uint64
		for _, b := range buffers {
			totalLen += uint64(len(b))
		}
		// 原子地更新发送字节数计数器
		peer.txBytes.Add(totalLen)
	}
	return err
}

// String 返回对等体的字符串表示形式
// 生成格式为 "peer(XXXX…YYYY)" 的字符串，其中XXXX和YYYY是公钥的Base64编码的首尾片段
// 这种表示方式既保护了完整公钥信息，又便于调试和日志记录
func (peer *Peer) String() string {
	// 以下代码实现与下面注释中的代码功能相同，但性能更高：
	//
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)
	//
	// 直接进行Base64编码计算，避免了字符串分配和格式化的开销

	src := peer.handshake.remoteStatic // 获取对等体的静态公钥

	// Base64编码函数：将6位数值转换为Base64字符
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}

	// 预分配结果字符串缓冲区
	b := []byte("peer(____…____)")
	const first = len("peer(")       // 第一段Base64字符的起始位置
	const second = len("peer(____…") // 第二段Base64字符的起始位置

	// 编码公钥的前3个字节为4个Base64字符（显示在开头）
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)

	// 编码公钥的最后3个字节为4个Base64字符（显示在末尾）
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)

	return string(b)
}

// Start 启动对等体的通信处理流程
// 启动后，对等体将能够发送和接收数据包，并处理握手等协议逻辑
func (peer *Peer) Start() {
	// 不应在已关闭的设备上启动对等体
	if peer.device.isClosed() {
		return
	}

	// 防止同时进行启动/停止操作
	peer.state.Lock()
	defer peer.state.Unlock()

	// 如果对等体已经在运行，则直接返回
	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	device.log.Verbosef("%v - Starting", peer)

	// 重置协程状态
	peer.stopping.Wait() // 等待之前的停止操作完成
	peer.stopping.Add(2) // 为即将启动的两个协程添加计数

	// 重置握手状态，设置上次发送握手的时间为很久以前
	// 这样可以立即触发新的握手过程
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	// 增加加密队列的等待组计数，保持加密队列开放以供写入
	peer.device.queue.encryption.wg.Add(1)

	// 启动所有定时器
	peer.timersStart()

	// 清空入站和出站队列中的旧数据包
	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)

	// 使用设备的批处理大小，而不是绑定的批处理大小
	// 因为设备大小是批处理池的大小
	batchSize := peer.device.BatchSize()

	// 启动两个核心协程
	go peer.RoutineSequentialSender(batchSize)   // 顺序发送协程
	go peer.RoutineSequentialReceiver(batchSize) // 顺序接收协程

	// 标记对等体为运行状态
	peer.isRunning.Store(true)
}

// ZeroAndFlushAll 清零并刷新对等体的所有敏感数据
// 这个方法用于安全地清除密钥材料和握手状态，确保敏感信息不会泄露
func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// 清除所有密钥对
	keypairs := &peer.keypairs
	keypairs.Lock()
	device.DeleteKeypair(keypairs.previous)    // 删除上一个密钥对
	device.DeleteKeypair(keypairs.current)     // 删除当前密钥对
	device.DeleteKeypair(keypairs.next.Load()) // 删除下一个密钥对（原子加载）
	keypairs.previous = nil                    // 清空上一个密钥对引用
	keypairs.current = nil                     // 清空当前密钥对引用
	keypairs.next.Store(nil)                   // 清空下一个密钥对引用（原子存储）
	keypairs.Unlock()

	// 清除握手状态
	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex) // 从索引表中删除本地索引
	handshake.Clear()                              // 清除所有握手相关数据
	handshake.mutex.Unlock()

	// 刷新暂存的数据包
	peer.FlushStagedPackets()
}

// ExpireCurrentKeypairs 使当前的密钥对过期
// 通过设置发送随机数为拒绝阈值，强制触发密钥重新协商 aw-玉石俱焚玩法
func (peer *Peer) ExpireCurrentKeypairs() {
	// 清除握手状态并重置握手时间
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex) // 从索引表中删除握手索引
	handshake.Clear()                                   // 清除握手状态
	// 设置上次握手时间为很久以前，立即触发新的握手
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	// 使当前和下一个密钥对过期
	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		// 将当前密钥对的发送随机数设置为拒绝阈值，使其无法再发送消息
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		// 同样处理下一个密钥对
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

// Stop 停止对等体的通信处理流程
// 安全地关闭所有协程，清理资源，并清除敏感数据
func (peer *Peer) Stop() {
	// 防止并发的启动/停止操作
	peer.state.Lock()
	defer peer.state.Unlock()

	// 原子地检查并设置运行状态为false，如果已经停止则直接返回
	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Verbosef("%v - Stopping", peer)

	// 停止所有定时器
	peer.timersStop()

	// 向队列发送nil信号，通知RoutineSequentialSender和RoutineSequentialReceiver协程退出
	peer.queue.inbound.c <- nil  // 通知入站处理协程退出
	peer.queue.outbound.c <- nil // 通知出站处理协程退出

	// 等待所有相关协程完全停止
	peer.stopping.Wait()

	// 减少加密队列的等待组计数，表示我们不再向加密队列写入数据
	peer.device.queue.encryption.wg.Done()

	// 清零所有敏感数据并刷新队列
	peer.ZeroAndFlushAll()
}

// SetEndpointFromPacket 从接收到的数据包中设置对等体的端点地址
// 这个方法实现了WireGuard的"漫游"功能，允许对等体的IP地址发生变化
// 参数：
//   - endpoint: 从数据包中提取的新端点地址
func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	// 如果禁用了漫游功能，则不更新端点
	if peer.endpoint.disableRoaming {
		return
	}

	// 更新端点配置
	peer.endpoint.clearSrcOnTx = false // 重置源地址清除标志
	peer.endpoint.val = endpoint       // 设置新的端点地址
}

// markEndpointSrcForClearing 标记端点源地址需要在下次发送时清除
// 这个方法通常在网络接口发生变化或需要重新绑定源地址时调用
// 用于处理多网卡环境下的路由选择问题
func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()

	// 如果端点不存在，则无需处理
	if peer.endpoint.val == nil {
		return
	}

	// 设置标志位，表示在下次发送数据包前需要清除源地址
	// 这将强制系统重新选择合适的源地址进行发送
	peer.endpoint.clearSrcOnTx = true
}
