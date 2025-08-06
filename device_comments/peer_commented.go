/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device_comments

import (
	"container/list"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// Peer represents a single WireGuard peer connection
// 每个 Peer 代表一个 WireGuard 对等连接，包含了与该对等方通信所需的所有状态信息
type Peer struct {
	// 对等方运行状态，使用原子操作确保线程安全
	isRunning atomic.Bool

	// 密钥对管理，包含当前、前一个和下一个密钥对
	keypairs Keypairs

	// 握手状态管理，包含 Noise 协议握手的所有信息
	handshake Handshake

	// 指向所属设备的指针
	device *Device

	// 用于等待所有相关协程退出的 WaitGroup
	stopping sync.WaitGroup // routines pending stop

	// 发送和接收的字节数统计，使用原子操作保证并发安全
	txBytes atomic.Uint64 // bytes send to peer (endpoint)
	rxBytes atomic.Uint64 // bytes received from peer

	// 最后一次握手时间（纳秒时间戳），用于统计和调试
	lastHandshakeNano atomic.Int64 // nano seconds since epoch

	// 端点信息管理
	endpoint struct {
		sync.Mutex                    // 保护端点信息的互斥锁
		val            conn.Endpoint  // 实际的网络端点信息（IP地址和端口）
		clearSrcOnTx   bool          // 标记是否在下次发送前清除源地址
		disableRoaming bool          // 是否禁用端点漫游（动态更新端点）
	}

	// 定时器管理，WireGuard 协议需要多个定时器来处理重传、保活等
	timers struct {
		retransmitHandshake     *Timer        // 握手重传定时器
		sendKeepalive           *Timer        // 发送保活包定时器
		newHandshake            *Timer        // 新握手定时器
		zeroKeyMaterial         *Timer        // 清零密钥材料定时器
		persistentKeepalive     *Timer        // 持久保活定时器
		handshakeAttempts       atomic.Uint32 // 握手尝试次数计数
		needAnotherKeepalive    atomic.Bool   // 是否需要另一个保活包
		sentLastMinuteHandshake atomic.Bool   // 是否在最后一分钟发送了握手
	}

	// 状态管理
	state struct {
		sync.Mutex // protects against concurrent Start/Stop
		// 保护并发的启动/停止操作
	}

	// 数据包队列管理
	queue struct {
		// 握手完成前的暂存数据包队列
		staged chan *QueueOutboundElementsContainer // staged packets before a handshake is available
		// 出站数据包队列，保证 UDP 传输的顺序
		outbound *autodrainingOutboundQueue // sequential ordering of udp transmission
		// 入站数据包队列，保证 TUN 设备写入的顺序
		inbound *autodrainingInboundQueue // sequential ordering of tun writing
	}

	// Cookie 生成器，用于 WireGuard 的 DoS 保护机制
	cookieGenerator CookieGenerator

	// 该对等方在路由树中的条目列表
	trieEntries list.List

	// 持久保活间隔（秒），0 表示禁用
	persistentKeepaliveInterval atomic.Uint32
}

// NewPeer 创建一个新的对等方连接
// pk: 对等方的公钥，用于加密通信和身份验证
func (device *Device) NewPeer(pk NoisePublicKey) (*Peer, error) {
	// 检查设备是否已关闭
	if device.isClosed() {
		return nil, errors.New("device closed")
	}

	// 获取静态身份的读锁，保护设备私钥不被并发修改
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	// 获取对等方列表的写锁，保护对等方映射表的修改
	device.peers.Lock()
	defer device.peers.Unlock()

	// 检查是否超过最大对等方数量限制
	if len(device.peers.keyMap) >= MaxPeers {
		return nil, errors.New("too many peers")
	}

	// 创建新的对等方实例
	peer := new(Peer)

	// 初始化 Cookie 生成器，使用对等方公钥
	peer.cookieGenerator.Init(pk)
	peer.device = device

	// 初始化数据包队列
	peer.queue.outbound = newAutodrainingOutboundQueue(device)
	peer.queue.inbound = newAutodrainingInboundQueue(device)
	peer.queue.staged = make(chan *QueueOutboundElementsContainer, QueueStagedSize)

	// 检查公钥是否已存在，防止重复添加
	_, ok := device.peers.keyMap[pk]
	if ok {
		return nil, errors.New("adding existing peer")
	}

	// 预计算 Diffie-Hellman 共享密钥，提高握手性能
	handshake := &peer.handshake
	handshake.mutex.Lock()
	handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(pk)
	handshake.remoteStatic = pk
	handshake.mutex.Unlock()

	// 重置端点信息
	peer.endpoint.Lock()
	peer.endpoint.val = nil
	peer.endpoint.disableRoaming = false
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.Unlock()

	// 初始化定时器
	peer.timersInit()

	// 将对等方添加到设备的对等方映射表中
	device.peers.keyMap[pk] = peer

	return peer, nil
}

// SendBuffers 向对等方发送数据缓冲区
// buffers: 要发送的数据缓冲区切片
func (peer *Peer) SendBuffers(buffers [][]byte) error {
	// 获取网络接口的读锁，防止网络配置在发送过程中被修改
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
	// 如果标记了需要清除源地址，则执行清除操作
	// 这通常用于 NAT 穿越或网络接口变更的情况
	if peer.endpoint.clearSrcOnTx {
		endpoint.ClearSrc()
		peer.endpoint.clearSrcOnTx = false
	}
	peer.endpoint.Unlock()

	// 通过网络绑定发送数据
	err := peer.device.net.bind.Send(buffers, endpoint)
	if err == nil {
		// 发送成功，更新发送字节数统计
		var totalLen uint64
		for _, b := range buffers {
			totalLen += uint64(len(b))
		}
		peer.txBytes.Add(totalLen)
	}
	return err
}

// String 返回对等方的字符串表示，用于日志和调试
// 格式: peer(前4个字符…后4个字符)，例如: peer(AbCd…XyZ0)
func (peer *Peer) String() string {
	// 这里是一个高度优化的 base64 编码实现
	// 等价于以下代码，但性能更好:
	//   base64Key := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	//   abbreviatedKey := base64Key[0:4] + "…" + base64Key[39:43]
	//   return fmt.Sprintf("peer(%s)", abbreviatedKey)

	src := peer.handshake.remoteStatic
	// 自定义 base64 编码函数，避免标准库的开销
	b64 := func(input byte) byte {
		return input + 'A' + byte(((25-int(input))>>8)&6) - byte(((51-int(input))>>8)&75) - byte(((61-int(input))>>8)&15) + byte(((62-int(input))>>8)&3)
	}
	b := []byte("peer(____…____)")
	const first = len("peer(")
	const second = len("peer(____…")
	
	// 编码前4个字符
	b[first+0] = b64((src[0] >> 2) & 63)
	b[first+1] = b64(((src[0] << 4) | (src[1] >> 4)) & 63)
	b[first+2] = b64(((src[1] << 2) | (src[2] >> 6)) & 63)
	b[first+3] = b64(src[2] & 63)
	
	// 编码后4个字符
	b[second+0] = b64(src[29] & 63)
	b[second+1] = b64((src[30] >> 2) & 63)
	b[second+2] = b64(((src[30] << 4) | (src[31] >> 4)) & 63)
	b[second+3] = b64((src[31] << 2) & 63)
	
	return string(b)
}

// Start 启动对等方的所有相关协程和定时器
func (peer *Peer) Start() {
	// 不应该在已关闭的设备上启动对等方
	if peer.device.isClosed() {
		return
	}

	// 防止并发的启动/停止操作
	peer.state.Lock()
	defer peer.state.Unlock()

	// 如果已经在运行，直接返回
	if peer.isRunning.Load() {
		return
	}

	device := peer.device
	device.log.Verbosef("%v - Starting", peer)

	// 重置协程状态
	peer.stopping.Wait() // 等待之前的停止操作完成
	peer.stopping.Add(2) // 添加两个协程的计数（发送器和接收器）

	// 重置握手状态，设置最后发送握手时间为很久以前
	// 这样可以立即触发新的握手尝试
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	peer.handshake.mutex.Unlock()

	// 增加加密队列的引用计数，保持队列打开以便写入
	peer.device.queue.encryption.wg.Add(1)

	// 启动定时器
	peer.timersStart()

	// 刷新队列中的待处理数据包
	device.flushInboundQueue(peer.queue.inbound)
	device.flushOutboundQueue(peer.queue.outbound)

	// 使用设备批处理大小而不是绑定批处理大小
	// 因为设备大小是批处理池的大小
	batchSize := peer.device.BatchSize()
	
	// 启动两个主要协程：
	// 1. 顺序发送器 - 处理出站数据包的顺序发送
	go peer.RoutineSequentialSender(batchSize)
	// 2. 顺序接收器 - 处理入站数据包的顺序接收和解密
	go peer.RoutineSequentialReceiver(batchSize)

	// 标记为运行状态
	peer.isRunning.Store(true)
}

// ZeroAndFlushAll 清零并刷新对等方的所有密钥和状态
// 这是一个安全措施，确保敏感数据不会在内存中残留
func (peer *Peer) ZeroAndFlushAll() {
	device := peer.device

	// 清除所有密钥对
	keypairs := &peer.keypairs
	keypairs.Lock()
	// 删除前一个、当前和下一个密钥对
	device.DeleteKeypair(keypairs.previous)
	device.DeleteKeypair(keypairs.current)
	device.DeleteKeypair(keypairs.next.Load())
	keypairs.previous = nil
	keypairs.current = nil
	keypairs.next.Store(nil)
	keypairs.Unlock()

	// 清除握手状态
	handshake := &peer.handshake
	handshake.mutex.Lock()
	device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	handshake.mutex.Unlock()

	// 刷新暂存的数据包
	peer.FlushStagedPackets()
}

// ExpireCurrentKeypairs 使当前密钥对过期
// 这会强制进行新的握手来建立新的密钥对
func (peer *Peer) ExpireCurrentKeypairs() {
	// 清除握手状态并重置握手时间
	handshake := &peer.handshake
	handshake.mutex.Lock()
	peer.device.indexTable.Delete(handshake.localIndex)
	handshake.Clear()
	// 设置最后握手时间为很久以前，触发新握手
	peer.handshake.lastSentHandshake = time.Now().Add(-(RekeyTimeout + time.Second))
	handshake.mutex.Unlock()

	// 设置当前密钥对的发送随机数为拒绝值，使其无法继续发送
	keypairs := &peer.keypairs
	keypairs.Lock()
	if keypairs.current != nil {
		keypairs.current.sendNonce.Store(RejectAfterMessages)
	}
	if next := keypairs.next.Load(); next != nil {
		next.sendNonce.Store(RejectAfterMessages)
	}
	keypairs.Unlock()
}

// Stop 停止对等方的所有活动
func (peer *Peer) Stop() {
	// 防止并发的启动/停止操作
	peer.state.Lock()
	defer peer.state.Unlock()

	// 如果没有运行，直接返回
	// Swap 返回之前的值，并设置新值为 false
	if !peer.isRunning.Swap(false) {
		return
	}

	peer.device.log.Verbosef("%v - Stopping", peer)

	// 停止所有定时器
	peer.timersStop()
	
	// 向队列发送 nil 信号，通知 RoutineSequentialSender 和 RoutineSequentialReceiver 退出
	peer.queue.inbound.c <- nil
	peer.queue.outbound.c <- nil
	
	// 等待所有协程退出
	peer.stopping.Wait()
	
	// 减少加密队列的引用计数，表示我们不再向加密队列写入
	peer.device.queue.encryption.wg.Done()

	// 清零所有密钥和状态
	peer.ZeroAndFlushAll()
}

// SetEndpointFromPacket 从接收到的数据包中更新端点信息
// 这实现了 WireGuard 的端点漫游功能
func (peer *Peer) SetEndpointFromPacket(endpoint conn.Endpoint) {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	
	// 如果禁用了漫游，则不更新端点
	if peer.endpoint.disableRoaming {
		return
	}
	
	// 清除源地址清除标记并更新端点
	peer.endpoint.clearSrcOnTx = false
	peer.endpoint.val = endpoint
}

// markEndpointSrcForClearing 标记端点源地址需要在下次发送时清除
// 这通常在网络接口变更或 NAT 情况下使用
func (peer *Peer) markEndpointSrcForClearing() {
	peer.endpoint.Lock()
	defer peer.endpoint.Unlock()
	
	// 如果没有端点，直接返回
	if peer.endpoint.val == nil {
		return
	}
	
	// 设置清除标记
	peer.endpoint.clearSrcOnTx = true
}