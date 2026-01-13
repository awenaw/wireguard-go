/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// device.go - WireGuard设备的核心实现
// 该文件包含了WireGuard设备的主要结构定义和生命周期管理
// Device是整个WireGuard实例的核心，管理网络接口、对等体、加密队列等所有组件

package device

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/ratelimiter"
	"golang.zx2c4.com/wireguard/rwcancel"
	"golang.zx2c4.com/wireguard/tun"
)

// Device 代表一个完整的WireGuard网络设备实例
// 包含了网络绑定、对等体管理、加密处理、隧道接口等所有核心组件
type Device struct {
	// 设备状态管理结构体
	state struct {
		// state保存设备的状态，使用原子操作访问
		// 使用device.deviceState()方法读取状态
		// deviceState()不获取互斥锁，因此只捕获快照
		// 在状态转换期间，state变量在设备本身之前更新
		// 因此状态要么是设备的当前状态，要么是设备的预期未来状态
		// 例如，在执行Up调用时，state将是deviceStateUp
		// 不保证设备的预期未来状态会成为实际状态；Up可能失败
		// 设备也可能在检查时间和使用时间之间多次改变状态
		// 因此，对state的非同步使用必须仅作为咨询/尽力而为
		state atomic.Uint32 // 实际上是deviceState，但为了方便起见类型为uint32
		// stopping阻塞直到所有对Device的输入都被关闭
		stopping sync.WaitGroup
		// mu保护状态变更
		sync.Mutex
	}

	// 网络层管理结构体
	net struct {
		stopping      sync.WaitGroup     // 网络协程停止等待组
		sync.RWMutex                     // 保护网络配置的读写锁
		bind          conn.Bind          // 网络绑定接口，处理UDP通信
		netlinkCancel *rwcancel.RWCancel // 网络链路监听器取消器
		port          uint16             // 监听端口号
		fwmark        uint32             // 防火墙标记值（0表示禁用）
		brokenRoaming bool               // 是否禁用漫游功能（处理某些网络环境下的问题）
	}

	// 静态身份管理结构体，存储设备的密钥对
	staticIdentity struct {
		sync.RWMutex                 // 保护密钥对的读写锁
		privateKey   NoisePrivateKey // 设备的私钥，用于Noise协议握手
		publicKey    NoisePublicKey  // 设备的公钥，对外标识身份
	}

	// 对等体管理结构体
	peers struct {
		sync.RWMutex                          // 保护keyMap的读写锁
		keyMap       map[NoisePublicKey]*Peer // 公钥到对等体的映射表
	}

	// 速率限制管理结构体
	rate struct {
		underLoadUntil atomic.Int64            // 负载状态截止时间（纳秒时间戳）
		limiter        ratelimiter.Ratelimiter // 速率限制器，防止DoS攻击
	}

	allowedips    AllowedIPs    // 允许的IP地址范围管理器，用于路由决策
	indexTable    IndexTable    // 索引表，用于快速查找握手和会话
	cookieChecker CookieChecker // Cookie检查器，用于DoS防护

	// 内存池管理结构体，用于高效的内存分配和回收
	pool struct {
		inboundElementsContainer  *WaitPool // 入站元素容器池
		outboundElementsContainer *WaitPool // 出站元素容器池
		messageBuffers            *WaitPool // 消息缓冲区池
		inboundElements           *WaitPool // 入站元素池
		outboundElements          *WaitPool // 出站元素池
	}

	// 处理队列管理结构体
	queue struct {
		encryption *outboundQueue  // 加密处理队列，处理出站数据包的加密
		decryption *inboundQueue   // 解密处理队列，处理入站数据包的解密
		handshake  *handshakeQueue // 握手处理队列，处理协议握手消息
	}

	// TUN隧道接口管理结构体
	tun struct {
		device tun.Device   // TUN设备接口，与操作系统网络栈交互
		mtu    atomic.Int32 // 最大传输单元大小（原子操作）
	}

	ipcMutex sync.RWMutex  // IPC操作互斥锁，保护配置变更
	closed   chan struct{} // 设备关闭信号通道
	log      *Logger       // 日志记录器
}

// deviceState 表示设备的状态
// 有三种状态：down（关闭）、up（运行）、closed（已关闭）
// 状态转换图：
//
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
//
// - down: 设备已创建但未启动网络功能
// - up: 设备正在运行，可以处理网络流量
// - closed: 设备已永久关闭，无法再次启动
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown   deviceState = iota // 设备关闭状态
	deviceStateUp                        // 设备运行状态
	deviceStateClosed                    // 设备已关闭状态（不可逆）
)

// deviceState 以deviceState类型返回设备的当前状态
// 使用原子操作读取状态值，确保并发安全
// 返回值的解释请参考device.state.state的文档说明
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed 报告设备是否已关闭（或正在关闭）
// 关闭状态是不可逆的，一旦设备关闭就无法再次启动
// 状态值的解释请参考device.state.state的注释
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp 报告设备是否处于运行状态（或正在尝试启动）
// 运行状态意味着设备正在处理网络流量和协议消息
// 状态值的解释请参考device.state.state的注释
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// removePeerLocked 在持有设备对等体锁的情况下移除指定的对等体
// 必须在调用前持有 device.peers.Lock()
// 参数：
//   - device: 设备实例
//   - peer: 要移除的对等体
//   - key: 对等体的公钥
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// 停止数据包的路由和处理
	device.allowedips.RemoveByPeer(peer) // 从允许IP列表中移除该对等体的路由
	peer.Stop()                          // 停止对等体的所有处理流程

	// 从对等体映射表中移除
	delete(device.peers.keyMap, key)
}

// changeState 尝试将设备状态更改为指定的目标状态
// 这是设备状态管理的核心方法，处理所有状态转换逻辑
// 参数：
//   - want: 期望的目标设备状态
//
// 返回：
//   - error: 状态转换过程中的错误
func (device *Device) changeState(want deviceState) (err error) {
	// 获取状态锁，确保状态转换的原子性
	device.state.Lock()
	defer device.state.Unlock()

	old := device.deviceState() // 获取当前状态
	if old == deviceStateClosed {
		// 一旦关闭，永远关闭 - 这是不可逆的状态
		device.log.Verbosef("Interface closed, ignored requested state %s", want)
		return nil
	}

	// 根据目标状态执行相应的转换操作
	switch want {
	case old:
		// 目标状态与当前状态相同，无需操作
		return nil
	case deviceStateUp:
		// 尝试启动设备
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break // 启动成功
		}
		// 启动失败，继续执行down逻辑，将设备完全关闭
		fallthrough
	case deviceStateDown:
		// 关闭设备
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown // 如果之前没有错误，使用down操作的错误
		}
	}

	// 记录状态转换信息
	device.log.Verbosef("Interface state was %s, requested %s, now %s", old, want, device.deviceState())
	return
}

// upLocked 尝试启动设备并报告是否成功
// 调用者必须持有 device.state.mu 锁，并负责更新 device.state.state
// 这个方法执行设备启动的所有必要步骤
func (device *Device) upLocked() error {
	// 更新网络绑定，建立UDP套接字连接
	if err := device.BindUpdate(); err != nil {
		device.log.Errorf("Unable to update bind: %v", err)
		return err
	}

	// IPC设置操作会等待对等体创建完成后才调用Start()，
	// 所以如果有并发的IPC设置请求正在进行，我们应该等待其完成
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	// 启动所有已配置的对等体
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Start() // 启动对等体的处理流程
		// 如果配置了持久保活间隔，立即发送一个保活包
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
	return nil
}

// downLocked 尝试关闭设备
// 调用者必须持有 device.state.mu 锁，并负责更新 device.state.state
// 这个方法执行设备关闭的所有必要步骤
func (device *Device) downLocked() error {
	// 关闭网络绑定，释放UDP套接字资源
	err := device.BindClose()
	if err != nil {
		device.log.Errorf("Bind close failed: %v", err)
	}

	// 停止所有对等体的处理流程
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop() // 停止对等体，清理其资源和协程
	}
	device.peers.RUnlock()
	return err
}

// Up 启动WireGuard设备，使其开始处理网络流量
// 这是一个公共API方法，用于用户或管理工具启动设备
func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

// Down 关闭WireGuard设备，停止处理网络流量
// 这是一个公共API方法，用于用户或管理工具关闭设备
// 注意：这不是永久性关闭，设备仍可以再次启动
func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

// IsUnderLoad 检查设备是否处于高负载状态
// 高负载状态用于决定是否需要启用DoS防护机制（如Cookie检查）
// 返回值：如果设备当前正在经历或最近经历过高负载，则返回true
func (device *Device) IsUnderLoad() bool {
	// 检查当前是否处于高负载状态
	now := time.Now()
	// 如果握手队列的长度超过总容量的1/8，则认为处于高负载状态
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		// 设置高负载状态的结束时间，维持一段时间的防护状态
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// 检查是否最近处于高负载状态（在防护时间窗口内）
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

// SetPrivateKey 设置设备的私钥，这是WireGuard配置的核心操作
// 更改私钥会影响所有现有的对等体连接，需要重新计算密钥材料
// 参数：
//   - sk: 新的私钥
//
// 返回：
//   - error: 设置过程中的错误
func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// 锁定所需资源，确保操作的原子性
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	// 如果新私钥与当前私钥相同，无需更改
	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	// 锁定对等体映射表
	device.peers.Lock()
	defer device.peers.Unlock()

	// 预先锁定所有对等体的握手状态，防止并发修改
	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// 移除具有匹配公钥的对等体（避免自连接）
	publicKey := sk.publicKey() // 从私钥计算出公钥
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			// 发现对等体的公钥与我们的新公钥相同，移除该对等体
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock() // 重新获取锁以保持一致性
		}
	}

	// 更新密钥材料
	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey) // 重新初始化Cookie检查器

	// 重新计算所有对等体的静态-静态Diffie-Hellman预计算值
	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		// 重新计算共享密钥（新私钥 * 对等体公钥）
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	// 释放所有握手锁
	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}

	// 使所有对等体的当前密钥对过期，强制重新握手
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

// NewDevice 创建一个新的WireGuard设备实例
// 这是WireGuard设备的主要构造函数，初始化所有必要的组件和工作协程
// 参数：
//   - tunDevice: TUN隧道设备接口，用于与操作系统网络栈交互
//   - bind: 网络绑定接口，用于UDP通信
//   - logger: 日志记录器
//
// 返回：
//   - *Device: 完全初始化的WireGuard设备实例
func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device {
	// 创建设备实例并初始化基本状态
	device := new(Device)
	device.state.state.Store(uint32(deviceStateDown)) // 初始状态为关闭
	device.closed = make(chan struct{})               // 创建关闭信号通道
	device.log = logger

	// 初始化网络和TUN接口
	device.net.bind = bind
	device.tun.device = tunDevice

	// 获取并设置MTU（最大传输单元）
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU // 使用默认MTU值
	}
	device.tun.mtu.Store(int32(mtu))

	// 初始化各种管理组件
	device.peers.keyMap = make(map[NoisePublicKey]*Peer) // 对等体映射表
	device.rate.limiter.Init()                           // 速率限制器
	device.indexTable.Init()                             // 索引表

	// 初始化内存池，用于高效的内存分配
	device.PopulatePools()

	// 创建处理队列
	device.queue.handshake = newHandshakeQueue() // 握手处理队列
	device.queue.encryption = newOutboundQueue() // 出站加密队列
	device.queue.decryption = newInboundQueue()  // 入站解密队列

	// 启动工作协程
	cpus := runtime.NumCPU()     // 获取CPU核心数
	device.state.stopping.Wait() // 确保之前的停止操作已完成

	// 为每个CPU核心启动一组处理协程，实现并行处理
	device.queue.encryption.wg.Add(cpus) // 为每个握手协程预留加密队列计数
	for i := 0; i < cpus; i++ {
		go device.RoutineEncryption(i + 1) // 加密处理协程
		go device.RoutineDecryption(i + 1) // 解密处理协程
		go device.RoutineHandshake(i + 1)  // 握手处理协程
	}

	// 启动TUN接口相关的协程
	device.state.stopping.Add(1)      // 为TUN读取协程添加计数
	device.queue.encryption.wg.Add(1) // 为TUN读取协程预留加密队列计数
	go device.RoutineReadFromTUN()    // TUN接口数据读取协程
	go device.RoutineTUNEventReader() // TUN接口事件监听协程

	return device
}

// BatchSize 返回设备的整体批处理大小
// 批处理大小是网络绑定批处理大小和TUN设备批处理大小中的较大值
// 设备报告的批处理大小用于构造内存池，并且是设备生命周期内允许的批处理大小
// 返回值用于优化网络数据包的批量处理性能
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()    // 获取网络绑定的批处理大小
	dSize := device.tun.device.BatchSize() // 获取TUN设备的批处理大小
	if size < dSize {
		size = dSize // 选择较大的批处理大小
	}
	return size
}

// LookupPeer 根据公钥查找对等体
// 这是一个线程安全的查找操作，使用读锁保护对等体映射表
// 参数：
//   - pk: 要查找的对等体的公钥
//
// 返回：
//   - *Peer: 找到的对等体实例，如果不存在则返回nil
func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock() // 获取读锁，允许并发读取
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk] // 从映射表中查找对等体
}

// RemovePeer 根据公钥移除指定的对等体
// 这个操作会停止对等体的所有处理流程并从路由表中移除相关条目
// 参数：
//   - key: 要移除的对等体的公钥
func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock() // 获取写锁，确保独占访问
	defer device.peers.Unlock()

	// 查找并移除对等体
	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key) // 执行实际的移除操作
	}
}

// RemoveAllPeers 移除设备上的所有对等体
// 这个操作会停止所有对等体的处理流程并清空整个对等体映射表
// 通常在设备关闭或重置时调用
func (device *Device) RemoveAllPeers() {
	device.peers.Lock() // 获取写锁，确保独占访问
	defer device.peers.Unlock()

	// 逐一移除所有对等体
	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	// 重新创建空的映射表，释放旧的内存
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

// Close 永久关闭设备，释放所有资源
// 这是一个不可逆的操作，设备一旦关闭就无法再次启动
// 该方法会清理所有资源，包括对等体、队列、协程和网络连接
func (device *Device) Close() {
	// 获取所有必要的锁，确保关闭操作的原子性
	device.state.Lock()
	defer device.state.Unlock()
	device.ipcMutex.Lock() // 防止并发的IPC操作
	defer device.ipcMutex.Unlock()

	// 检查设备是否已经关闭，避免重复关闭
	if device.isClosed() {
		return
	}

	// 设置设备状态为已关闭，这个状态是不可逆的
	device.state.state.Store(uint32(deviceStateClosed))
	device.log.Verbosef("Device closing")

	// 关闭TUN设备接口
	device.tun.device.Close()

	// 执行设备关闭操作，关闭网络绑定和对等体
	device.downLocked()

	// 在关闭队列之前移除所有对等体，
	// 因为对等体假设队列是活跃的
	device.RemoveAllPeers()

	// 我们保持了对加密和解密队列的引用，
	// 以防我们启动了任何可能写入它们的新对等体。
	// 现在不会有新的对等体了；我们对这些队列的使用已经结束。
	device.queue.encryption.wg.Done() // 减少加密队列的等待组计数
	device.queue.decryption.wg.Done() // 减少解密队列的等待组计数
	device.queue.handshake.wg.Done()  // 减少握手队列的等待组计数

	// 等待所有工作协程完全停止
	device.state.stopping.Wait()

	// 关闭速率限制器
	device.rate.limiter.Close()

	device.log.Verbosef("Device closed")
	// 关闭设备的关闭信号通道，通知所有等待者
	close(device.closed)
}

// Wait 返回一个通道，当设备关闭时该通道会被关闭
// 这允许外部代码等待设备的关闭事件
// 返回：
//   - chan struct{}: 关闭信号通道，当设备关闭时会被关闭
func (device *Device) Wait() chan struct{} {
	return device.closed
}

// SendKeepalivesToPeersWithCurrentKeypair 向拥有当前有效密钥对的所有对等体发送保活消息
// 保活消息用于维持NAT穿越和检测连接状态
// 只有在设备处于运行状态且对等体有有效密钥时才会发送
func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	// 检查设备是否处于运行状态
	if !device.isUp() {
		return
	}

	// 遍历所有对等体
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		// 检查对等体是否有有效的当前密钥对
		peer.keypairs.RLock()
		// 判断密钥对是否存在且在有效期内（未超过RejectAfterTime）
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()

		// 如果密钥对有效，发送保活消息
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

// closeBindLocked 关闭设备的网络绑定
// 调用者必须持有网络互斥锁
// 这个函数处理所有网络资源的清理工作
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net

	// 取消网络链路监听器
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}

	// 关闭网络绑定接口
	if netc.bind != nil {
		err = netc.bind.Close()
	}

	// 等待所有网络相关的协程停止
	netc.stopping.Wait()
	return err
}

// Bind 返回设备的网络绑定接口
// 这是一个线程安全的操作，使用互斥锁保护网络配置
// 返回：
//   - conn.Bind: 当前的网络绑定接口实例
func (device *Device) Bind() conn.Bind {
	device.net.Lock() // 获取网络配置的互斥锁
	defer device.net.Unlock()
	return device.net.bind
}

// BindSetMark 设置网络绑定的防火墙标记
// 防火墙标记用于标识由该设备发送的数据包，便于防火墙规则处理
// 参数：
//   - mark: 新的防火墙标记值（0表示禁用）
//
// 返回：
//   - error: 设置过程中的错误
func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock() // 获取网络配置的互斥锁
	defer device.net.Unlock()

	// 检查是否有修改
	if device.net.fwmark == mark {
		return nil // 标记值未变化，无需操作
	}

	// 更新现有绑定的防火墙标记
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// 清除缓存的源地址，强制重新选择路由
	// 这确保新的防火墙标记能在所有后续数据包中生效
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing() // 标记对等体端点需要清除源地址
	}
	device.peers.RUnlock()

	return nil
}

// BindUpdate 更新设备的网络绑定，重新建立网络连接
// 这个操作会关闭现有的套接字并创建新的连接
// 【【通常在网络接口变化或配置更新时调用】】
func (device *Device) BindUpdate() error {
	device.net.Lock() // 获取网络配置的互斥锁
	defer device.net.Unlock()

	// 关闭现有的套接字
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// 如果设备没有运行，不需要打开新的套接字
	if !device.isUp() {
		return nil
	}

	// 绑定到新端口
	var err error
	var recvFns []conn.ReceiveFunc // 接收函数列表
	netc := &device.net
	// [1. 核心] 调用底层 Bind 接口的 Open 方法，真正执行 UDP 监听
	// 打开网络绑定，获取接收函数和实际端口
	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0 // 失败时清零端口
		return err
	}

	// 启动路由监听器，监听网络路由变化
	netc.netlinkCancel, err = device.startRouteListener(netc.bind)
	if err != nil {
		netc.bind.Close() // 失败时清理资源
		netc.port = 0
		return err
	}

	// 设置防火墙标记
	if netc.fwmark != 0 {
		err = netc.bind.SetMark(netc.fwmark)
		if err != nil {
			return err
		}
	}

	// 清除缓存的源地址，强制重新选择路由
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	// 启动接收协程
	device.net.stopping.Add(len(recvFns))        // 为每个接收协程添加停止计数
	device.queue.decryption.wg.Add(len(recvFns)) // 每个RoutineReceiveIncoming协程都会写入解密队列
	device.queue.handshake.wg.Add(len(recvFns))  // 每个RoutineReceiveIncoming协程都会写入握手队列

	batchSize := netc.bind.BatchSize() // 获取网络绑定的批处理大小
	// [2. 启动] 只有监听成功后，才会为每个接收器启动收包协程
	for _, fn := range recvFns {
		// 为每个接收函数启动一个协程
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Verbosef("UDP bind has been updated")
	return nil
}

// BindClose 关闭设备的网络绑定
// 这是一个线程安全的封装，在获取适当锁的情况下调用closeBindLocked
// 返回：
//   - error: 关闭过程中的错误
func (device *Device) BindClose() error {
	device.net.Lock()              // 获取网络配置的互斥锁
	err := closeBindLocked(device) // 执行实际的关闭操作
	device.net.Unlock()
	return err
}
