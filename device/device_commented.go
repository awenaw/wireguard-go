/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

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

// Device 代表一个完整的 WireGuard 设备实例
// 这是 WireGuard-Go 的核心结构，管理所有网络接口、对等方和协议状态
type Device struct {
	// 设备状态管理
	state struct {
		// state 保存设备的状态，通过原子操作访问
		// 使用 device.deviceState() 方法读取它
		// device.deviceState() 不获取互斥锁，所以它只捕获一个快照
		// 在状态转换期间，状态变量在设备本身之前更新
		// 因此状态要么是设备的当前状态，要么是设备的预期未来状态
		// 例如，在执行 Up() 调用时，state 将是 deviceStateUp
		// 不能保证设备的预期未来状态会成为实际状态；Up() 可能失败
		// 设备也可能在检查时间和使用时间之间多次改变状态
		// 因此，state 的非同步使用必须仅作为建议/尽力而为
		state atomic.Uint32 // 实际上是 deviceState，但为方便起见类型化为 uint32
		
		// stopping 会阻塞直到所有输入到 Device 的都被关闭
		stopping sync.WaitGroup
		
		// mu 保护状态变更
		sync.Mutex
	}

	// 网络管理
	net struct {
		stopping      sync.WaitGroup      // 等待网络相关协程停止
		sync.RWMutex                     // 保护网络配置的读写锁
		bind          conn.Bind          // 网络绑定接口，处理 UDP 套接字
		netlinkCancel *rwcancel.RWCancel // 用于取消 netlink 监听的取消器
		port          uint16             // 监听端口
		fwmark        uint32             // 防火墙标记值（0 = 禁用）
		brokenRoaming bool               // 是否存在破坏性漫游问题
	}

	// 静态身份信息（本设备的密钥对）
	staticIdentity struct {
		sync.RWMutex                // 保护密钥对的读写锁
		privateKey NoisePrivateKey  // 设备私钥
		publicKey  NoisePublicKey   // 设备公钥
	}

	// 对等方管理
	peers struct {
		sync.RWMutex                          // 保护 keyMap 的读写锁
		keyMap       map[NoisePublicKey]*Peer // 公钥到对等方的映射表
	}

	// 速率限制和负载管理
	rate struct {
		underLoadUntil atomic.Int64           // 负载状态持续到的时间戳
		limiter        ratelimiter.Ratelimiter // 速率限制器，防止 DoS 攻击
	}

	// 允许的 IP 地址范围管理（路由表）
	allowedips AllowedIPs

	// 索引表，用于快速查找握手和密钥对
	indexTable IndexTable

	// Cookie 检查器，用于 DoS 保护
	cookieChecker CookieChecker

	// 内存池管理，用于高效的内存分配和重用
	pool struct {
		inboundElementsContainer  *WaitPool // 入站元素容器池
		outboundElementsContainer *WaitPool // 出站元素容器池
		messageBuffers            *WaitPool // 消息缓冲区池
		inboundElements           *WaitPool // 入站元素池
		outboundElements          *WaitPool // 出站元素池
	}

	// 处理队列，用于数据包的流水线处理
	queue struct {
		encryption *outboundQueue // 加密队列，处理出站数据包加密
		decryption *inboundQueue  // 解密队列，处理入站数据包解密
		handshake  *handshakeQueue // 握手队列，处理协议握手消息
	}

	// TUN 设备管理
	tun struct {
		device tun.Device   // TUN 设备接口
		mtu    atomic.Int32 // 最大传输单元（MTU）
	}

	// IPC（进程间通信）互斥锁，保护配置操作
	ipcMutex sync.RWMutex

	// 设备关闭信号通道
	closed chan struct{}

	// 日志记录器
	log *Logger
}

// deviceState 表示设备的状态
// 有三种状态：down（下线）、up（上线）、closed（已关闭）
// 状态转换图：
//	down -----+
//	  ↑↓      ↓
//	  up -> closed
type deviceState uint32

//go:generate go run golang.org/x/tools/cmd/stringer -type deviceState -trimprefix=deviceState
const (
	deviceStateDown   deviceState = iota // 设备下线状态
	deviceStateUp                        // 设备上线状态
	deviceStateClosed                    // 设备已关闭状态（不可恢复）
)

// deviceState 返回 device.state.state 作为 deviceState 类型
// 查看相关文档了解如何解释这个值
func (device *Device) deviceState() deviceState {
	return deviceState(device.state.state.Load())
}

// isClosed 报告设备是否已关闭（或正在关闭）
// 查看 device.state.state 注释了解如何解释这个值
func (device *Device) isClosed() bool {
	return device.deviceState() == deviceStateClosed
}

// isUp 报告设备是否已上线（或正在尝试上线）
// 查看 device.state.state 注释了解如何解释这个值
func (device *Device) isUp() bool {
	return device.deviceState() == deviceStateUp
}

// removePeerLocked 移除一个对等方（必须持有 device.peers.Lock()）
func removePeerLocked(device *Device, peer *Peer, key NoisePublicKey) {
	// 停止路由和数据包处理
	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// 从对等方映射中移除
	delete(device.peers.keyMap, key)
}

// changeState 尝试将设备状态更改为匹配 want
func (device *Device) changeState(want deviceState) (err error) {
	device.state.Lock()
	defer device.state.Unlock()
	
	old := device.deviceState()
	if old == deviceStateClosed {
		// 一旦关闭，就永远关闭
		device.log.Verbosef("Interface closed, ignored requested state %s", want)
		return nil
	}
	
	switch want {
	case old:
		// 已经是期望状态，无需改变
		return nil
	case deviceStateUp:
		// 尝试上线
		device.state.state.Store(uint32(deviceStateUp))
		err = device.upLocked()
		if err == nil {
			break
		}
		fallthrough // 上线失败；将设备完全下线
	case deviceStateDown:
		// 下线设备
		device.state.state.Store(uint32(deviceStateDown))
		errDown := device.downLocked()
		if err == nil {
			err = errDown
		}
	}
	
	device.log.Verbosef("Interface state was %s, requested %s, now %s", old, want, device.deviceState())
	return
}

// upLocked 尝试启动设备并报告是否成功
// 调用者必须持有 device.state.mu 并负责更新 device.state.state
func (device *Device) upLocked() error {
	// 更新网络绑定
	if err := device.BindUpdate(); err != nil {
		device.log.Errorf("Unable to update bind: %v", err)
		return err
	}

	// IPC 设置操作会等待对等方被创建后才调用 Start()
	// 所以如果有并发的 IPC 设置请求发生，我们应该等待它完成
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()

	// 启动所有对等方
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Start()
		// 如果配置了持久保活间隔，发送保活包
		if peer.persistentKeepaliveInterval.Load() > 0 {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
	return nil
}

// downLocked 尝试关闭设备
// 调用者必须持有 device.state.mu 并负责更新 device.state.state
func (device *Device) downLocked() error {
	// 关闭网络绑定
	err := device.BindClose()
	if err != nil {
		device.log.Errorf("Bind close failed: %v", err)
	}

	// 停止所有对等方
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Stop()
	}
	device.peers.RUnlock()
	return err
}

// Up 启动设备
func (device *Device) Up() error {
	return device.changeState(deviceStateUp)
}

// Down 关闭设备
func (device *Device) Down() error {
	return device.changeState(deviceStateDown)
}

// IsUnderLoad 检查设备是否处于高负载状态
// 这用于触发 DoS 保护机制
func (device *Device) IsUnderLoad() bool {
	// 检查当前是否处于负载状态
	now := time.Now()
	// 如果握手队列占用超过 1/8，认为处于高负载
	underLoad := len(device.queue.handshake.c) >= QueueHandshakeSize/8
	if underLoad {
		// 设置负载状态持续时间
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime).UnixNano())
		return true
	}
	// 检查是否最近处于负载状态
	return device.rate.underLoadUntil.Load() > now.UnixNano()
}

// SetPrivateKey 设置设备的私钥
// 这会影响所有现有的对等方连接
func (device *Device) SetPrivateKey(sk NoisePrivateKey) error {
	// 锁定必需的资源
	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	// 如果私钥没有改变，直接返回
	if sk.Equals(device.staticIdentity.privateKey) {
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	// 收集所有对等方的握手锁
	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// 移除公钥匹配的对等方（防止自连接）
	publicKey := sk.publicKey()
	for key, peer := range device.peers.keyMap {
		if peer.handshake.remoteStatic.Equals(publicKey) {
			peer.handshake.mutex.RUnlock()
			removePeerLocked(device, peer, key)
			peer.handshake.mutex.RLock()
		}
	}

	// 更新密钥材料
	device.staticIdentity.privateKey = sk
	device.staticIdentity.publicKey = publicKey
	device.cookieChecker.Init(publicKey)

	// 执行静态-静态 DH 预计算
	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		// 重新计算与每个对等方的共享密钥
		handshake.precomputedStaticStatic, _ = device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic)
		expiredPeers = append(expiredPeers, peer)
	}

	// 释放握手锁
	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	
	// 使所有对等方的当前密钥对过期，强制重新握手
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

// NewDevice 创建一个新的 WireGuard 设备实例
// tunDevice: TUN 设备接口
// bind: 网络绑定接口
// logger: 日志记录器
func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *Logger) *Device {
	device := new(Device)
	
	// 初始化设备状态为下线
	device.state.state.Store(uint32(deviceStateDown))
	device.closed = make(chan struct{})
	device.log = logger
	device.net.bind = bind
	device.tun.device = tunDevice
	
	// 获取并设置 MTU
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}
	device.tun.mtu.Store(int32(mtu))
	
	// 初始化对等方映射表
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
	
	// 初始化速率限制器和索引表
	device.rate.limiter.Init()
	device.indexTable.Init()

	// 填充内存池
	device.PopulatePools()

	// 创建处理队列
	device.queue.handshake = newHandshakeQueue()
	device.queue.encryption = newOutboundQueue()
	device.queue.decryption = newInboundQueue()

	// 启动工作协程
	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	device.queue.encryption.wg.Add(cpus) // 每个 RoutineHandshake 一个
	
	// 为每个 CPU 核心启动加密、解密和握手处理协程
	for i := 0; i < cpus; i++ {
		go device.RoutineEncryption(i + 1)  // 处理数据包加密
		go device.RoutineDecryption(i + 1)  // 处理数据包解密
		go device.RoutineHandshake(i + 1)   // 处理握手消息
	}

	// 启动 TUN 设备读取协程
	device.state.stopping.Add(1)      // RoutineReadFromTUN
	device.queue.encryption.wg.Add(1) // RoutineReadFromTUN
	go device.RoutineReadFromTUN()     // 从 TUN 设备读取数据包
	go device.RoutineTUNEventReader()  // 监听 TUN 设备事件

	return device
}

// BatchSize 返回设备的批处理大小
// 这是绑定批处理大小和 TUN 批处理大小的最大值
// 设备报告的批处理大小用于构建内存池，并且是设备生命周期内允许的批处理大小
func (device *Device) BatchSize() int {
	size := device.net.bind.BatchSize()
	dSize := device.tun.device.BatchSize()
	if size < dSize {
		size = dSize
	}
	return size
}

// LookupPeer 根据公钥查找对等方
func (device *Device) LookupPeer(pk NoisePublicKey) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()

	return device.peers.keyMap[pk]
}

// RemovePeer 移除指定的对等方
func (device *Device) RemovePeer(key NoisePublicKey) {
	device.peers.Lock()
	defer device.peers.Unlock()
	
	// 停止对等方并从路由中移除
	peer, ok := device.peers.keyMap[key]
	if ok {
		removePeerLocked(device, peer, key)
	}
}

// RemoveAllPeers 移除所有对等方
func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	// 移除所有对等方
	for key, peer := range device.peers.keyMap {
		removePeerLocked(device, peer, key)
	}

	// 重新创建映射表
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)
}

// Close 关闭设备并清理所有资源
func (device *Device) Close() {
	device.state.Lock()
	defer device.state.Unlock()
	device.ipcMutex.Lock()
	defer device.ipcMutex.Unlock()
	
	// 如果已经关闭，直接返回
	if device.isClosed() {
		return
	}
	
	// 设置设备状态为已关闭
	device.state.state.Store(uint32(deviceStateClosed))
	device.log.Verbosef("Device closing")

	// 关闭 TUN 设备
	device.tun.device.Close()
	device.downLocked()

	// 在关闭队列之前移除对等方
	// 因为对等方假设队列是活跃的
	device.RemoveAllPeers()

	// 我们保持对加密和解密队列的引用
	// 以防我们启动了任何可能写入它们的新对等方
	// 现在没有新的对等方来了；我们完成了这些队列的使用
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	device.queue.handshake.wg.Done()
	
	// 等待所有协程停止
	device.state.stopping.Wait()

	// 关闭速率限制器
	device.rate.limiter.Close()

	device.log.Verbosef("Device closed")
	// 关闭信号通道，通知等待者设备已关闭
	close(device.closed)
}

// Wait 返回一个通道，当设备关闭时该通道会被关闭
func (device *Device) Wait() chan struct{} {
	return device.closed
}

// SendKeepalivesToPeersWithCurrentKeypair 向拥有当前密钥对的对等方发送保活包
func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	// 如果设备未上线，直接返回
	if !device.isUp() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		// 检查是否有当前密钥对且未过期
		sendKeepalive := peer.keypairs.current != nil && 
			!peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

// closeBindLocked 关闭设备的网络绑定
// 调用者必须持有网络互斥锁
func closeBindLocked(device *Device) error {
	var err error
	netc := &device.net
	
	// 取消 netlink 监听
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	
	// 关闭网络绑定
	if netc.bind != nil {
		err = netc.bind.Close()
	}
	
	// 等待网络相关协程停止
	netc.stopping.Wait()
	return err
}

// Bind 返回设备的网络绑定
func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

// BindSetMark 设置网络绑定的防火墙标记
func (device *Device) BindSetMark(mark uint32) error {
	device.net.Lock()
	defer device.net.Unlock()

	// 检查是否已修改
	if device.net.fwmark == mark {
		return nil
	}

	// 在现有绑定上更新防火墙标记
	device.net.fwmark = mark
	if device.isUp() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// 清除缓存的源地址
	// 因为防火墙标记变化可能影响路由选择
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	return nil
}

// BindUpdate 更新网络绑定
// 这会关闭现有套接字并打开新的套接字
func (device *Device) BindUpdate() error {
	device.net.Lock()
	defer device.net.Unlock()

	// 关闭现有套接字
	if err := closeBindLocked(device); err != nil {
		return err
	}

	// 如果设备未上线，不需要打开新套接字
	if !device.isUp() {
		return nil
	}

	// 打开新套接字
	var err error
	var recvFns []conn.ReceiveFunc
	netc := &device.net

	// 绑定到新端口
	recvFns, netc.port, err = netc.bind.Open(netc.port)
	if err != nil {
		netc.port = 0
		return err
	}

	// 启动路由监听器
	netc.netlinkCancel, err = device.startRouteListener(netc.bind)
	if err != nil {
		netc.bind.Close()
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

	// 清除缓存的源地址
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.markEndpointSrcForClearing()
	}
	device.peers.RUnlock()

	// 启动接收协程
	device.net.stopping.Add(len(recvFns))
	device.queue.decryption.wg.Add(len(recvFns)) // 每个 RoutineReceiveIncoming 协程写入设备解密队列
	device.queue.handshake.wg.Add(len(recvFns))  // 每个 RoutineReceiveIncoming 协程写入设备握手队列
	
	batchSize := netc.bind.BatchSize()
	for _, fn := range recvFns {
		// 为每个接收函数启动一个处理协程
		go device.RoutineReceiveIncoming(batchSize, fn)
	}

	device.log.Verbosef("UDP bind has been updated")
	return nil
}

// BindClose 关闭设备的网络绑定
func (device *Device) BindClose() error {
	device.net.Lock()
	err := closeBindLocked(device)
	device.net.Unlock()
	return err
}