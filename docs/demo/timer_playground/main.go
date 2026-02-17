package main

import (
	"fmt"
	"sync"
	"time"
)

// 模拟 WireGuard 的状态机定时器
// 场景：模拟一个 Peer 的握手和保活机制

const (
	RekeyTimeout      = 5 * time.Second // 5秒没握手成功就重试
	KeepaliveInterval = 3 * time.Second // 3秒没发数据就发个心跳
)

type Peer struct {
	Name string
	mu   sync.Mutex

	// 定时器
	rekeyTimer     *time.Timer
	keepaliveTimer *time.Timer

	// 状态
	handshakeCompleted bool
}

func NewPeer(name string) *Peer {
	return &Peer{
		Name: name,
	}
}

// 模拟：开始握手（发送了 Handshake Initiation）
func (p *Peer) StartHandshake() {
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Printf("[%s] 开始握手 (发送 Initiation)...\n", p.Name)
	p.handshakeCompleted = false

	// 启动重传定时器：如果5秒内没收到响应，就重发
	if p.rekeyTimer != nil {
		p.rekeyTimer.Stop()
	}
	p.rekeyTimer = time.AfterFunc(RekeyTimeout, func() {
		// 注意：回调在一个新的 goroutine 中执行
		fmt.Printf("🔴 [%s] 握手超时！触发重传逻辑...\n", p.Name)
		// 在真实代码中，这里会再次调用 StartHandshake
		p.StartHandshake()
	})
}

// 模拟：收到了握手响应 (Handshake Response)
func (p *Peer) ReceiveHandshakeResponse() {
	p.mu.Lock()
	defer p.mu.Unlock()

	fmt.Printf("🟢 [%s] 收到握手响应！连接建立。\n", p.Name)
	p.handshakeCompleted = true

	// 握手成功，停止重传定时器
	if p.rekeyTimer != nil {
		p.rekeyTimer.Stop()
	}

	// 启动保活定时器
	p.resetKeepalive()
}

// 模拟：发送数据包
func (p *Peer) SendData() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.handshakeCompleted {
		fmt.Printf("⚠️ [%s]还没握手成功，数据包先缓存或丢弃\n", p.Name)
		return
	}

	fmt.Printf("⬆️ [%s] 发送数据包... (Keepalive 推迟)\n", p.Name)
	// 既然发了数据，对方就知道我活着，所以重置保活倒计时
	p.resetKeepalive()
}

// 内部：重置保活定时器
func (p *Peer) resetKeepalive() {
	if p.keepaliveTimer != nil {
		p.keepaliveTimer.Stop()
	}
	p.keepaliveTimer = time.AfterFunc(KeepaliveInterval, func() {
		fmt.Printf("💓 [%s] 太久没说话了，发送 Keepalive 心跳包\n", p.Name)
		// 发完心跳后，再次重置自己
		p.resetKeepalive()
	})
}

func main() {
	// 场景 1: 握手失败不断重试
	fmt.Println("=== Case 1: 模拟握手超时 ===")
	peer1 := NewPeer("Peer-Failed")
	peer1.StartHandshake()

	time.Sleep(12 * time.Second) // 观察它重试两次 (5s, 10s)

	fmt.Println("\n=== Case 2: 正常连接与保活 ===")
	peer2 := NewPeer("Peer-Success")
	peer2.StartHandshake()

	// 模拟1秒后收到响应
	time.Sleep(1 * time.Second)
	peer2.ReceiveHandshakeResponse()

	// 观察 Keepalive (每3秒一次)
	time.Sleep(7 * time.Second)

	// 模拟主动发数据
	fmt.Println("\n--- 主动发送数据 ---")
	peer2.SendData()

	// 再次等待，观察时间被推迟了
	time.Sleep(5 * time.Second)
}
