/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// ip 限流器
// 问题：
//1、限流变量是哪个？（ip维度的限流，限流变量为RatelimiterEntry的 tokens)
//2、tokens 恢复的原理是？
//3、如果没有限流机制，会怎样？

package ratelimiter

import (
	"net/netip"
	"sync"
	"time"
)

const (
	packetsPerSecond   = 20                            // 每秒发包数
	packetsBurstable   = 5                             // 突发包数
	garbageCollectTime = time.Second                   // 过期IP回收时间
	packetCost         = 1000000000 / packetsPerSecond // 按纳秒计量的令牌成本
	maxTokens          = packetCost * packetsBurstable // 令牌桶最大容量
)

type RatelimiterEntry struct {
	mu       sync.Mutex
	lastTime time.Time
	tokens   int64
}

type Ratelimiter struct {
	mu      sync.RWMutex
	timeNow func() time.Time

	stopReset chan struct{} // send to reset, close to stop
	table     map[netip.Addr]*RatelimiterEntry
}

func (rate *Ratelimiter) Close() {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	if rate.stopReset != nil {
		close(rate.stopReset)
	}
}

func (rate *Ratelimiter) Init() {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	if rate.timeNow == nil {
		rate.timeNow = time.Now
	}

	// stop any ongoing garbage collection routine
	if rate.stopReset != nil {
		close(rate.stopReset)
	}

	rate.stopReset = make(chan struct{})
	rate.table = make(map[netip.Addr]*RatelimiterEntry)

	stopReset := rate.stopReset // store in case Init is called again.

	// Start garbage collection routine.
	go func() {
		ticker := time.NewTicker(time.Second)
		// 刚创建出来就立刻关掉。因为此时还没有任何 IP 进来，不需要每秒去检查
		ticker.Stop()
		for {
			select {
			case _, ok := <-stopReset:
				ticker.Stop()
				if !ok {
					return
				}
				ticker = time.NewTicker(time.Second)
			// 每过 1 秒钟，它就会尝试往 ticker.C 这个通道里塞入当前的时间
			case <-ticker.C:
				//每当 C 收到信号（过了 1 秒），就跑一次 cleanup()。
				// 如果发现 cleanup() 返回了 true（意思是：现在 IP 表已经空了），就顺手把定时器再次 Stop() 掉，省电省 CPU。
				if rate.cleanup() {
					ticker.Stop()
				}
			}
		}
	}()
}

func (rate *Ratelimiter) cleanup() (empty bool) {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	for key, entry := range rate.table {
		entry.mu.Lock()
		if rate.timeNow().Sub(entry.lastTime) > garbageCollectTime {
			delete(rate.table, key)
		}
		entry.mu.Unlock()
	}

	return len(rate.table) == 0
}

// 这个函数只接收一个参数：IP 地址。

// Map (Table): 只要有新 IP 来发包，就给他建一个
// RatelimiterEntry
// （令牌桶）。
// Tokens (令牌):
// 初始给你满满一桶令牌 (maxTokens)。
// 每发一个包，扣除一点 (packetCost)。
// 随着时间流逝，令牌会自动补满 (entry.tokens += timeDiff)。
// 阈值:
// 默认限制是：每秒 20 个包 (packetsPerSecond = 20)。
// 允许突发：最多连发 5 个包 (packetsBurstable = 5)。
func (rate *Ratelimiter) Allow(ip netip.Addr) bool {
	var entry *RatelimiterEntry
	// lookup entry
	rate.mu.RLock()
	entry = rate.table[ip] // 查找是否有这个ip的令牌桶
	rate.mu.RUnlock()

	// make new entry if not found
	if entry == nil {
		entry = new(RatelimiterEntry)
		// 1/20*5 - 1/20 = 4/20 意味着初始允许发5个包(4 份是因为排除了进来的那一份)
		entry.tokens = maxTokens - packetCost
		entry.lastTime = rate.timeNow()
		rate.mu.Lock()
		rate.table[ip] = entry
		// 如果是第一个ip，则启动垃圾回收goroutine
		if len(rate.table) == 1 {
			rate.stopReset <- struct{}{}
		}
		rate.mu.Unlock()
		return true
	}

	// add tokens to entry
	entry.mu.Lock()
	now := rate.timeNow()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds() // 延时补充令牌
	entry.lastTime = now
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}

	// subtract cost of packet
	// 第一秒的理论“极限”令牌数是 25 个（5 个存货 + 20 个新生的）。
	if entry.tokens > packetCost {
		entry.tokens -= packetCost // 扣除令牌
		entry.mu.Unlock()
		return true
	}
	entry.mu.Unlock()
	return false
}
