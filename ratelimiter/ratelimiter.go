/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package ratelimiter

import (
	"net/netip"
	"sync"
	"time"
)

const (
	packetsPerSecond   = 20
	packetsBurstable   = 5
	garbageCollectTime = time.Second
	packetCost         = 1000000000 / packetsPerSecond
	maxTokens          = packetCost * packetsBurstable
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
		ticker.Stop()
		for {
			select {
			case _, ok := <-stopReset:
				ticker.Stop()
				if !ok {
					return
				}
				ticker = time.NewTicker(time.Second)
			case <-ticker.C:
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
	entry = rate.table[ip]
	rate.mu.RUnlock()

	// make new entry if not found
	if entry == nil {
		entry = new(RatelimiterEntry)
		entry.tokens = maxTokens - packetCost
		entry.lastTime = rate.timeNow()
		rate.mu.Lock()
		rate.table[ip] = entry
		if len(rate.table) == 1 {
			rate.stopReset <- struct{}{}
		}
		rate.mu.Unlock()
		return true
	}

	// add tokens to entry
	entry.mu.Lock()
	now := rate.timeNow()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	if entry.tokens > maxTokens {
		entry.tokens = maxTokens
	}

	// subtract cost of packet
	if entry.tokens > packetCost {
		entry.tokens -= packetCost
		entry.mu.Unlock()
		return true
	}
	entry.mu.Unlock()
	return false
}
