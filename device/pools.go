/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
)

// pools.go 有 5 个池子：
// device.pool
//
//	│
//	├── inboundElementsContainer   → 入站元素容器（一批入站包的集合）
//	├── outboundElementsContainer  → 出站元素容器（一批出站包的集合）
//	├── messageBuffers             → 原始字节缓冲区（UDP 收发用的大数组）
//	├── inboundElements            → 单个入站元素
//	└── outboundElements           → 单个出站元素
// ==============================
// WaitPool：有限对象池（复用 + 上限 + 等待）

type WaitPool struct {
	pool sync.Pool
	cond sync.Cond
	lock sync.Mutex

	// 牛鼻子：count 当前借出的数量；max 允许借出的最大上限
	// max == 0 表示不设限，WaitPool 就退化成普通 sync.Pool。
	count uint32
	max   uint32
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		// 牛鼻子：池子不是“没对象就无限造”，而是借出数到上限就睡眠等待。
		// 用 for 而不是 if，是为了防止被唤醒后条件已经被别的 goroutine 抢先改变。
		for p.count >= p.max {
			p.cond.Wait()
		}
		p.count++
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	// 牛鼻子：Put 必须和 Get 成对出现；归还后释放一个额度，并叫醒一个等待者。
	p.count--
	p.cond.Signal()
}

// ==============================
// Device 池子初始化：一次性把 5 个池子搭起来

func (device *Device) PopulatePools() {
	device.pool.inboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueInboundElement, 0, device.BatchSize())
		return &QueueInboundElementsContainer{elems: s}
	})
	device.pool.outboundElementsContainer = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueOutboundElement, 0, device.BatchSize())
		return &QueueOutboundElementsContainer{elems: s}
	})
	device.pool.messageBuffers = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
	device.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	device.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
}

// ==============================
// Container 池：复用“一批包”的容器

func (device *Device) GetInboundElementsContainer() *QueueInboundElementsContainer {
	c := device.pool.inboundElementsContainer.Get().(*QueueInboundElementsContainer)
	// 容器会复用，锁也要重置成干净状态，避免带着上一次使用的锁状态回来。
	c.Mutex = sync.Mutex{}
	return c
}

func (device *Device) PutInboundElementsContainer(c *QueueInboundElementsContainer) {
	for i := range c.elems {
		// 牛鼻子：断开旧元素引用，让 GC 不被复用的 slice 底层数组“拽住”。
		c.elems[i] = nil
	}
	// 长度归零但保留容量，下次可以复用底层数组，少分配。
	c.elems = c.elems[:0]
	device.pool.inboundElementsContainer.Put(c)
}

func (device *Device) GetOutboundElementsContainer() *QueueOutboundElementsContainer {
	c := device.pool.outboundElementsContainer.Get().(*QueueOutboundElementsContainer)
	// 容器会复用，锁也要重置成干净状态，避免带着上一次使用的锁状态回来。
	c.Mutex = sync.Mutex{}
	return c
}

func (device *Device) PutOutboundElementsContainer(c *QueueOutboundElementsContainer) {
	for i := range c.elems {
		// 牛鼻子：清掉旧指针，避免旧 outbound element 被容器继续引用。
		c.elems[i] = nil
	}
	// 长度归零但保留容量，下次可以复用底层数组，少分配。
	c.elems = c.elems[:0]
	device.pool.outboundElementsContainer.Put(c)
}

// ==============================
// Message buffer 池：复用 UDP 收发的大字节数组

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

// ==============================
// Element 池：复用单个入站/出站队列元素

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
