package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// 这个 demo 把 device/pools.go 的核心用法单独拎出来：
// 1. NewWaitPool(max, new)：创建一个“有限对象池”。
// 2. Get()：借对象；借出数量达到 max 时会等待。
// 3. Put(x)：还对象；归还前要清理旧状态。
//
// 运行：go run ./docs/demo/pools

type packetBuffer struct {
	id   uint64
	data []byte
}

type packetBatch struct {
	elems []*packetBuffer
}

func main() {
	fmt.Println("=== WaitPool demo: 资源不是无限的，满了就等 😎 ===")

	bufferPool := newBufferPool(2)
	runConcurrentBorrowDemo(bufferPool)

	fmt.Println("\n=== Container demo: 还回池子前，先把旧引用擦干净 🧹 ===")
	runContainerCleanupDemo()
}

// newBufferPool 对应 pools.go 里的 messageBuffers / inboundElements 这类池子。
func newBufferPool(max uint32) *device.WaitPool {
	var nextID atomic.Uint64
	return device.NewWaitPool(max, func() any {
		id := nextID.Add(1)
		fmt.Printf("new: 真正创建 packetBuffer #%d\n", id)
		return &packetBuffer{
			id:   id,
			data: make([]byte, 0, 64),
		}
	})
}

func runConcurrentBorrowDemo(pool *device.WaitPool) {
	const workers = 5

	var wg sync.WaitGroup
	var active atomic.Int32
	var maxActive atomic.Int32
	var printMu sync.Mutex

	logf := func(format string, args ...any) {
		printMu.Lock()
		defer printMu.Unlock()
		fmt.Printf(format, args...)
	}

	rememberMax := func(n int32) {
		for {
			old := maxActive.Load()
			if n <= old || maxActive.CompareAndSwap(old, n) {
				return
			}
		}
	}

	wg.Add(workers)
	for i := 1; i <= workers; i++ {
		workerID := i
		go func() {
			defer wg.Done()

			logf("worker %d: 准备 Get()\n", workerID)

			// 牛鼻子：如果已经有 max 个对象借出，这里会卡住等待 Put()。
			buf := pool.Get().(*packetBuffer)

			now := active.Add(1)
			rememberMax(now)
			logf("worker %d: 拿到 buffer #%d，当前使用中=%d\n", workerID, buf.id, now)

			buf.data = append(buf.data, fmt.Sprintf("packet-from-worker-%d", workerID)...)
			time.Sleep(300 * time.Millisecond)

			// 归还前清理旧内容：对象可以复用，但别把上次的数据带回池子。
			clear(buf.data)
			buf.data = buf.data[:0]

			now = active.Add(-1)
			pool.Put(buf)
			logf("worker %d: Put(buffer #%d)，当前使用中=%d\n", workerID, buf.id, now)
		}()
	}

	wg.Wait()
	fmt.Printf("\n观察结果：max=2，所以同时使用中的对象最多只有 %d 个。\n", maxActive.Load())
}

func runContainerCleanupDemo() {
	batchPool := device.NewWaitPool(1, func() any {
		fmt.Println("new: 真正创建 packetBatch")
		return &packetBatch{elems: make([]*packetBuffer, 0, 4)}
	})

	batch := batchPool.Get().(*packetBatch)
	batch.elems = append(batch.elems,
		&packetBuffer{id: 101, data: []byte("old-packet-a")},
		&packetBuffer{id: 102, data: []byte("old-packet-b")},
	)
	fmt.Printf("借出 batch：len=%d cap=%d\n", len(batch.elems), cap(batch.elems))

	// 对应 pools.go 里的 c.elems[i] = nil：断开旧元素引用，避免 GC 被旧指针拖住。
	for i := range batch.elems {
		batch.elems[i] = nil
	}

	// 对应 pools.go 里的 c.elems = c.elems[:0]：清空长度，但保留底层数组容量。
	batch.elems = batch.elems[:0]
	fmt.Printf("清理后归还：len=%d cap=%d\n", len(batch.elems), cap(batch.elems))
	batchPool.Put(batch)

	reused := batchPool.Get().(*packetBatch)
	fmt.Printf("再次借出 batch：len=%d cap=%d（容量还在，内容已清）\n", len(reused.elems), cap(reused.elems))
	batchPool.Put(reused)
}
