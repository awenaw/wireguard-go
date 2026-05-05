package main

import (
	"fmt"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/ratelimiter" // 修正为正确的模块路径
)

func main() {
	// 1. 创建并初始化限流器
	rl := &ratelimiter.Ratelimiter{}
	rl.Init()
	defer rl.Close() // 记得最后关闭清理协程

	testIP := netip.MustParseAddr("192.168.1.1")

	// 2. 模拟突发流量 (Burstable)
	// 根据源码：packetsBurstable = 5
	fmt.Println("--- 开始突发流量测试 ---")
	for i := 1; i <= 10; i++ {
		allowed := rl.Allow(testIP)
		fmt.Printf("第 %d 个包: 允许 = %v\n", i, allowed)

		// 快速发包，不给令牌恢复时间
		if !allowed {
			fmt.Println(">> [已限流] 令牌已耗尽")
		}
	}

	// 3. 模拟等待恢复
	// 根据源码：packetsPerSecond = 20，即每 50ms 恢复 1 个令牌
	fmt.Println("\n--- 等待 200ms 让令牌恢复 ---")
	time.Sleep(200 * time.Millisecond)

	// 4. 再次尝试发包
	fmt.Println("--- 恢复测试 ---")
	for i := 1; i <= 3; i++ {
		allowed := rl.Allow(testIP)
		fmt.Printf("恢复后第 %d 个包: 允许 = %v\n", i, allowed)
	}
}
