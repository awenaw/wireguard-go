package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

// 验证假设：每次创建新 socket（新端口）是否会导致 NAT 问题

func main() {
	serverIP := flag.String("server", "", "服务器 IP")
	port := flag.Int("p", 51830, "服务器端口")
	wait := flag.Int("wait", 10, "等待时间 (秒)")
	rounds := flag.Int("rounds", 5, "测试轮次")
	flag.Parse()

	if *serverIP == "" {
		fmt.Println("用法: go run main.go -server <IP> -wait 10 -rounds 5")
		os.Exit(1)
	}

	serverAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *serverIP, *port))

	fmt.Printf("=== 验证：每次新 socket 是否导致 NAT 问题 ===\n")
	fmt.Printf("目标: %s, 等待: %d秒, 轮次: %d\n", serverAddr, *wait, *rounds)
	fmt.Println("------------------------------------------------")

	for i := 1; i <= *rounds; i++ {
		// 每次创建新 socket（模拟旧版本行为）
		conn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			fmt.Printf("#%d 创建 socket 失败: %v\n", i, err)
			continue
		}

		localPort := conn.LocalAddr().(*net.UDPAddr).Port
		fmt.Printf("\n[#%d] 新端口: %d, 发送 WAIT:%d\n", i, localPort, *wait)

		// 发送请求
		msg := fmt.Sprintf("WAIT:%d", *wait)
		conn.Write([]byte(msg))

		// 设置超时并等待
		conn.SetReadDeadline(time.Now().Add(time.Duration(*wait)*time.Second + 10*time.Second))

		buf := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(buf)

		if err != nil {
			fmt.Printf("[#%d] ❌ 超时！端口 %d 的回复没收到\n", i, localPort)
		} else {
			fmt.Printf("[#%d] ✅ 收到: %s (端口 %d)\n", i, string(buf[:n]), localPort)
		}

		conn.Close()

		// 短暂间隔，避免太快
		time.Sleep(1 * time.Second)
	}

	fmt.Println("\n------------------------------------------------")
	fmt.Println("如果全部成功 → 问题不在于每次新端口")
	fmt.Println("如果失败 → 验证了你的假设：新端口覆盖导致问题")
}
