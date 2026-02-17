package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"
)

func main() {
	port := flag.Int("p", 51830, "服务器端口")
	start := flag.Int("s", 20, "起始等待时间 (秒)")
	interval := flag.Int("i", 5, "递增步长 (秒)")
	maxTime := flag.Int("m", 300, "最大测试时间 (秒)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("用法: ./nattest <IP> [-s 20] [-i 5] [-m 300] [-p 51830]")
		os.Exit(1)
	}
	serverIP := args[0]

	serverAddr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", serverIP, *port))

	// 创建一个 socket 并复用 (关键！)
	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Printf("连接失败: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	localPort := conn.LocalAddr().(*net.UDPAddr).Port
	fmt.Printf("🚀 开始测试: %s (本地端口: %d)\n", serverAddr, localPort)
	fmt.Printf("策略: 从 %ds 开始, 步长 %ds, 最大 %ds\n", *start, *interval, *maxTime)
	fmt.Println("------------------------------------------------")

	// 处理 Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	go func() {
		<-sigChan
		fmt.Println("\n用户终止测试。")
		os.Exit(0)
	}()

	for t := *start; t <= *maxTime; t += *interval {
		fmt.Printf("\n[测试中] 尝试静默 %d 秒...\n", t)

		// 发送指令给服务端
		msg := fmt.Sprintf("WAIT:%d", t)
		conn.Write([]byte(msg))

		// 客户端本地同步休眠 (和 Python 一样)
		time.Sleep(time.Duration(t) * time.Second)

		// 设置接收超时 (略大于步长)
		conn.SetReadDeadline(time.Now().Add(15 * time.Second))

		// 尝试接收
		buf := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("❌ 失败: 在 %d 秒时触发超时 (NAT 已丢弃包)\n", t)
			fmt.Printf("💡 结论: 你的 NAT 连接保持时长约为 %d 到 %d 秒之间。\n", t-*interval, t)
			break
		}

		reply := string(buf[:n])
		if reply == "PONG" {
			fmt.Printf("✅ 成功: %d 秒时 NAT 映射依然有效\n", t)
		} else {
			fmt.Printf("❓ 异常: 收到非预期数据 %s\n", reply)
		}
	}
}
