package main

import (
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

func main() {
	port := 51830
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	log.Printf("✅ 服务端启动成功，正在监听 UDP 端口: %d", port)

	buf := make([]byte, 1024)
	for {
		log.Println("等待客户端连接...")
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("ReadFromUDP error: %v", err)
			continue
		}

		msg := string(buf[:n])
		log.Printf("收到来自 %s 的请求: %s", addr, msg)

		// 支持 WAIT:N 和 PING:N 两种格式
		var waitTime int
		if strings.HasPrefix(msg, "WAIT:") {
			waitTime, _ = strconv.Atoi(strings.TrimPrefix(msg, "WAIT:"))
		} else if strings.HasPrefix(msg, "PING:") {
			waitTime, _ = strconv.Atoi(strings.TrimPrefix(msg, "PING:"))
		} else {
			log.Printf("数据格式错误: %s", msg)
			continue
		}

		// 在 goroutine 中处理回复
		go func(addr *net.UDPAddr, waitTime int) {
			log.Printf("⏳ 进入休眠，等待 %d 秒...", waitTime)
			time.Sleep(time.Duration(waitTime) * time.Second)
			log.Printf("🚀 休眠结束，尝试回写 PONG 到 %s", addr)
			conn.WriteToUDP([]byte("PONG"), addr)
		}(addr, waitTime)
	}
}
