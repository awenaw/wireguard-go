package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// 1. 定义云端下发的 JSON 结构 (这就是我们要处理的乐高块)
type CloudConfig struct {
	PrivateKey string `json:"private_key"` // 实际场景中私钥通常在本地，这里为了演示包含进来
	ListenPort int    `json:"listen_port"`
	Peers      []Peer `json:"peers"`
}

type Peer struct {
	PublicKey  string   `json:"public_key"`
	Endpoint   string   `json:"endpoint"`
	AllowedIPs []string `json:"allowed_ips"`
}

func main() {
	// 2. 模拟收到的一段 JSON 字符串
	jsonStr := `{
		"private_key": "WKJIVRKfxJR1ybJoTIyxI1utCWVeZ0Zes1QDa07BJ3Y=",
		"listen_port": 51820,
		"peers": [
			{
				"public_key": "f4uHssluh2IT2O/4wOt0Lv73f4Fl8P3plAanQxsIHgM=",
				"endpoint": "1.2.3.4:38200",
				"allowed_ips": ["10.166.0.1/32", "10.10.0.0/16"]
			}
		]
	}`

	// 3. 解析 JSON
	var cfg CloudConfig
	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		panic(err)
	}

	// 4. 转换成 UAPI 文本 (积木拼接过程)
	var sb strings.Builder

	// Part 1: Device Config
	sb.WriteString("set=1\n") // 动作指令
	fmt.Fprintf(&sb, "private_key=%s\n", cfg.PrivateKey)
	fmt.Fprintf(&sb, "listen_port=%d\n", cfg.ListenPort)
	sb.WriteString("replace_peers=true\n") // 覆盖模式

	// Part 2: Peer Config
	for _, peer := range cfg.Peers {
		fmt.Fprintf(&sb, "public_key=%s\n", peer.PublicKey)
		fmt.Fprintf(&sb, "endpoint=%s\n", peer.Endpoint)
		fmt.Fprintf(&sb, "persistent_keepalive_interval=25\n") // 默认写死保活

		for _, ip := range peer.AllowedIPs {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", ip)
		}
	}
	// 结尾空行 (协议要求)
	sb.WriteString("\n")

	// 5. 展示成果
	fmt.Println("--- Generated UAPI Command ---")
	fmt.Print(sb.String())
	fmt.Println("------------------------------")
	fmt.Println("(这段文本就是可以直接喂给 wireguard-go Socket 的最终指令)")
}
