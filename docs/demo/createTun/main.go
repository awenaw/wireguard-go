package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// 这个 Demo 展示了如何像 wireguard-go 一样创建一个 TUN 设备（虚拟网卡）
// 在 MacOS 上运行通常需要 sudo 权限，或者会有系统弹窗请求权限。
// sudo go run main.go
// p2p 模式
// sudo ifconfig utun996 10.0.0.1 10.0.0.2 up
// ping 10.0.0.2
// vpn模式
// sudo ifconfig utun996 10.0.0.1 10.0.0.1 up
//sudo route add -net 10.0.0.0/24 -interface utun996

func main() {
	// 1. 定义网卡名称
	// 在 MacOS 上通常是 utun0, utun1 等。如果填 "" 系统会自动分配。
	interfaceName := "utun996"
	if runtime.GOOS == "linux" {
		interfaceName = "wg0"
	}

	fmt.Printf("🚀 正在尝试创建虚拟网卡: %s...\n", interfaceName)

	// 2. 调用 wireguard-go/tun 包创建设备
	// 参数: 预期的网卡名, MTU (1420 是 WireGuard 的标准值)
	tdev, err := tun.CreateTUN(interfaceName, device.DefaultMTU)
	if err != nil {
		fmt.Printf("❌ 创建失败: %v\n", err)
		if os.Geteuid() != 0 {
			fmt.Println("💡 提示: 尝试使用 'sudo' 运行此程序。")
		}
		return
	}

	// 确保程序退出时关闭设备
	defer tdev.Close()

	// 3. 获取网卡的真实名称 (如果是自动分配的，这里能拿到具体是 utunX)
	realName, _ := tdev.Name()
	mtu, _ := tdev.MTU()

	fmt.Println("✅ 虚拟网卡创建成功!")
	fmt.Printf("   网卡名称: %s\n", realName)
	fmt.Printf("   MTU 值  : %d\n", mtu)
	fmt.Println("\n------------------------------------------------")
	fmt.Println("现在你可以打开另一个终端运行 'ifconfig' 或 'ip addr' 查看它。")
	fmt.Println("按 Ctrl+C 退出并销毁该网卡。")
	fmt.Println("------------------------------------------------")

	// 4. 演示循环读取 (可选)
	// 在真实的 WireGuard 中，此时会启动协程不断从 tdev.File() 中读取原始 IP 包。
	go func() {
		// 注意 1：wireguard-go 的 TUN 接口支持批量读取以提高性能
		bufs := make([][]byte, 1)
		bufs[0] = make([]byte, mtu+100)
		sizes := make([]int, 1)

		// 注意 2：在 Darwin (MacOS) 平台上，Read 操作会尝试访问 offset-4 的位置
		// 用来存放系统自带的 4 字节头部。如果 offset 为 0 会触发 panic。
		const offset = 4

		for {
			// n 是读取到的数据包数量
			n, err := tdev.Read(bufs, sizes, offset)
			if err != nil {
				return
			}
			for i := 0; i < n; i++ {
				if sizes[i] > 0 {
					// 真正的 IP 数据包是从 offset 开始的
					packet := bufs[i][offset : offset+sizes[i]]
					fmt.Printf("📥 捕获到来自 OS 的数据包! 长度: %d 字节, IP版本: %d\n", sizes[i], packet[0]>>4)
				}
			}
		}
	}()

	// 5. 等待退出信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println("\n👋 正在关闭设备并退出...")
}
