/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/manager"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s INTERFACE-NAME\n", os.Args[0])
		os.Exit(ExitSetupFailed)
	}
	interfaceName := os.Args[1]

	fmt.Fprintln(os.Stderr, "Warning: this is a test program for Windows, mainly used for debugging this Go package. For a real WireGuard for Windows client, the repo you want is <https://git.zx2c4.com/wireguard-windows/>, which includes this code as a module.")

	// 获取日志等级 (默认: info)
	logLevel := func() int {
		switch os.Getenv("LOG_LEVEL") {
		case "verbose", "debug":
			return device.LogLevelVerbose
		case "error":
			return device.LogLevelError
		case "silent":
			return device.LogLevelSilent
		}
		return device.LogLevelError
	}()

	logger := device.NewLogger(
		logLevel,
		fmt.Sprintf("(%s) ", interfaceName),
	)
	logger.Verbosef("Starting wireguard-go version %s", Version)

	// 创建 TUN 设备
	tdev, err := tun.CreateTUN(interfaceName, 0)
	if err == nil {
		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}
	} else {
		logger.Errorf("Failed to create TUN device: %v", err)
		os.Exit(ExitSetupFailed)
	}

	// 初始化设备核心
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	logger.Verbosef("Device created")

	// 加载并应用持久化配置
	config, err := manager.LoadConfig()
	if err != nil {
		logger.Errorf("Failed to load config: %v", err)
	} else {
		// 确保身份存在
		if config.EnsureIdentity() {
			if err := manager.SaveConfig(config); err != nil {
				logger.Errorf("Failed to save auto-generated identity: %v", err)
			} else {
				logger.Verbosef("Auto-generated new server identity")
			}
		}

		if err := config.ApplyToDevice(dev); err != nil {
			logger.Errorf("Failed to apply config to device: %v", err)
		} else {
			logger.Verbosef("Persistent configuration applied successfully")
			// 激活网卡设备 (开启数据平面)
			if err := dev.Up(); err != nil {
				logger.Errorf("Failed to bring up device: %v", err)
			}
			// 自动化配置网卡 IP 和 状态 (在 Windows 下需要管理员权限以运行 netsh)
			if err := config.ConfigureInterface(interfaceName); err != nil {
				logger.Errorf("Auto-config interface failed: %v (Try running as Administrator)", err)
			} else {
				logger.Verbosef("Interface %s auto-configured", interfaceName)
			}
		}
	}

	logger.Verbosef("Device started")

	// 启动 Web UI (这个通常不受 Windows 管道权限影响)
	webUI := manager.NewWebUI(dev, config, ":8080")
	if err := webUI.Start(); err != nil {
		logger.Errorf("Failed to start WebUI: %v", err)
	} else {
		logger.Verbosef("WebUI available at http://localhost:8080")
	}

	errs := make(chan error)
	term := make(chan os.Signal, 1)

	// 监听 UAPI (容错处理：Windows 管道权限问题可能导致失败)
	uapi, err := ipc.UAPIListen(interfaceName)
	if err != nil {
		logger.Errorf("UAPI pipe creation failed: %v. You can still use WebUI to manage.", err)
	} else {
		go func() {
			for {
				conn, err := uapi.Accept()
				if err != nil {
					return
				}
				go dev.IpcHandle(conn)
			}
		}()
		logger.Verbosef("UAPI listener started")
	}

	// 等待退出信号
	signal.Notify(term, os.Interrupt)
	signal.Notify(term, os.Kill)
	signal.Notify(term, windows.SIGTERM)

	select {
	case <-term:
	case <-errs:
	case <-dev.Wait():
	}

	// 清理资源
	webUI.Stop()
	if uapi != nil {
		uapi.Close()
	}
	dev.Close()

	logger.Verbosef("Shutting down")
}
