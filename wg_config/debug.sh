#!/bin/bash

# WireGuard-Go 调试脚本
# 使用 Delve 调试器，需要 root 权限

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TUN_NAME_FILE="$SCRIPT_DIR/.tun_name"

# 检查 Delve 是否安装
if ! command -v dlv &> /dev/null; then
    echo "正在安装 Delve 调试器..."
    go install github.com/go-delve/delve/cmd/dlv@latest
fi

echo "=== WireGuard-Go 调试模式 ==="
echo ""
echo "调试器将监听在 127.0.0.1:2345"
echo "可以用 VS Code 的 'Attach to WireGuard-Go' 配置连接"
echo ""

cd "$PROJECT_DIR"

# 编译带调试信息的版本
echo "[1/2] 编译调试版本..."
go build -gcflags="all=-N -l" -o wireguard-go-debug

# 使用 Delve 启动
echo "[2/2] 启动调试器..."
echo ""
echo "常用命令:"
echo "  b main.main     - 在 main 函数设置断点"
echo "  b device.go:100 - 在指定行设置断点"
echo "  c               - 继续执行"
echo "  n               - 单步执行"
echo "  s               - 步入函数"
echo "  p <变量>         - 打印变量"
echo "  q               - 退出"
echo ""

# 以 root 权限启动 Delve（headless 模式供远程连接）
sudo WG_TUN_NAME_FILE="$TUN_NAME_FILE" LOG_LEVEL=debug \
    dlv exec ./wireguard-go-debug -- -f utun
