#!/bin/bash
# WireGuard-Go 调试启动脚本
# 使用方法: ./wg_config/debug_start.sh
# 启动后在 VS Code 按 F5 选择 "Attach to WireGuard-Go" 连接调试器

set -e
cd "$(dirname "$0")/.."

echo "=== WireGuard-Go 调试模式 ==="
echo ""

# 1. 编译调试版本
echo "[1/3] 编译调试版本..."
go build -gcflags="all=-N -l" -o wireguard-go-debug
echo "  编译完成: wireguard-go-debug"

# 2. 清理旧进程
echo ""
echo "[2/3] 清理旧进程..."
sudo pkill -f "wireguard-go" 2>/dev/null || true
sudo pkill -f "dlv.*wireguard" 2>/dev/null || true
sleep 1

# 3. 启动 Delve
echo ""
echo "[3/3] 启动 Delve 调试服务器..."
echo ""
echo "============================================"
echo "  Delve 监听: 127.0.0.1:2345"
echo "  VS Code: 按 F5 选择 'Attach to WireGuard-Go'"
echo "  连接后按 F5 让程序运行"
echo "  然后运行: ./wg_config/debug_config.sh 配置服务端"
echo "============================================"
echo ""
echo "日志将显示在下方 (Ctrl+C 停止):"
echo ""

sudo WG_TUN_NAME_FILE="$(pwd)/wg_config/.tun_name" \
     LOG_LEVEL=debug \
     /Users/hmini/go/bin/dlv exec ./wireguard-go-debug \
     --headless --listen=:2345 --api-version=2 -- -f utun
