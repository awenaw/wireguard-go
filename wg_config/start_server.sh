#!/bin/bash

# WireGuard-Go macOS 服务端启动脚本
# 使用方法: sudo ./start_server.sh

set -e

# 配置参数
LISTEN_PORT="38200"
SERVER_PRIVATE_KEY="4JEAywd0eJoBKptUOzBdcTH9WuzZuG0Xd8nDhe0ZSFU="
SERVER_IP="10.166.0.1"
SERVER_NETMASK="255.255.255.0"
VPN_NETWORK="10.166.0.0/24"

# 项目目录
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# 接口名文件（用于获取内核分配的实际接口名）
TUN_NAME_FILE="$SCRIPT_DIR/.tun_name"

echo "=== WireGuard-Go 服务端启动 ==="
echo "监听端口: $LISTEN_PORT"
echo "服务端 IP: $SERVER_IP"

# 1. 启动 wireguard-go（使用 utun 让内核自动分配接口名）
echo ""
echo "[1/5] 启动 wireguard-go..."
rm -f "$TUN_NAME_FILE"
WG_TUN_NAME_FILE="$TUN_NAME_FILE" LOG_LEVEL=debug "$PROJECT_DIR/wireguard-go" -f utun &
WG_PID=$!
sleep 2

# 检查进程是否启动成功
if ! kill -0 $WG_PID 2>/dev/null; then
    echo "错误: wireguard-go 启动失败"
    exit 1
fi

# 读取实际分配的接口名
if [ -f "$TUN_NAME_FILE" ]; then
    INTERFACE=$(cat "$TUN_NAME_FILE")
    echo "内核分配的接口名: $INTERFACE"
else
    echo "错误: 无法获取接口名"
    kill $WG_PID 2>/dev/null
    exit 1
fi

echo "wireguard-go 进程 PID: $WG_PID"

# 2. 配置 WireGuard 接口
echo ""
echo "[2/5] 配置 WireGuard..."
wg set "$INTERFACE" \
    private-key <(echo "$SERVER_PRIVATE_KEY") \
    listen-port "$LISTEN_PORT"

# 3. 配置 IP 地址
echo ""
echo "[3/5] 配置 IP 地址..."
ifconfig "$INTERFACE" inet "$SERVER_IP" "$SERVER_IP" netmask "$SERVER_NETMASK" up
route add -net "$VPN_NETWORK" -interface "$INTERFACE" 2>/dev/null || true

# 4. 添加已知的客户端 peer
echo ""
echo "[4/5] 添加客户端 peer..."
# iPhone peer
wg set "$INTERFACE" peer WKO1H3uFd1YYlMHGn1GltA6npl9RLsF9E0x3OIugcnU= allowed-ips 10.166.0.2/32
echo "  已添加 iPhone peer (10.166.0.2)"
# Debian peer
wg set "$INTERFACE" peer d/bLS0aD77K6N5tv9PqywHn3w8djtuouK6i86dT2mXs= allowed-ips 10.166.0.3/32
echo "  已添加 Debian peer (10.166.0.3)"

# 5. 显示配置信息
echo ""
echo "[5/5] 当前配置:"
wg show "$INTERFACE"

echo ""
echo "=== 服务端已启动 ==="
echo ""
echo "接口名: $INTERFACE"
echo "客户端配置信息："
echo "  服务端公钥: f4uHssluh2IT2O/4wOt0Lv73f4Fl8P3plAanQxsIHgM="
echo "  端点地址: <你的局域网IP>:$LISTEN_PORT"
echo "  允许的 IP: $VPN_NETWORK"
echo ""
echo "添加客户端 peer 示例:"
echo "  sudo wg set $INTERFACE peer <客户端公钥> allowed-ips 10.166.0.x/32"
echo ""
echo "按 Ctrl+C 停止服务..."

# 等待进程
wait $WG_PID
