#!/bin/bash
# WireGuard-Go 调试模式配置脚本
# 在 debug_start.sh 启动并 VS Code 连接后运行此脚本配置服务端

set -e
cd "$(dirname "$0")/.."

echo "=== 配置 WireGuard 服务端 ==="

# 等待接口创建
sleep 1
INTERFACE=$(cat wg_config/.tun_name 2>/dev/null)
if [ -z "$INTERFACE" ]; then
    echo "错误: 接口未创建，请确保 wireguard-go 已运行"
    exit 1
fi

echo "接口: $INTERFACE"

# 配置私钥和端口
echo ""
echo "[1/4] 配置私钥和端口..."
echo "4JEAywd0eJoBKptUOzBdcTH9WuzZuG0Xd8nDhe0ZSFU=" | sudo wg set $INTERFACE private-key /dev/stdin listen-port 38200

# 配置 IP
echo "[2/4] 配置 IP 地址..."
sudo ifconfig $INTERFACE inet 10.166.0.1 10.166.0.1 netmask 255.255.255.0 up
sudo route add -net 10.166.0.0/24 -interface $INTERFACE 2>/dev/null || true

# 添加 peers
echo "[3/4] 添加客户端 peers..."
# Debian
sudo wg set $INTERFACE peer d/bLS0aD77K6N5tv9PqywHn3w8djtuouK6i86dT2mXs= allowed-ips 10.166.0.3/32
echo "  已添加 Debian (10.166.0.3)"
# iPhone
sudo wg set $INTERFACE peer WKO1H3uFd1YYlMHGn1GltA6npl9RLsF9E0x3OIugcnU= allowed-ips 10.166.0.2/32
echo "  已添加 iPhone (10.166.0.2)"

# 显示状态
echo ""
echo "[4/4] 当前配置:"
sudo wg show $INTERFACE

echo ""
echo "=== 配置完成 ==="
echo "可以开始调试了！"
