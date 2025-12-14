#!/bin/bash

# WireGuard-Go 停止脚本

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TUN_NAME_FILE="$SCRIPT_DIR/.tun_name"

# 读取接口名
if [ -f "$TUN_NAME_FILE" ]; then
    INTERFACE=$(cat "$TUN_NAME_FILE")
    echo "停止 WireGuard 接口: $INTERFACE"
    
    # 删除 socket 文件会触发 wireguard-go 退出
    if [ -S "/var/run/wireguard/$INTERFACE.sock" ]; then
        rm -f "/var/run/wireguard/$INTERFACE.sock"
        echo "已发送停止信号"
    fi
else
    echo "未找到运行中的接口"
fi

# 确保进程已终止
pkill -f "wireguard-go.*utun" 2>/dev/null || true

echo "完成"
