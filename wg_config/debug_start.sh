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

# 4. 启动自动配置监控 (后台运行)
(
    # 清理旧标志
    rm -f wg_config/.tun_name
    
    echo "[自动配置] 等待调试器连接 (请在 VS Code 按 F5)..."
    
    # 循环等待直到 .tun_name 文件生成且非空
    # 这是一个信号，代表 Go 程序已经被 VS Code 唤醒并创建了 TUN 接口
    while [ ! -s wg_config/.tun_name ]; do
        sleep 0.5
    done
    
    echo -e "\r[自动配置] 检测到程序已启动，1秒后执行网络配置..."
    sleep 1 # 等待设备完全就绪
    
    # 执行配置 (通过 sed 修复阶梯状输出)
    ./wg_config/debug_config.sh | sed 's/$/\r/'
) &
MONITOR_PID=$!

# 退出时清理后台进程
trap "kill $MONITOR_PID 2>/dev/null" EXIT


sudo WG_TUN_NAME_FILE="$(pwd)/wg_config/.tun_name" \
     LOG_LEVEL=debug \
     /Users/hmini/go/bin/dlv exec ./wireguard-go-debug \
     --headless --listen=:2345 --api-version=2 -- -f utun
