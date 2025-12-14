# WireGuard-Go macOS 调试完全指南

> 本文档记录了在 macOS 上运行和调试 wireguard-go 的完整流程。

---

## 🚀 快速开始

### 调试模式（推荐）

必须严格按照以下顺序操作，否则会报错 `No such file or directory`：

1. **启动调试服务器**（终端 1）：
   ```bash
   sudo ./wg_config/debug_start.sh
   # 此时程序会暂停并显示 "API server listening at: 127.0.0.1:2345"
   # 不要关闭这个终端！
   ```

2. **连接调试器**（VS Code）：
   - 按 `F5`（确保选择 "Attach to WireGuard-Go"）。
   - **关键步骤**：连接成功后，程序依然是暂停状态，必须再次点击调试工具栏的 **"继续/运行"** 按钮（或再按一次 `F5`），让程序真正跑起来。

3. **下发配置**（终端 2）：
   - 必须等步骤 2 完成，程序开始运行后才能执行。
   ```bash
   sudo ./wg_config/debug_config.sh
   ```

### 普通模式（不调试）

```bash
# 启动服务端
sudo ./wg_config/start_server.sh

# 停止服务端
sudo ./wg_config/stop_server.sh
## 📋 环境要求

## 🚀 快速开始

### 普通模式（不调试）

```bash
# 启动服务端
sudo ./wg_config/start_server.sh

# 停止服务端
sudo ./wg_config/stop_server.sh
```

### 调试模式

### 调试模式

必须严格按照以下顺序操作，否则会报错 `No such file or directory`：

1. **启动调试服务器**（终端 1）：
   ```bash
   sudo ./wg_config/debug_start.sh
   # 此时程序会暂停并显示 "API server listening at: 127.0.0.1:2345"
   # 不要关闭这个终端！
   ```

2. **连接调试器**（VS Code）：
   - 按 `F5`（确保选择 "Attach to WireGuard-Go"）。
   - **关键步骤**：连接成功后，程序依然是暂停状态，必须再次点击调试工具栏的 **"继续/运行"** 按钮（或再按一次 `F5`），让程序真正跑起来。

3. **下发配置**（终端 2）：
   - 必须等步骤 2 完成，程序开始运行后才能执行。
   ```bash
   sudo ./wg_config/debug_config.sh
   ```

---

## 🛠️ 脚本说明

| 脚本 | 用途 | 权限 |
|------|------|------|
| `debug_start.sh` | 编译调试版 + 启动 Delve | 普通用户 |
| `debug_config.sh` | 配置 WireGuard 服务端 | 需要 sudo |
| `start_server.sh` | 普通模式启动 | 需要 sudo |
| `stop_server.sh` | 停止服务端 | 需要 sudo |

---

## 📱 网络配置

### 服务端 (macOS)

| 配置项 | 值 |
|--------|-----|
| 接口名 | 自动分配 (utun) |
| 监听端口 | 38200 |
| 服务端 IP | 10.166.0.1 |
| VPN 网段 | 10.166.0.0/24 |
| 服务端公钥 | `f4uHssluh2IT2O/4wOt0Lv73f4Fl8P3plAanQxsIHgM=` |

### 客户端

| 设备 | IP | 配置文件 |
|------|-----|----------|
| iPhone | 10.166.0.2 | `wg_config/iphone.conf` |
| Debian | 10.166.0.3 | `wg_config/debian.conf` |

---

## 🐛 VS Code 调试配置

### launch.json

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug Test - TwoDevicePing",
            "type": "go",
            "request": "launch",
            "mode": "test",
            "program": "${workspaceFolder}/device",
            "args": ["-test.run", "TestTwoDevicePing", "-test.v"]
        },
        {
            "name": "Attach to WireGuard-Go",
            "type": "go",
            "request": "attach",
            "mode": "remote",
            "remotePath": "${workspaceFolder}",
            "port": 2345,
            "host": "127.0.0.1"
        }
    ]
}
```

### 调试流程

1. **启动 Delve**：运行 `./wg_config/debug_start.sh`
2. **连接 VS Code**：按 `F5` 选择 "Attach to WireGuard-Go"
3. **让程序运行**：再按 `F5`
4. **配置服务端**：运行 `sudo ./wg_config/debug_config.sh`
5. **设置断点**：在代码中点击行号左侧
6. **触发断点**：从客户端发送请求

---

## 🎯 关键断点位置

### 数据包接收

| 文件 | 行号 | 代码 | 说明 |
|------|------|------|------|
| `device/receive.go` | 465 | `if len(elem.packet) == 0` | Keepalive 包 |
| `device/receive.go` | 469 | `dataPacketReceived = true` | 真实数据包 |
| `device/receive.go` | 524 | `device.tun.device.Write(...)` | 写入 TUN |

### 握手流程

| 文件 | 函数 | 说明 |
|------|------|------|
| `device/receive.go:278` | `RoutineHandshake` | 处理握手消息 |
| `device/noise-protocol.go` | `ConsumeMessageInitiation` | 解析握手请求 |
| `device/noise-protocol.go` | `CreateMessageResponse` | 创建握手响应 |

### 数据包发送

| 文件 | 函数 | 说明 |
|------|------|------|
| `device/send.go` | `RoutineSequentialSender` | 发送加密数据包 |

---

## 📝 添加自定义日志

在代码中添加日志示例：

```go
// 带时间戳的日志
device.log.Verbosef("%v - 我进来了 [keepalive] 时间: %s", peer, time.Now().Format("2006-01-02 15:04:05.000"))
```

修改代码后需要：
1. 重新编译：`go build -gcflags="all=-N -l" -o wireguard-go-debug`
2. 重启调试服务器

---

## 🧪 测试方法

### 使用单元测试（最干净）

```bash
# VS Code 选择 "Debug Test - TwoDevicePing"
# 按 F5 启动
```

### 使用 Debian 客户端

```bash
# Debian 上
unset all_proxy http_proxy https_proxy  # 清除代理

ping 10.166.0.1                         # 测试连通性

echo -e "GET / HTTP/1.0\r\n\r\n" | nc 10.166.0.1 8080  # 最小 HTTP 请求

curl http://10.166.0.1:8080/            # 完整 HTTP 请求
```

### 最小 HTTP 服务器

```bash
# Mac 上运行
while true; do echo -e "HTTP/1.0 200 OK\r\n\r\nOK" | nc -l 8080; done
```

---

## ⌨️ 调试快捷键

| 快捷键 | 功能 |
|--------|------|
| `F5` | 继续运行 / 连接调试器 |
| `F10` | 单步跳过 |
| `F11` | 单步进入 |
| `Shift+F11` | 跳出函数 |
| `Shift+F5` | 停止调试 |
| `Cmd+G` | 跳转到行号 |

---

## 📂 目录结构

```
wg_config/
├── .tun_name              # 当前接口名（运行时生成）
├── server_private.key     # 服务端私钥
├── server_public.key      # 服务端公钥
├── iphone_private.key     # iPhone 私钥
├── iphone_public.key      # iPhone 公钥
├── iphone.conf            # iPhone 配置文件
├── iphone_qr.png          # iPhone 二维码
├── debian_private.key     # Debian 私钥
├── debian_public.key      # Debian 公钥
├── debian.conf            # Debian 配置文件
├── start_server.sh        # 普通模式启动脚本
├── stop_server.sh         # 停止脚本
├── debug_start.sh         # 调试模式启动脚本
├── debug_config.sh        # 调试模式配置脚本
└── DEBUG_GUIDE.md         # 本文档
```

---

## 🗺️ 核心代码导航

| 目录/文件 | 说明 |
|-----------|------|
| `main.go` | 程序入口，TUN 设备创建，UAPI 监听 |
| `device/device.go` | 核心设备结构和生命周期管理 |
| `device/peer.go` | Peer 连接管理 |
| `device/send.go` | 数据包发送逻辑 |
| `device/receive.go` | 数据包接收逻辑 |
| `device/noise-protocol.go` | Noise 协议握手实现 |
| `device/timers.go` | 定时器和重传逻辑 |
| `conn/` | 网络绑定（UDP socket） |
| `tun/` | TUN 设备抽象 |
| `ipc/` | UAPI 控制接口 |

---

## 🔧 常用命令

```bash
# 查看 WireGuard 状态
sudo wg show

# 测试连通性
ping 10.166.0.1

# 查看接口信息
ifconfig utun6

# 查看路由
netstat -rn | grep 10.166

# 编译调试版本
go build -gcflags="all=-N -l" -o wireguard-go-debug

# 编译普通版本
make
```

---

## ⚠️ 注意事项

1. **Delve 需要 sudo**：因为 wireguard-go 需要 root 权限创建 TUN 接口
2. **代理环境变量**：Debian 上使用前记得 `unset all_proxy http_proxy https_proxy`
3. **macOS TUN 限制**：本机无法直接访问 TUN 接口的 IP，需从外部客户端访问
4. **Keepalive 干扰**：调试时建议用条件断点过滤 keepalive 包
5. **报错 `Unable to modify interface`**：这通常是因为您在 VS Code 中连接调试器后忘了按第二次 F5 让程序运行，导致 TUN 设备还没被创建。请确保 `debug_start.sh` 的终端已经开始滚动日志或不再阻塞。

---

*创建于 2024-12-14*
