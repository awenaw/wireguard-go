
## PVE Alpine 实验台配置 (wg-study)

为方便调试 WireGuard 组网及 P2P 通信，在 Proxmox VE (PVE) 环境下部署了 3 个轻量级 Alpine LXC 容器作为实验节点。

### 1. 实验节点全览

| Hostname | LXC ID | LAN IP | VPN IP (AllowedIPs) | Public Key | Private Key Path |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **wg-study** | 201 | `10.0.0.201` | `10.166.0.201/32` | `vf6g11UBrdxBuvbm4zNomaTYVWB5OJkX1oHBZto0mlA=` | `/etc/wireguard/privatekey` |
| **wg-study2** | 202 | `10.0.0.202` | `10.166.0.202/32` | `4PmfLjpFQFiZbJSbAhLN+VAol8gi0St7B8MS/KLkixU=` | `/etc/wireguard/privatekey` |
| **wg-study3** | 203 | `10.0.0.203` | `10.166.0.203/32` | `ekdwl4M/8DTTks1Y0p6PjWMJPfC9T/7TIe6kw+i0ogE=` | `/etc/wireguard/privatekey` |

> **注**: 所有 LXC 容器的 root 密码均为 `123456`，且已配置 SSH 公钥免密登录。
> 登录方式: `ssh wg-study` 或 `ssh root@10.0.0.20X`

### 2. macOS Server 信息

*   **VPN IP**: `10.166.0.1`
*   **Listen Port**: `38200`
*   **Public Key**: `f4uHssluh2IT2O/4wOt0Lv73f4Fl8P3plAanQxsIHgM=`

### 3. Alpine 节点初始化命令 (One-Liner)

若需重置某个容器或在新容器中重新配置，只需在 Alpine 容器内执行以下命令即可快速连接到 macOS Server。

**重要**: 请将 `ENDPOINT_IP` 替换为 macOS 在局域网内的真实 IP (例如 `10.0.0.x`)。

```bash
# 请将 20X 替换为当前节点的最后一位 IP (例如 201, 202, 203)
MY_ID="201" 
ENDPOINT_IP="10.0.0.X" 

# 安装工具并生成配置
apk add wireguard-tools openresolv && \
mkdir -p /etc/wireguard && \
cat <<CONF > /etc/wireguard/wg0.conf
[Interface]
# 使用已存在的私钥
PrivateKey = $(cat /etc/wireguard/privatekey)
Address = 10.166.0.${MY_ID}/32
DNS = 223.5.5.5

[Peer]
# macOS Server
PublicKey = f4uHssluh2IT2O/4wOt0Lv73f4Fl8P3plAanQxsIHgM=
Endpoint = ${ENDPOINT_IP}:38200
AllowedIPs = 10.166.0.0/24
PersistentKeepalive = 25
CONF

# 启动 WireGuard
wg-quick up wg0
```

### 4. 常用调试命令

*   **查看状态**: `wg show`
*   **测试连通性**: `ping 10.166.0.1` (Ping Server)
*   **节点互 Ping**: `ping 10.166.0.202` (前提是 Server 端已开启转发或配置了路由)

### 5. 快速启动 (调试模式)

一键编译并启动调试服务端（含 WebUI）：

```bash
$ make run
```

该命令将执行以下操作：
1. 编译源代码。
2. 运行 `wg_config/start_server.sh` (需要 sudo 创建网络接口)。
3. 在端口 `38200` 启动 WireGuard 控制器。
4. 在 `http://localhost:8080` 启动调试 WebUI。
