## 运行依赖 (Dependencies)

| 平台 (Platform) | 运行时依赖 (Runtime Deps) | 内核/系统要求 (System Requirements) |
| :--- | :--- | :--- |
| **Linux** (Debian/Ubuntu) | `wireguard-tools`, `iproute2` | 必须支持 TUN/TAP (`/dev/net/tun`)；**无需 5.6+内核** |
| **macOS** | `wireguard-tools` (brew) | 原生支持 `utun`接口 |
| **Windows** | `wintun.dll` (放入 exe 同级) | **必须管理员权限**运行；支持 Wintun 驱动 |
| **编译环境** | `Go 1.22+`, `make` | 需要完整的 Go 编译工具链 |

---

## Windows 运行指南 (Windows Guide)

Windows 版本的开发旨在提供与 Unix/Mac 等同的二开体验。

### 1. 核心依赖
*   **Wintun 驱动**: 请从 [wintun.net](https://www.wintun.net/) 下载 `wintun.dll` 并放置在 `wireguard-go.exe` 的同一目录下。
*   **管理员权限**: 修改网卡和路由表必须以 **管理员身份** 运行 PowerShell/CMD。

### 2. 编译与执行 (单行命令)
建议使用 PowerShell 执行：
```powershell
# 编译
go build -o wireguard-go.exe
## mac环境编译打包成exe
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o wireguard-go.exe

# 设置环境变量并启动 (一次运行)
$env:LOG_LEVEL="debug"; $env:WEBUI_PASSWORD="your_password"; ./wireguard-go.exe wg0
```

### 3. 本地路由关键配置
在 `config.json` (或通过 WebUI) 配置时，请务必注意：
*   **internal_subnet**: 在 Windows 下必须使用 **`/24`** 掩码（例如 `10.0.0.7/24`），确保系统路由表能正确覆盖整个网段。若设为 `/32`，则无法通往该网段的其他节点。
*   **WebUI**: 访问 `http://localhost:8080` 进行可视化管理。由于 Windows 命名管道 (UAPI) 权限限制，WebUI 是 Windows 下最稳定的配置方式。

---

## 运行说明 (Running Instructions)

本项目提供两种运行模式：标准快速运行和源码断点调试。

### 1. 快速运行 (标准模式)

一键编译并直接启动服务端（非断点调试）：

```bash
$ make run
```

该命令将执行以下操作：
1. 编译源代码。
2. 运行 `wg_config/start_server.sh` (需要 sudo 创建网络接口)。
3. 在端口 `38200` 启动 WireGuard 控制器。
4. 在 `http://localhost:8080` 启动调试 WebUI。

### 2. 源码断点调试 (Source Debugging)

使用 Delve 调试器进行源码级断点调试。

#### 前置条件
确保已安装 `dlv` (Delve) 调试器：
```bash
brew install delve
```

#### 启动步骤

1. **启动调试服务端**
   
   ```bash
   sudo ./wg_config/debug_start.sh
   # 此时终端会显示: "Delve 监听: 127.0.0.1:2345" 并等待连接
   ```

2. **连接 VS Code**
   
   确保 `.vscode/launch.json` 包含以下配置：

   ```json
   {
       "version": "0.2.0",
       "configurations": [
           {
               "name": "Attach to WireGuard-Go",
               "type": "go",
               "request": "attach",
               "mode": "remote",
               "port": 2345,
               "host": "127.0.0.1",
               "apiVersion": 2
           }
       ]
   }
   ```
   
   然后按 `F5` 选择 **"Attach to WireGuard-Go"** 开始调试。

3. **配置接口 (自动/手动)**
   
   ```bash
   ./wg_config/debug_config.sh
   ```


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
