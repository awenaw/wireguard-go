# Go Implementation of [WireGuard](https://www.wireguard.com/)

This is an implementation of WireGuard in Go.

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-go, instead simply run:

```
$ wireguard-go wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-go shutting down.

To run wireguard-go without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-go -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://git.zx2c4.com/wireguard-go
$ cd wireguard-go
$ make
```

## Quick Start (Debug Mode)

To obtain the binary, configure the interface, and start the debug server with a single command:

```bash
$ make run
```

This will:
1. Compile the code.
2. Run `wg_config/start_server.sh` (requires `sudo` for network interface creation).
3. Start the WireGuard controller on port `38200`.
4. Start a Debug WebUI at `http://localhost:8080`.

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

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
