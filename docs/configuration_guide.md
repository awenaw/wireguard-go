# WireGuard 配置指南 (Configuration Guide)

本文档详细说明了 WireGuard 配置文件 (`.conf`) 的各项参数含义，并提供了标准的服务端与客户端配置示例。

## 1. 配置文件结构

WireGuard 的配置文件通常遵循 INI 格式，主要包含两个部分：
*   **[Interface]**: 定义本机（本节点）的网络接口配置。
*   **[Peer]**: 定义与之通信的对端（Peer）节点的配置。一个配置文件可以包含多个 `[Peer]` 块。

---

## 2. [Interface] 块参数说明

这部分配置**本机**的属性。

| 参数 | 必填 | 说明 |
| :--- | :---: | :--- |
| **PrivateKey** | 是 | 本机的私钥（Base64 编码）。**绝对保密**。由 `wg genkey` 生成。 |
| **Address** | 是 | 本机在 VPN 网络中的 IP 地址（CIDR 格式）。<br>例如：`10.0.0.1/24` (IPv4) 或 `fd00::1/64` (IPv6)。 |
| **ListenPort** | 否 | 本机监听的 UDP 端口。<br>**服务端**：通常固定为 `51820`。<br>**客户端**：通常不填（随机端口）或填 `0`，除非位于某些需要特定端口防火墙后。 |
| **DNS** | 否 | 隧道建立后使用的 DNS 服务器地址。<br>常用于客户端，确保 DNS 请求也走 VPN 隧道。 |
| **MTU** | 否 | 最大传输单元。默认通常是 1420。如果遇到网络包丢失或卡顿，可尝试调小（如 1280）。 |
| **PostUp** | 否 | 接口启动**后**执行的脚本命令。<br>常用于服务端设置 iptables 转发规则（NAT）。 |
| **PostDown** | 否 | 接口关闭**后**执行的脚本命令。<br>常用于清除 iptables 规则。 |
| **PreUp** / **PreDown** | 否 | 接口启动前 / 关闭前执行的命令。 |

---

## 3. [Peer] 块参数说明

这部分配置**对方**的属性。你需要为每一个连接的设备添加一个 `[Peer]` 块。

| 参数 | 必填 | 说明 |
| :--- | :---: | :--- |
| **PublicKey** | 是 | **对方**的公钥（Base64 编码）。由 `wg pubkey` 从对方私钥生成。 |
| **AllowedIPs** | 是 | **核心路由参数**。定义允许从该 Peer 接收哪些 IP 的包，以及路由哪些 IP 的包给该 Peer。<br>**服务端视角**：通常填客户端的 VPN IP（如 `10.0.0.2/32`），表示“这个 IP 是这个人的”。<br>**客户端视角**：若要全局代理（所有流量走 VPN），填 `0.0.0.0/0, ::/0`；若只访问内网，填内网网段（如 `10.0.0.0/24`）。 |
| **Endpoint** | 否 | **对方**的公网地址和端口（`IP:Port`）。<br>**客户端**：必须填服务端的公网地址（如 `vip.example.com:51820`）。<br>**服务端**：通常不填，因为客户端 IP 是变动的（Roaming），服务端会被动学习客户端的 Endpoint。 |
| **PersistentKeepalive** | 否 | 心跳包间隔（秒）。<br>**NAT 后设备必备**。通常填 `25`。<br>用于防止 NAT 映射在路由器上过期，保持连接活跃。 |
| **PresharedKey** | 否 | 预共享密钥（可选，增强安全性）。双方必须配置完全相同的 Key。 |

---

## 4. 配置示例

假设场景：
*   **VPN 网段**: `10.0.0.0/24`
*   **服务端**: 公网 IP `1.2.3.4`，内网 VPN IP `10.0.0.1`，监听端口 `51820`。
*   **客户端**: 处于 NAT 后（家里），内网 VPN IP `10.0.0.2`。

### 4.1. 服务端配置 (`/etc/wireguard/wg0.conf`)

服务端通常作为中心节点，拥有固定的公网 IP 和端口。

```ini
[Interface]
# --- 本机身份 ---
PrivateKey = <服务端私钥_Private_Key>
Address = 10.0.0.1/24
ListenPort = 51820

# --- 路由转发与 NAT (这是让客户端能上网的关键) ---
# 启动时：开启 IP 转发，设置 NAT 伪装
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# 关闭时：清理规则
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# --- 客户端 1 (手机) ---
[Peer]
PublicKey = <客户端1公钥_Public_Key>
# 允许此 Peer 使用 10.0.0.2 这个 IP
AllowedIPs = 10.0.0.2/32

# --- 客户端 2 (笔记本) ---
[Peer]
PublicKey = <客户端2公钥_Public_Key>
AllowedIPs = 10.0.0.3/32
```

### 4.2. 客户端配置 (`client.conf`)

客户端通常位於 NAT 后面，需要主动连接服务端。

```ini
[Interface]
# --- 本机身份 ---
PrivateKey = <客户端私钥_Private_Key>
Address = 10.0.0.2/24    # 自己的 VPN IP
DNS = 8.8.8.8            # 可选：让 DNS 查询走隧道

[Peer]
# --- 连接服务端 ---
PublicKey = <服务端公钥_Public_Key>

# --- 流量路由 ---
# 场景 A (全局代理)：所有流量都走 VPN -> 填 0.0.0.0/0
# 场景 B (仅访问内网)：只填服务端 VPN 网段 -> 填 10.0.0.0/24
AllowedIPs = 0.0.0.0/0

# --- 连接地址 ---
Endpoint = 1.2.3.4:51820

# --- NAT 穿透保活 ---
# 非常重要！只要客户端在 NAT 后，建议设置为 25
PersistentKeepalive = 25
```

---

## 5. 关键原理解析

### 5.1. `AllowedIPs` 的双重作用

这是新手最容易混淆的参数，它同时充当 **路由表** 和 **防火墙**：

1.  **出站 (路由)**: 当本机要发包给 `10.0.0.5` 时，WireGuard 会查 AllowedIPs 列表。
    *   如果发现 `10.0.0.5` 在 `[Peer A]` 的 AllowedIPs 里，就用 Peer A 的公钥加密并发送。
    *   这就是为什么客户端填 `0.0.0.0/0` 会让所有流量都发给服务端。

2.  **入站 (防火墙 ACL)**: 当本机从 `[Peer A]` 收到一个解密后的包，且包里的**源 IP** 是 `10.0.0.5`。
    *   WireGuard 会检查：`10.0.0.5` 真的属于 `[Peer A]` 的 AllowedIPs 吗？
    *   如果**是** -> 接收。
    *   如果**不是** -> **丢弃**（防止 IP 欺骗）。

### 5.2. `Endpoint` 与漫游 (Roaming)

*   **客户端**必须填服务端的 `Endpoint`，否则不知道包往哪发。
*   **服务端**通常不填客户端的 `Endpoint`。
    *   当服务端收到客户端发来的第一个正确加密包时，服务端会**自动更新**该 Peer 的 Endpoint 为“对方刚才发包时的公网 IP:端口”。
    *   这意味着客户端从家里的 WiFi 切换到 4G 网络，IP 变了，只要客户端发一个包过来，服务端自动更新目标地址，连接无缝保持。这就是 **Roaming**。
