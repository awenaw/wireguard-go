# WireGuard-Go 源码架构解析

## 1. 核心流水线 (The Pipeline)
> **这是心脏，负责搬运数据。**

*   **相关文件**: `device.go` (Device/State/Goroutines), `receive.go`, `send.go`
*   **核心概念**: 
    *   Producer-Consumer (生产-消费模型)
    *   Channel Dispatch (通道分发)
    *   Concurrent Workers (并行工作者)
    *   Sequential Delivery (串行交付)
*   **主要职责**: 
    *   从 TUN 虚拟网卡读取数据 -> 加密 -> 通过 UDP 发送
    *   从 UDP Socket 接收数据 -> 解密 -> 写入 TUN 虚拟网卡

## 2. 密码学与握手 (Crypto & Handshake)
> **这是大脑，负责协商密钥。**

*   **相关文件**: `noise-protocol.go`, `noise-helpers.go`, `handshake.go`, `cookie.go`
*   **核心概念**: 
    *   Noise_IK Pattern (Noise 协议模式)
    *   ECDH (Curve25519 密钥交换)
    *   ChaCha20Poly1305 (AEAD 加密认证)
    *   Cookie/MAC 验证 (抗 DoS 防御)
*   **主要职责**: 
    *   生成和解析 Type 1 (Initiation), Type 2 (Response), Type 3 (Cookie Reply) 握手包
    *   计算 Session Key (会话密钥)
    *   处理高负载下的 Cookie 验证

## 3. 连接与传输 (Connectivity & Transport)
> **这是手脚，负责具体的网络 IO。**

*   **相关文件**: `conn/` (Package), `bind_std.go`, `sticky_*.go`
*   **核心概念**: 
    *   UDP Socket
    *   Sticky Socket (黏性路由)
    *   `recvmsg` / `sendmsg` (系统调用)
    *   GSO (Generic Segmentation Offload) / GRO (Generic Receive Offload) 优化
*   **主要职责**: 
    *   直接调用操作系统的网络 API 发送和接收字节流
    *   处理底层的网络包分段和聚合

## 4. 路由与寻址 (Routing & Addressing)
> **这是门卫，负责决定包去哪里。**

*   **相关文件**: `allowedips.go`, `peer.go`, `indextable.go`
*   **核心概念**: 
    *   Radix Trie (基数树/字典树)
    *   AllowedIPs (允许 IP 列表)
    *   Cryptokey Routing (加密键路由)
    *   Index Table (索引表)
*   **主要职责**: 
    *   `Lookup(IP) -> Peer`: 根据 IP 地址查找对应的 Peer
    *   `Lookup(Index) -> Peer`: 根据连接索引查找对应的 Peer (用于握手)

## 5. 资源管理 (Resource Management)
> **这是后勤，负责粮草和清洁。**

*   **相关文件**: `pools.go`, `timers.go`, `ratelimiter`
*   **核心概念**: 
    *   `sync.Pool` (对象池)
    *   Zero-Allocation (零内存分配原则)
    *   Timer Wheel (时间轮: 用于重握手 Rewind / 密钥更新 Rekey)
    *   Rate Limiting (限流)
*   **主要职责**: 
    *   内存对象的复用与回收
    *   管理定时任务（如保活 Keepalive、会话过期）
    *   防止资源耗尽

## 6. 控制面接口 (Control Plane / UAPI)
> **这是对外的遥控器。**

*   **相关文件**: `uapi.go`, `ipc.go`
*   **核心概念**: 
    *   Configuration Protocol (基于文本的 IPC 协议)
    *   UAPI Listener
*   **主要职责**: 
    *   解析如 `private_key=...` 这样的配置指令
    *   动态修改 Device 的状态（添加删除 Peer、修改密钥等）
