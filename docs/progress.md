# WireGuard-Go 源码阅读宏观进度

## ✅ 已达成成就 (55%)

### 1. 核心数据平面 (Data Plane) - **S 级通关**
*   **收包流水线 (`receive.go`)**
    *   [x] `RoutineReceiveIncoming`: 批量收包、双通道分发
    *   [x] `RoutineDecryption`: 并行 ChaCha20 解密
    *   [x] `RoutineSequentialReceiver`: 串行保序、防重放、AllowedIPs 过滤、写 TUN
*   **发包流水线 (`send.go`)**
    *   [x] `RoutineReadFromTUN`: 读 TUN、查路由
    *   [x] `StagePackets` & `SendStagedPackets`: **关键!** 暂存队列、Nonce 分配、双通道分发
    *   [x] `RoutineEncryption`: 并行 ChaCha20 加密
    *   [x] `RoutineSequentialSender`: 串行保序、物理发送
*   **并发架构 (Architecture)**
    *   [x] Producer-Consumer Worker Pool 模型
    *   [x] `select` 非阻塞队列设计
    *   [x] `lock` 显式同步机制

---

## 🚧 待探索领地 (45%)

### 2. 路由与索引模块 (Routing) - **推荐下一步**
*   **目标**: 理解“查表”背后的数据结构。
*   **文件**: 
    *   `device/allowedips.go`: **Radix Trie (基数树)** 实现。如何根据 IP 快速找到 Peer？
    *   `device/indextable.go`: 如何根据 Handshake 里的 Index 快速找到 Peer？

### 3. 握手与控制模块 (Control Plane)
*   **目标**: 理解密钥是如何协商出来的。
*   **文件**:
    *   `device/handshake.go`: 握手状态机 (Initiation -> Response -> Auth)。
    *   `device/noise-protocol.go`: Noise 协议的核心数学逻辑 (ECDH, Hash)。
    *   `device/cookie.go`: 极其精妙的抗 DoS Cookie 机制。

### 4. 系统底层模块 (System)
*   **目标**: 理解跨平台适配和网络优化。
*   **文件**:
    *   `conn/*.go`: Sticky Socket, GSO/GRO 优化。
    *   `tun/*.go`: 与不同操作系统内核的虚拟网卡交互。
    *   `ipc/*.go`: UAPI 接口 (wg set/show)。

---

## 💡 学习建议
你已经拿下了最难的动态部分。接下来的推荐路线：
1.  **攻克静态算法**: 看 `allowedips.go`，欣赏数据结构之美。
2.  **攻克协议逻辑**: 看 `handshake.go`，理解 Noise 安全握手。
3.  **收尾**: 扫一眼 System 模块，了解底层 Dirty Works。
