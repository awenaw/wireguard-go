# WireGuard-Go 源码阅读生存指南 (Survival Map)

> 这是一份为"不想成为密码学家，只想魔改 VPN 做业务"的开发者准备的寻宝地图。
> 我们跳过复杂的数学公式，直击**数据流转**和**状态管理**的核心命脉。

---

## 🗺️ 核心地理图 (Topography)

整个项目其实就干了三件事：**配置(Config) -> 建立隧道(Handshake) -> 搬运数据(Transport)**。

| 目录/文件 | 角色 | 什么时候看？ | 难度 |
| :--- | :--- | :--- | :--- |
| `device/device.go` | **总司令** | 想了解程序是如何启动、关闭、管理资源时。 | ⭐⭐ |
| `device/peer.go` | **大客户经理** | 想统计流量、踢掉某个用户、查看连接状态时。 | ⭐⭐ |
| `device/receive.go` | **进口安检** | **最核心！** 想魔改鉴权逻辑、拦截特定流量、抓包时。 | ⭐⭐⭐⭐ |
| `device/send.go` | **出口打包** | 想调整 MTU、做流量整形(QoS)时。 | ⭐⭐⭐ |
| `device/uapi.go` | **前台接待** | 想知道 `wg set` 命令是怎么生效的，或者如何动态加 Peer。 | ⭐⭐ |
| `tun/*` | **硬件接口** | 想移植到 Android/iOS 或特殊硬件时。 | ⭐⭐⭐ |
| `conn/*` | **快递员** | 处理 UDP Socket 读写，想做 STUN/打洞优化时。 | ⭐⭐⭐ |
| `device/noise-protocol.go` | **黑盒子** | ⚠️ **没事别看**。这是握手协议的数学实现，除非你是密码学专家。 | ⭐⭐⭐⭐⭐ |

---

## 🧶 关键红线 (The Red Threads)

跟着这些线索，你就能串起整个逻辑。

### 线索 1：Peer 是怎么来的？ (生命之源)
*   **入口**：`device/uapi.go` -> `IpcSet()`
*   **动作**：解析 `public_key=...` -> 调用 `device/peer.go` -> `NewPeer()`
*   **结果**：一个 `Peer` 对象诞生，并且立刻启动了它的 `Start()` 方法，开始干活。

### 线索 2：如何从网卡拿到数据包？ (出站 - Outbound)
这是把数据从“你的电脑”发到“VPN”的过程。
1.  **用户态读取**：`device/device.go` -> `RoutineTUNEventReader()`
    *   这里死循环 `tun.Read()`，时刻等待操作系统喂数据。
2.  **查路由表**：`device/device.go` -> 拿到包 -> 查 `AllowedIPs` -> 找到对应的 `Peer`。
3.  **入队**：找到 Peer 后，把包扔进 `Peer.queue.outbound`。
4.  **加密发送**：`device/send.go` -> `RoutineSequentialSender()`
    *   工人发现队列有货 -> 加密 -> 调用 `bind.Send()` (UDP 发射)。

### 线索 3：如何把数据包给用户？ (入站 - Inbound)
这是“VPN”收到数据，吐给“你的电脑”的过程。
1.  **UDP 接收**：`device/receive.go` -> `RoutineReceiveIncoming()`
    *   死循环 `conn.Receive()`，时刻监听 UDP 端口。
2.  **解密分发**：收到一堆乱码 -> 丢给解密 Worker (`RoutineDecryption`)。
3.  **排序**：解密完是乱序的，丢给 `device/receive.go` -> `RoutineSequentialReceiver()` 重新排队。
4.  **写入系统**：检查无误 -> 调用 `tun.Write()` -> 你的电脑收到了乒乓包 (`Ping`)。

### 线索 4：握手是怎么发生的？ (Handshake)
这是所有魔法的前提。
*   **触发**：`device/peer.go` -> 定时器 `retransmitHandshake` 或者 发包时发现没有 Key。
*   **执行**：`device/send.go` -> `SendHandshakeInitiation()`
*   **黑话**：
    *   `Initiation`: "你好，我是 A，我想连你。"
    *   `Response`: "收到 A，我是 B，这是我的证件。"
    *   `Cookie`: "你发太快了，做个算术题证明你不是机器人(DDoS)。"

---

## 🔍 你现在应该看哪里？ (Actionable Advice)

针对您的 **IoT 运维中台** 目标：

1.  **想看“对端活没活”？**
    *   去 `device/peer.go` 找 `LastHandshakeNano` 字段。这个时间戳如果超过 3 分钟，说明设备可能挂了。

2.  **想解决“连上了但网页打不开” (MTU问题)？**
    *   去 `device/device.go` 找 `MTU` 常量。Windows 上 `wintun` 默认可能是 1420，有些 4G 路由 MTU 只有 1300，需要在这里魔改或者动态调整。

3.  **想“踢掉”非法接入的设备？**
    *   去 `device/receive.go` 的 `RoutineSequentialReceiver`。在这里加一个 Hook，如果发现某个 Peer ID 在黑名单里，直接 `continue` (丢弃)，它就断网了。

---

*Keep this map, and you won't get lost.*
