# 商业技术改造计划：基于 WireGuard 的万级 IoT 设备运维中台

> 本文档描述了针对 10,000+ 台分布式 Windows IoT 终端（线下拍照机）的下一代运维架构改造方案。
> 版本：v1.1 (增强版)

---

## 1. 背景与痛点

当前业务规模已达全国 1 万台设备，原有的单一 MQTT 架构面临以下瓶颈：

*   **远程交互弱**：只能进行简单的状态上报和指令下发，无法进行实时、复杂的远程桌面操作（需依赖第三方昂贵或不安全的软件）。
*   **大文件传输难**：通过 MQTT 主题传输几十 MB 的日志文件或 Dump 文件极其低效且不稳定。
*   **运维效率低**：设备出现复杂故障（非死机）时，无法“亲临现场”诊断，只能盲目重启或派人出差。

---

## 2. 核心价值主张 (Value Proposition)

我们将构建一套 **“MQTT 唤醒 + WireGuard 按需组网”** 的混合架构，实现：

1.  **降本 (Cost Efficiency)**：
    *   **硬性节省**：替代 TeamViewer/向日葵等企业版授权。按 50 个并发通道计算，年节省授权费约 **50万+ RMB**。
    *   **自主可控**：利用 `wireguard-go` 开源方案自建，无被“卡脖子”或涨价风险。

2.  **增效 (Operational Efficiency)**：
    *   **毫秒级响应**：运维人员可像访问局域网电脑一样访问全国任意一台设备。
    *   **无感运维**：利用 RDP Wrapper 实现“影子会话”，运维排查故障时，顾客依然可以正常使用设备，业务零中断，提升单机营收。

3.  **安全 (Security)**：
    *   收敛公网暴露面，所有管理端口（RDP 3389, SSH 22, SMB 445）仅对 VPN 内网开放。
    *   基于私钥的身份认证，杜绝传统弱口令爆破风险。

---

## 3. 技术架构 (Architecture)

### 3.1 混合控制流 (Hybrid Control Plane)

采用 **信令与数据分离** 的设计原则：

*   **信令层 (MQTT / HTTP - Always On)**
    *   保持现有 MQTT 长连接不变，极低带宽心跳。
    *   **Topic 设计**：
        *   `iot/{device_id}/cmd` <- `{"action": "vpn_up", "server": "wg-bj-01"}`
        *   `iot/{device_id}/status` -> `{"vpn": "connected", "ip": "10.166.0.5"}`
    
*   **数据层 (WireGuard - On Demand)**
    *   **按需连接**：设备收到 MQTT 指令后，动态拉起 `wireguard-go` 进程。
    *   **职责**：RDP 远程桌面流、SCP 日志文件流、SMB 共享挂载。
    *   **生命周期**：运维结束 -> 发送指令 -> 进程销毁，释放资源。

### 3.2 关键组件选型

| 模块 | 选型 | 理由 |
| :--- | :--- | :--- |
| **设备端网络** | `wireguard-go` + `wintun` | 用户态高性能网络栈，无需 NDIS 驱动开发，部署风险低 (Risk-Free)。 |
| **远程服务** | RDP Wrapper + OpenSSH | 实现多用户并发会话和标准化 CLI 管理。 |
| **中心网关** | Linux (Debian) (Kvm/Bare-metal) | 高 PPS 转发能力。对于 1 万台设备，计划采用 **Anycast** 或 DNS 轮询进行多节点分流。 |
| **打洞策略** | UDP Hole Punching + STUN | 应对复杂的 4G/5G NAT 环境，必要时回落到 Relay (DERP) 模式。 |

---

## 4. 典型运维场景 (User Story)

**场景：某商场设备报修“无法打印”，但屏幕正常。**

1.  **报警**：客服后台收到工单。
2.  **一键连接**：
    *   运维在 Web 后台点击“远程连接”。
    *   后端发送 MQTT 指令 `VPN_CONNECT` 给目标设备。
    *   设备启动 WireGuard，连接网关，上报虚拟 IP `10.166.X.X`。
3.  **无感介入**：
    *   运维一键调起 RDP 客户端连接 `10.166.X.X`。
    *   利用**并发会话**进入后台，查看打印机队列，发现卡纸或驱动报错。
    *   与此同时，前台顾客依然在浏览照片，完全无感知。
4.  **修复闭环**：
    *   运维通过 RDP 清理打印队列，修复驱动。
    *   关闭连接，后台自动发送 MQTT 指令 `VPN_DISCONNECT`。
    *   设备断开 VPN，回归静默状态。

---

## 5. 实施路线图 (Roadmap)

### 第一阶段：PoC 验证 (✅ 已完成)
- [x] macOS 编译调试 `wireguard-go` 环境搭建。
- [x] 验证 Windows (`hiot`) 与 Linux 网关 (`debian`) 的连通性。
- [x] 验证 RDP Wrapper 并发会话可行性。

### 第二阶段：客户端集成 (🚧 进行中)
- [ ] **Agent 开发** (Golang): 封装 MQTT Client 和 `wireguard-go/tun` 控制逻辑。
- [ ] **自愈机制**: 增加 Watchdog，防止 VPN 进程假死导致失联。
- [ ] **NAT 穿透优化**: 增加 Keepalive 动态调整逻辑，对抗运营商 NAT 超时。

### 第三阶段：中控平台建设 (Q2 计划)
- [ ] **Web 管理后台**: 设备列表、在线状态、一键唤起 VPN 包含 Web-based RDP (Guacamole)。
- [ ] **密钥管理系统 (KMS)**: 自动化管理 1 万对公私钥，支持密钥轮换。

### 第四阶段：灰度与全量 (Q3 计划)
- [ ] 选取 50 台复杂网络环境设备进行试点。
- [ ] 压力测试中心网关，确定单机承载上限。
- [ ] 全网推送，从 Gen 2 架构平滑升级至 Gen 3。

---

## 6. 风险评估与应对 (Risk Management)

| 风险点 | 极值情况 | 应对策略 |
| :--- | :--- | :--- |
| **NAT 穿透失败** | 对称型 NAT (Symmetric NAT) 导致 UDP 不通 | 部署 TURN/DERP 中继服务器作为兜底方案（成本略增但保证可用性）。 |
| **Windows 更新** | 更新破坏 RDP Wrapper 或 wintun 驱动 | Agent 启动时校验环境，自动拉取最新 ini 补丁；使用微软签名的 wintun。 |
| **安全泄露** | 私钥泄露 | 实施**短期证书**或**一次性密钥**机制，每次连接动态生成密钥对。 |
| **带宽打爆** | 100 人同时传日志 | 网关实施 QoS 策略，限制单 Peer 带宽；大文件强制走并在 FTP/S3 上传通道。 |

---

## 附录：技术资产

- **代码库**: `github.com/wireguard-go` (已做适配修改)
- **调试指南**: `docs/DEBUG_GUIDE.md`
- **操作指南**: `docs/RDP_WRAPPER_GUIDE.md`
- **SSH 指南**: `docs/windows_ssh_guide.md`

*Created by Antigravity & User - 2025-12-14*
