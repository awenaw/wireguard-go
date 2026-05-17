# WireGuard 握手 UDP 消息格式

> 源码定义位于 `device/noise-protocol.go` 第 85~117 行

## 消息 1：Initiator → Responder（固定 148 字节）

对应结构体 `MessageInitiation`

| 偏移量 | 字段 | 大小 | 说明 |
|--------|------|------|------|
| 0 | Type | 4B | 固定值 `1`（小端序，实际只用第一个字节） |
| 4 | Sender | 4B | Initiator 的本地索引号，Responder 回包时用它定位握手 |
| 8 | Ephemeral | 32B | Initiator 的**临时公钥** `E_i`（明文） |
| 40 | Static | 48B | Initiator 的**静态公钥** `S_i`（加密的！32B 公钥 + 16B Poly1305 认证标签） |
| 88 | Timestamp | 28B | **时间戳**（加密的！12B TAI64N 时间戳 + 16B 认证标签），防重放 |
| 116 | MAC1 | 16B | 用 Responder 静态公钥派生的 MAC，防止伪造 |
| 132 | MAC2 | 16B | 用 Cookie 计算的 MAC，防 DDoS（通常全 0） |

**要点**：
- 临时公钥 `E_i` 是**明文**发送的（没关系，它是一次性的）
- 静态公钥 `S_i` 是**加密**发送的（保护 Initiator 身份隐私）
- 时间戳也是**加密**的（防止重放攻击）

## 消息 2：Responder → Initiator（固定 92 字节）

对应结构体 `MessageResponse`

| 偏移量 | 字段 | 大小 | 说明 |
|--------|------|------|------|
| 0 | Type | 4B | 固定值 `2` |
| 4 | Sender | 4B | Responder 的本地索引号 |
| 8 | Receiver | 4B | 就是消息 1 中 Initiator 发来的 Sender 值，用于定位握手 |
| 12 | Ephemeral | 32B | Responder 的**临时公钥** `E_r`（明文） |
| 44 | Empty | 16B | 加密的**空载荷**（0 字节明文 + 16B 认证标签），纯粹用于验证握手正确性 |
| 60 | MAC1 | 16B | 同上 |
| 76 | MAC2 | 16B | 同上 |

**要点**：
- 消息 2 比消息 1 **小很多**（92 vs 148），因为 Responder 不需要加密传输自己的静态公钥（Initiator 已经事先知道了）
- `Empty` 字段看起来没用，但它的认证标签证明了"我确实用正确的密钥完成了所有 4 次 ECDH"
- `Receiver` 字段让 Initiator 能把这个回包和自己之前发出的握手关联起来

## 握手后：数据传输消息

对应结构体 `MessageTransport`

| 偏移量 | 字段 | 大小 | 说明 |
|--------|------|------|------|
| 0 | Type | 4B | 固定值 `4` |
| 4 | Receiver | 4B | 对方的索引号 |
| 8 | Counter | 8B | 包序号（用于 nonce 和防重放） |
| 16 | Content | 可变 | 用 sk 加密的实际数据（IP 包） |

## 一图总结

```
Initiator                                          Responder
    |                                                  |
    |  ---- 消息 1 (148B) ---- UDP ----->               |
    |  [Type=1, Sender, E_i, Enc(S_i), Enc(时间戳)]    |
    |                                                  |
    |               <----- UDP ---- 消息 2 (92B) ----  |
    |    [Type=2, Sender, Receiver, E_r, Enc(空)]      |
    |                                                  |
    |  ==== 握手完成，双方各自算出 sk_send/sk_recv ====  |
    |                                                  |
    |  ---- 数据包 (Type=4) ---- UDP ----->             |
    |  [Receiver, Counter, ChaCha20加密的IP包]          |
    |                                                  |
```
