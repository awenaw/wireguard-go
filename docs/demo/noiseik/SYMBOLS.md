# WireGuard 握手符号速查表

## 大小写规则

- **小写** = 私钥（秘密的，绝不出门）
- **大写** = 公钥（公开的，可以发出去）

## 角色

| 符号 | 全称 | 解释 |
|------|------|------|
| `i` | initiator | 发起者（主动连接的那一方） |
| `r` | responder | 响应者（等着别人来连的那一方） |

## 密钥类型

| 符号 | 全称 | 解释 |
|------|------|------|
| `s` | static | 静态密钥（长期不变，写在配置文件里的） |
| `e` | ephemeral | 临时密钥（每次握手临时生成，用完就扔） |

## 密钥组合

| 符号 | 含义 | 举例 |
|------|------|------|
| `s_i` | Initiator 的静态**私**钥 | 小写 = 私钥 |
| `S_i` | Initiator 的静态**公**钥 | 大写 = 公钥 |
| `e_i` | Initiator 的临时**私**钥 | |
| `E_i` | Initiator 的临时**公**钥 | |
| `s_r` | Responder 的静态**私**钥 | |
| `S_r` | Responder 的静态**公**钥 | |
| `e_r` | Responder 的临时**私**钥 | |
| `E_r` | Responder 的临时**公**钥 | |

## 计算结果

| 符号 | 全称 | 解释 |
|------|------|------|
| `ss` | shared secret | ECDH 算出来的共享秘密 |
| `ss_ee` | — | 临时×临时 的共享秘密 |
| `ss_es` | — | 临时×静态 的共享秘密 |
| `sk` | session key | 最终的会话密钥（加密数据用的） |
| `sk_send` | — | 发送方向的会话密钥 |
| `sk_recv` | — | 接收方向的会话密钥 |

## 握手状态变量

| 符号 | 解释 |
|------|------|
| `chainKey` | 链密钥，握手过程中不断进化的"汤底"，4 次 ECDH 的结果都往里加 |
| `hash` | 握手记录摘要，mixHash 的产物，每一步公开数据都揉进去 |
| `key` | 当前步骤的临时工作密钥，用完即弃（从 KDF 派生，用于 AEAD 加密） |

## 算法/函数名

| 符号 | 全称 | 一句话解释 |
|------|------|-----------|
| `DH` | Diffie-Hellman | 密钥交换算法（WireGuard 中就是 ECDH / Curve25519） |
| `KDF` | Key Derivation Function | 密钥派生函数（从一份原料派生出多把独立钥匙） |
| `HKDF` | HMAC-based KDF | KDF 的具体实现方式（基于 HMAC） |
| `AEAD` | Authenticated Encryption with Associated Data | 认证加密（ChaCha20-Poly1305），加密的同时防篡改 |
| `mixHash` | — | 把数据揉进 hash，形成链式记录 |
| `mixKey` | — | 把数据揉进 chainKey，等价于 KDF1 |
| `PSK` | Pre-Shared Key | 预共享密钥（可选，默认全 0，等于没有） |
| `MAC` | Message Authentication Code | 消息认证码（用于快速验证消息完整性） |

## 读变量名技巧

从右往左拼读：

```
e_i_priv  →  priv(私钥) / i(Initiator) / e(临时)  →  "Initiator 的临时私钥"
s_r_pub   →  pub(公钥) / r(Responder) / s(静态)   →  "Responder 的静态公钥"
ss_es     →  s(静态) × e(临时) 的 ss(共享秘密)    →  "临时×静态的共享秘密"
```
