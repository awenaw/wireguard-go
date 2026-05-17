# WireGuard 握手速查表

> 前提：你已经理解 ECDH（两人各出一对密钥，各自算出相同的 shared secret）。

## 角色

- **Initiator (I)**：发起连接的一方，拥有静态密钥 `s_i`，**事先知道**对方的静态公钥 `S_r`
- **Responder (R)**：等待连接的一方，拥有静态密钥 `s_r`

小写 = 私钥，大写 = 公钥，`e` = 临时密钥，`s` = 静态密钥

## 核心思路

整个握手就是在做一件事：**往 chainKey 这锅汤里加料**。

每次加料的方式都一样：
```
做一次 ECDH → 把结果喂进 HKDF → chainKey 进化一次
```

加完 4 次料后，从最终的 chainKey 里切出 sk_send 和 sk_recv，握手结束。

## 4 次 ECDH 速查

```
消息 1：Initiator → Responder
├── ECDH ①: e_i × S_r  （我的临时 × 你的静态）→ 证明我在跟真正的你说话
├── ECDH ②: s_i × S_r  （我的静态 × 你的静态）→ 绑定双方长期身份
└── 附带：加密传输 Initiator 的静态公钥 + 时间戳

消息 2：Responder → Initiator
├── ECDH ③: e_r × E_i  （你的临时 × 我的临时）→ 双方临时密钥混合，保证前向安全
├── ECDH ④: e_r × S_i  （你的临时 × 我的静态）→ 再次绑定 Initiator 身份
└── 附带：加密空载荷作为确认

最终：sk_send, sk_recv = KDF2(chainKey, nil)
```

## chainKey 进化过程（主线剧情）

```
chainKey₀ = Hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")   ← 初始值（协议名称的哈希）
    │
    ├─ KDF(chainKey₀, E_i)           ← 混入临时公钥
    │
    ├─ KDF(chainKey₁, ECDH①结果)     ← 第 1 次加料
    │
    ├─ KDF(chainKey₂, ECDH②结果)     ← 第 2 次加料
    │
    ├─ KDF(chainKey₃, E_r)           ← 混入 Responder 临时公钥
    │
    ├─ KDF(chainKey₄, ECDH③结果)     ← 第 3 次加料
    │
    ├─ KDF(chainKey₅, ECDH④结果)     ← 第 4 次加料
    │
    ├─ KDF(chainKey₆, PSK)           ← 混入预共享密钥（默认全 0）
    │
    └─ KDF2(chainKey₇, nil)          ← 最终切出 sk_send 和 sk_recv
```

## 为什么要 4 次？每次的安全意义

| # | ECDH 操作 | 如果少了这一次会怎样 |
|---|----------|-------------------|
| ① | e_i × S_r | 任何人都能冒充 Initiator 发起连接 |
| ② | s_i × S_r | 无法证明 Initiator 的长期身份，Responder 不知道在跟谁说话 |
| ③ | e_r × E_i | 没有前向安全性：未来私钥泄露 → 历史通信全部可解密 |
| ④ | e_r × S_i | 中间人可以在消息 2 中冒充 Responder |

4 次 ECDH = 身份认证 + 前向安全 + 抗中间人，缺一不可。

## 副线剧情（可以先忽略的细节）

- **mixHash**：每一步都把公开数据揉进一个 hash 值，用于后续 AEAD 加密的 AD 参数，保证握手完整性
- **加密静态公钥**：Initiator 的身份（静态公钥）是加密传输的，窃听者看不到是谁在连接
- **加密时间戳**：防止重放攻击（把旧的握手消息录下来重新发送）
- **PSK**：可选的预共享密钥，额外的安全层，默认全 0（等于没有）

## 一句话总结

> 4 次 ECDH 提供 4 种不同维度的安全保障，HKDF 把它们全部炖成一锅，最后从锅里盛出两碗 sk。
