# Noise_IK 握手演示 (WireGuard 核心流程)

这个演示程序展示了 WireGuard 如何使用 Noise 协议的 `IK` 模式完成身份验证、密钥交换以及最终会话密钥（sk）生成的全过程。

## 演示内容

1.  **静态密钥准备**: 模拟客户端（Initiator）和服务器（Responder）生成自己的长期静态密钥对。
2.  **Noise 状态初始化**: 设置初始的 `ChainKey` 和 `Hash`。
3.  **第一阶段 (Initiation)**:
    *   生成临时密钥 (Ephemeral Key)。
    *   执行 Diffie-Hellman (DH) 交换。
    *   使用 KDF 派生临时加密密钥。
    *   加密发送者的静态公钥和时间戳。
4.  **第二阶段 (Response)**:
    *   生成响应者的临时密钥。
    *   执行多轮 DH 交换（ee, es）。
    *   派生最终的 `ChainKey`。
    *   加密空载荷以确认握手成功。
5.  **第三阶段 (Session Key Derivation)**:
    *   从最终的 `ChainKey` 中派生出对称加密会话密钥（发送密钥和接收密钥）。

## 如何运行

确保你已经安装了 Go 环境，在根目录下运行：

```bash
go run docs/demo/noiseik/main.go
```

## 核心原理

WireGuard 选择了 Noise_IKpsk2 模式，它具有以下特性：
*   **相互认证**: 双方都验证了对方的静态公钥。
*   **完美正向加密 (PFS)**: 即使长期私钥泄露，过去的会话记录也无法被破解，因为会话密钥是由临时密钥参与生成的。
*   **隐身性**: 握手包经过加密，且在没有正确公钥的情况下无法被识别，这使得 WireGuard 服务对未授权者是不可见的。
