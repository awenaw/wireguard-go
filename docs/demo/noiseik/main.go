package main

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"hash"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

//noiseik笔记草稿：
// 1 KDF 的目标是从同一个种子生成多个独立密钥。
// 2 DH 输出（shared secret）生成 PRK，然后再派生发送/接收密钥。

// Noise 协议相关常量，取自 WireGuard 源码
const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
)

// 定义一些基本类型，方便理解
type (
	PrivateKey [32]byte
	PublicKey  [32]byte
)

// 辅助函数：生成密钥对
func generateKeyPair() (PrivateKey, PublicKey) {
	var sk PrivateKey
	_, _ = rand.Read(sk[:])
	// Curve25519 私钥需要进行 clamping
	sk[0] &= 248
	sk[31] = (sk[31] & 127) | 64

	var pk PublicKey
	curve25519.ScalarBaseMult((*[32]byte)(&pk), (*[32]byte)(&sk))
	return sk, pk
}

// 辅助函数：计算共享密钥 (Diffie-Hellman)
func dh(sk PrivateKey, pk PublicKey) [32]byte {
	var ss [32]byte
	curve25519.ScalarMult(&ss, (*[32]byte)(&sk), (*[32]byte)(&pk))
	return ss
}

// HMAC 是 基于 hash 的消息认证码
// HMAC-BLAKE2s 相关辅助函数
func hmac1(key, in0 []byte) [32]byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	return sum
}

func hmac2(key, in0, in1 []byte) [32]byte {
	mac := hmac.New(func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}, key)
	mac.Write(in0)
	mac.Write(in1)
	var sum [32]byte
	copy(sum[:], mac.Sum(nil))
	return sum
}

// KDF 函数：WireGuard 使用的 HKDF 变体
func KDF1(key, input []byte) [32]byte {
	prk := hmac1(key, input)
	return hmac1(prk[:], []byte{0x01})
}

func KDF2(key, input []byte) ([32]byte, [32]byte) {
	prk := hmac1(key, input)
	t0 := hmac1(prk[:], []byte{0x01})
	t1 := hmac2(prk[:], t0[:], []byte{0x02})
	return t0, t1
}

func KDF3(key, input []byte) ([32]byte, [32]byte, [32]byte) {
	prk := hmac1(key, input)
	t0 := hmac1(prk[:], []byte{0x01})
	t1 := hmac2(prk[:], t0[:], []byte{0x02})
	t2 := hmac2(prk[:], t1[:], []byte{0x03})
	return t0, t1, t2
}

// MixHash: 将数据混合进当前哈希值
func mixHash(h [32]byte, data []byte) [32]byte {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	var sum [32]byte
	copy(sum[:], hash.Sum(nil))
	return sum
}

func main() {
	fmt.Println("==========================================================")
	fmt.Println("   WireGuard Noise_IK 握手与会话密钥 (sk) 生成全过程演示")
	fmt.Println("==========================================================")

	// --- 准备阶段 ---
	fmt.Println("\n[0] 准备阶段: 生成 Initiator(发起者) 和 Responder(响应者) 的静态密钥")

	s_i_priv, s_i_pub := generateKeyPair() // 发起者静态密钥
	s_r_priv, s_r_pub := generateKeyPair() // 响应者静态密钥

	fmt.Printf("Initiator 静态公钥: %s\n", hex.EncodeToString(s_i_pub[:]))
	fmt.Printf("Responder 静态公钥: %s\n", hex.EncodeToString(s_r_pub[:]))

	// 协议初始状态
	chainKey := blake2s.Sum256([]byte(NoiseConstruction))
	hash := mixHash(chainKey, []byte(WGIdentifier))

	fmt.Printf("初始 ChainKey: %s\n", hex.EncodeToString(chainKey[:]))
	fmt.Printf("初始 Hash:     %s\n", hex.EncodeToString(hash[:]))

	// --- 第一步: Initiator 构建 Initiation 消息 ---
	fmt.Println("\n[1] 第一阶段: Initiator 构建 Initiation 消息 (Message 1)")

	// 1.1 混合响应者的静态公钥 (Initiator 必须事先知道对方公钥)
	hash = mixHash(hash, s_r_pub[:])

	// 1.2 生成临时密钥 (Ephemeral Key)
	e_i_priv, e_i_pub := generateKeyPair()
	fmt.Printf("Initiator 临时公钥 (e): %s\n", hex.EncodeToString(e_i_pub[:]))

	// 1.3 混合临时公钥
	chainKey = KDF1(chainKey[:], e_i_pub[:])
	hash = mixHash(hash, e_i_pub[:])

	// 1.4 计算 DH(e_i, s_r) 并派生新密钥
	ss := dh(e_i_priv, s_r_pub)
	var key [32]byte
	chainKey, key = KDF2(chainKey[:], ss[:])

	// 1.5 加密 Initiator 的静态公钥 (s_i)
	// 使用得到的 key 进行 ChaCha20-Poly1305 加密
	aead, _ := chacha20poly1305.New(key[:])
	msg1_static := aead.Seal(nil, make([]byte, 12), s_i_pub[:], hash[:])
	hash = mixHash(hash, msg1_static)
	fmt.Printf("加密后的 Initiator 静态公钥: %s\n", hex.EncodeToString(msg1_static))

	// 1.6 计算 DH(s_i, s_r) 并派生密钥加密时间戳 (防止重放)
	ss_static := dh(s_i_priv, s_r_pub)
	chainKey, key = KDF2(chainKey[:], ss_static[:])

	aead, _ = chacha20poly1305.New(key[:])
	timestamp := []byte(time.Now().Format(time.RFC3339))
	msg1_timestamp := aead.Seal(nil, make([]byte, 12), timestamp, hash[:])
	hash = mixHash(hash, msg1_timestamp)

	fmt.Println("Initiation 消息构建完成，包含: [Type, SenderIndex, Ephemeral, Static, Timestamp, MAC1, MAC2]")

	// --- 第二步: Responder 处理 Initiation 并构建 Response 消息 ---
	fmt.Println("\n[2] 第二阶段: Responder 处理消息并构建 Response 消息 (Message 2)")

	// (模拟 Responder 端的 hash 和 chainKey 状态同步)
	// Responder 会使用自己的私钥 s_r_priv 来解密消息
	_ = s_r_priv // 显式使用以满足编译器要求
	// ... (此处省略解密验证过程，直接进入构建 Response)

	// 2.1 生成 Responder 的临时密钥 (e_r)
	e_r_priv, e_r_pub := generateKeyPair()
	fmt.Printf("Responder 临时公钥 (e): %s\n", hex.EncodeToString(e_r_pub[:]))

	// 2.2 混合临时公钥
	hash = mixHash(hash, e_r_pub[:])
	chainKey = KDF1(chainKey[:], e_r_pub[:])

	// 2.3 计算 DH(e_r, e_i) 和 DH(e_r, s_i) 并混合
	ss_ee := dh(e_r_priv, e_i_pub)
	chainKey = KDF1(chainKey[:], ss_ee[:])

	ss_es := dh(e_r_priv, s_i_pub)
	chainKey = KDF1(chainKey[:], ss_es[:])

	// 2.4 处理预共享密钥 (PSK)
	// 虽然 WireGuard 支持 PSK，但默认为全 0。这里展示 KDF3 过程。
	psk := make([]byte, 32) // 假设没有 PSK
	var tau [32]byte
	chainKey, tau, key = KDF3(chainKey[:], psk)
	hash = mixHash(hash, tau[:])

	// 2.5 加密空有效载荷作为确认
	aead, _ = chacha20poly1305.New(key[:])
	msg2_empty := aead.Seal(nil, make([]byte, 12), nil, hash[:])
	hash = mixHash(hash, msg2_empty)

	fmt.Printf("Response 消息中的加密载荷 (Empty): %s\n", hex.EncodeToString(msg2_empty))
	fmt.Println("Response 消息构建完成。")

	// --- 第三步: 最终会话密钥 (sk) 的生成 ---
	fmt.Println("\n[3] 第三阶段: 派生最终的对称加密会话密钥 (Session Keys)")

	// 此时握手已经完成，双方都拥有相同的 chainKey
	fmt.Printf("握手结束后的最终 ChainKey: %s\n", hex.EncodeToString(chainKey[:]))

	// 使用 KDF2 从最终的 chainKey 中导出两把钥匙
	// 1. 发送密钥 (Send Key)
	// 2. 接收密钥 (Receive Key)

	var sk_send, sk_recv [32]byte

	// 对于 Initiator 来说:
	sk_send, sk_recv = KDF2(chainKey[:], nil)

	fmt.Println("\n--- Initiator 视角 ---")
	fmt.Printf("发送密钥 (Transport Send Key): %s\n", hex.EncodeToString(sk_send[:]))
	fmt.Printf("接收密钥 (Transport Recv Key): %s\n", hex.EncodeToString(sk_recv[:]))

	// 对于 Responder 来说，顺序相反:
	// sk_recv_r, sk_send_r = KDF2(chainKey[:], nil)

	fmt.Println("\n[总结] 会话密钥生成完毕！")
	fmt.Println("从此开始，双方将使用上述密钥通过 ChaCha20-Poly1305 对所有数据包进行加密传输。")
	fmt.Println("每 2 分钟或传输量过大时，WireGuard 会自动发起新的握手，重新生成这套密钥，实现完美正向加密。")
}
