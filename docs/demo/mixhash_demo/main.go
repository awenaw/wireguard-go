package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/blake2s"
)

// mixHash: 将新数据 (data) 与当前哈希值 (h) 混合，生成新的哈希值
// 它是 Noise 协议中保证握手完整性的核心机制
func mixHash(h [32]byte, data []byte) [32]byte {
	// 创建一个 BLAKE2s 哈希实例 (WireGuard 使用 BLAKE2s)
	hasher, _ := blake2s.New256(nil)
	
	// 1. 先写入之前的哈希状态
	hasher.Write(h[:])
	
	// 2. 再写入新的数据 (比如公钥或加密载荷)
	hasher.Write(data)
	
	// 3. 计算并返回新的 32 字节哈希值
	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return sum
}

func main() {
	fmt.Println("==========================================")
	fmt.Println("   MixHash 机制演示 (Noise Protocol)")
	fmt.Println("==========================================")

	// Step 0: 协议初始化
	// 在 WireGuard 中，初始哈希是根据协议名称生成的
	protocolName := "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	h0 := blake2s.Sum256([]byte(protocolName))
	fmt.Printf("[Step 0] 协议初始化哈希:\n  %s\n\n", hex.EncodeToString(h0[:]))

	// Step 1: 混合第一个数据
	// 假设我们在握手中发送了 Initiator 的临时公钥
	ephemeralPubKey := []byte("this-is-a-32-byte-ephemeral-key-")
	h1 := mixHash(h0, ephemeralPubKey)
	fmt.Printf("[Step 1] 混合临时公钥后的哈希:\n  %s\n\n", hex.EncodeToString(h1[:]))

	// Step 2: 混合第二个数据
	// 假设我们接着发送了加密后的静态公钥
	encryptedStaticKey := []byte("some-encrypted-data-payload-here")
	h2 := mixHash(h1, encryptedStaticKey)
	fmt.Printf("[Step 2] 混合加密载荷后的哈希:\n  %s\n\n", hex.EncodeToString(h2[:]))

	fmt.Println("------------------------------------------")
	fmt.Println("结论：")
	fmt.Println("1. 累加性：h2 是在 h1 的基础上生成的，包含了之前所有步骤的信息。")
	fmt.Println("2. 唯一性：如果中间任何一个步骤的数据被改动，最后的哈希值会完全崩溃。")
	fmt.Println("3. 安全性：这个哈希值会被用作后续加密的 AD (Associated Data)，确保握手全过程不被篡改。")
}
