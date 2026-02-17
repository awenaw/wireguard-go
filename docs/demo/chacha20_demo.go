package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	fmt.Println("=== ChaCha20-Poly1305 Encryption Demo (The WireGuard Way) ===")

	// 1. 准备 Key (32 bytes = 256 bits)
	// 这是你的传家宝秘方（在 WG 里是 ECDH 协商出来的 Shared Key）
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n[1] 密钥 (Key) - 32字节:\n%s\n", hex.EncodeToString(key))

	// 2. 准备 AEAD (Authenticated Encryption with Associated Data) 实例
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}

	// 3. 准备 Nonce (12 bytes = 96 bits)
	// 在 WG 里，这里由 4字节固定值(0) + 8字节 Counter 组成
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\n[2] 随机数 (Nonce) - 12字节:\n%s\n", hex.EncodeToString(nonce))

	// 4. 准备明文数据 (Plaintext)
	plaintext := []byte("Hello, WireGuard! ChaCha20 is dancing!")
	fmt.Printf("\n[3] 明文 (Plaintext) - %d字节:\n字符串: %s\n十六进制: %s\n", len(plaintext), string(plaintext), hex.EncodeToString(plaintext))

	// 5. 加密 (Encrypt + Seal)
	// Seal 的第一个参数 dst 是为了避免内存分配，可以直接传入一个足够大的 slice 或者 nil
	// 它会把 Authentication Tag (16字节) 自动追加到密文后面
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	fmt.Printf("\n[4] 密文 (Ciphertext) - %d字节 (原长度 + 16字节 Tag):\n", len(ciphertext))
	fmt.Printf("%s\n", hex.EncodeToString(ciphertext))

	// 验证长度增加
	fmt.Printf("(%d + 16 = %d)\n", len(plaintext), len(ciphertext))

	// 6. 解密 (Decrypt + Open)
	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal("解密失败! 可能是 Key 错、Nonce 错，或者数据被篡改!")
	}

	fmt.Printf("\n[5] 解密还原 (Decrypted):\n%s\n", string(decrypted))

	fmt.Println("\n=== Demo Finished ===")
}
