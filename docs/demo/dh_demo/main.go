package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// 生成密钥对
func generateKeyPair() ([32]byte, [32]byte) {
	var priv [32]byte
	_, _ = rand.Read(priv[:])
	
	// Curve25519 私钥处理 (Clamping)
	priv[0] &= 248
	priv[31] = (priv[31] & 127) | 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)
	return priv, pub
}

// 执行 DH 计算：我的私钥 + 对方的公钥 = 共享密钥
func computeSharedSecret(myPriv [32]byte, theirPub [32]byte) [32]byte {
	var secret [32]byte
	curve25519.ScalarMult(&secret, &myPriv, &theirPub)
	return secret
}

func main() {
	fmt.Println("==========================================")
	fmt.Println("   Diffie-Hellman (Curve25519) 演示")
	fmt.Println("==========================================")

	// 1. 双方各自生成密钥对
	alicePriv, alicePub := generateKeyPair()
	bobPriv, bobPub := generateKeyPair()

	fmt.Printf("Alice 公钥: %s\n", hex.EncodeToString(alicePub[:]))
	fmt.Printf("Bob   公钥: %s\n\n", hex.EncodeToString(bobPub[:]))

	// 2. 交换公钥后，各自计算共享密钥
	// Alice 使用自己的私钥和 Bob 的公钥
	aliceShared := computeSharedSecret(alicePriv, bobPub)
	
	// Bob 使用自己的私钥和 Alice 的公钥
	bobShared := computeSharedSecret(bobPriv, alicePub)

	fmt.Println("--- 计算结果 ---")
	fmt.Printf("Alice 算出的密钥: %s\n", hex.EncodeToString(aliceShared[:]))
	fmt.Printf("Bob   算出的密钥: %s\n", hex.EncodeToString(bobShared[:]))

	// 3. 验证结果
	if aliceShared == bobShared {
		fmt.Println("\n结论：双方算出的密钥完全一致！")
		fmt.Println("即使在公开网络传输公钥，第三方也无法得出这个共享密钥。")
	} else {
		fmt.Println("\n错误：密钥不匹配。")
	}
}
