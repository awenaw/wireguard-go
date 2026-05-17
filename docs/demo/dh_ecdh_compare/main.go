package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"math/big"
)

// ==========================================
// 1. 传统的 DH (Diffie-Hellman) 演示 (基于有限域)
// ==========================================
// 这里我们使用 math/big 来模拟一个最基础的经典 DH 交换过程
func classicDHDemo() {
	fmt.Println("--- 1. 经典 DH (Finite Field Diffie-Hellman) 演示 ---")
	
	// 在真实的经典 DH 中，p 是一个非常大的素数（例如 2048 bit），g 是原根
	// 为了演示，我们使用相对较小的值（切勿在生产环境使用这么小的素数！）
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16) // RFC 2409 1024-bit MODP Group
	g := big.NewInt(2)

	// Alice 生成私钥 a，计算公钥 A = g^a mod p
	alicePriv, _ := rand.Int(rand.Reader, p)
	alicePub := new(big.Int).Exp(g, alicePriv, p)

	// Bob 生成私钥 b，计算公钥 B = g^b mod p
	bobPriv, _ := rand.Int(rand.Reader, p)
	bobPub := new(big.Int).Exp(g, bobPriv, p)

	// 交换公钥后，计算共享密钥
	// Alice 计算: secret = B^a mod p
	aliceSecret := new(big.Int).Exp(bobPub, alicePriv, p)
	
	// Bob 计算: secret = A^b mod p
	bobSecret := new(big.Int).Exp(alicePub, bobPriv, p)

	fmt.Printf("Alice 计算出的共享密钥前缀: %x...\n", aliceSecret.Bytes()[:8])
	fmt.Printf("Bob   计算出的共享密钥前缀: %x...\n", bobSecret.Bytes()[:8])
	fmt.Printf("密钥是否一致: %v\n\n", aliceSecret.Cmp(bobSecret) == 0)
}

// ==========================================
// 2. 现代的 ECDH (Elliptic Curve DH) 演示
// ==========================================
// ECDH 将 DH 的底层数学从“大质数求幂”换成了“椭圆曲线上的点乘”
// WireGuard 使用的正是 ECDH 中的 Curve25519 (在 Go 标准库中称为 X25519)
func ecdhDemo() {
	fmt.Println("--- 2. 现代 ECDH (Elliptic Curve Diffie-Hellman) 演示 ---")
	
	// Go 1.20 引入了标准库 crypto/ecdh
	// 我们选择 X25519 曲线（WireGuard 使用的曲线）
	curve := ecdh.X25519()

	// Alice 生成椭圆曲线密钥对
	alicePriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	alicePub := alicePriv.PublicKey()

	// Bob 生成椭圆曲线密钥对
	bobPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	bobPub := bobPriv.PublicKey()

	// 交换公钥后，计算共享密钥 (在曲线上进行标量乘法)
	// Alice 使用自己的私钥和 Bob 的公钥
	aliceSecret, err := alicePriv.ECDH(bobPub)
	if err != nil {
		panic(err)
	}

	// Bob 使用自己的私钥和 Alice 的公钥
	bobSecret, err := bobPriv.ECDH(alicePub)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Alice 计算出的共享密钥: %x\n", aliceSecret)
	fmt.Printf("Bob   计算出的共享密钥: %x\n", bobSecret)
	
	// 验证是否一致
	match := true
	for i := range aliceSecret {
		if aliceSecret[i] != bobSecret[i] {
			match = false
			break
		}
	}
	fmt.Printf("密钥是否一致: %v\n", match)
}

func main() {
	fmt.Println("==========================================================")
	fmt.Println("     DH (经典有限域) vs ECDH (椭圆曲线) 密钥交换演示")
	fmt.Println("==========================================================")
	fmt.Println("提示: 之前我们用 curve25519 写的 Demo 实际上就是 ECDH。")
	fmt.Println("为了对比，这里展示传统的基于大质数的 DH 和 现代的 ECDH。")
	fmt.Println()

	classicDHDemo()
	ecdhDemo()
}
