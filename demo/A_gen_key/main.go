package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"golang.org/x/crypto/curve25519"
)

func main() {
	// 1. 生成私钥 (32 bytes random)
	var privateKey [32]byte
	_, err := rand.Read(privateKey[:])
	if err != nil {
		log.Fatal(err)
	}

	// 2. 按 WireGuard 标准处理私钥 (Clamp)
	// 这一步是 Curve25519 的安全要求，确保私钥落在特定范围内
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	// 3. 推导公钥 (Curve25519 Scalar Multiplication)
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	// 4. 转 Base64 (User Friendly String)
	privStr := base64.StdEncoding.EncodeToString(privateKey[:])
	pubStr := base64.StdEncoding.EncodeToString(publicKey[:])

	fmt.Println("--- WireGuard Keypair Generator ---")
	fmt.Printf("Private Key: %s\n", privStr)
	fmt.Printf("Public Key:  %s\n", pubStr)
	fmt.Println("-----------------------------------")
}
