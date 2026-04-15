package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	fmt.Println("=== AEAD Seal Demo ===")
	fmt.Println("模拟 CreateMessageInitiation 里这段逻辑：")
	fmt.Println("aead.Seal(msg.Static[:0], ZeroNonce[:], staticPublicKey[:], handshakeHash[:])")
	fmt.Println()

	var (
		// 用固定字节让输出稳定，便于对照理解。
		key             [chacha20poly1305.KeySize]byte
		zeroNonce       [chacha20poly1305.NonceSize]byte
		staticPublicKey [32]byte
		handshakeHash   [32]byte
		msgStatic       [32 + chacha20poly1305.Overhead]byte
	)

	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range staticPublicKey {
		staticPublicKey[i] = byte(0xa0 + i)
	}
	for i := range handshakeHash {
		handshakeHash[i] = byte(0x10 + i)
	}

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("key            = %s\n", hex.EncodeToString(key[:]))
	fmt.Printf("ZeroNonce      = %s\n", hex.EncodeToString(zeroNonce[:]))
	fmt.Printf("staticPublicKey= %s\n", hex.EncodeToString(staticPublicKey[:]))
	fmt.Printf("handshakeHash  = %s\n", hex.EncodeToString(handshakeHash[:]))
	fmt.Println()

	ciphertext := aead.Seal(
		msgStatic[:0],      // dst: 把输出直接写进 msgStatic
		zeroNonce[:],       // nonce: 这里模拟 WireGuard 的 ZeroNonce
		staticPublicKey[:], // plaintext: 要被加密的“我方静态公钥”
		handshakeHash[:],   // associated data: 当前握手上下文
	)

	fmt.Printf("len(staticPublicKey) = %d\n", len(staticPublicKey))
	fmt.Printf("AEAD overhead        = %d\n", chacha20poly1305.Overhead)
	fmt.Printf("len(ciphertext)      = %d\n", len(ciphertext))
	fmt.Printf("ciphertext(msgStatic)= %s\n", hex.EncodeToString(ciphertext))
	fmt.Println()

	opened, err := aead.Open(nil, zeroNonce[:], ciphertext, handshakeHash[:])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Open() -> %s\n", hex.EncodeToString(opened))
	fmt.Printf("Open() == staticPublicKey ? %v\n", string(opened) == string(staticPublicKey[:]))
	fmt.Println()

	_, err = aead.Open(nil, zeroNonce[:], ciphertext, []byte("wrong associated data"))
	fmt.Printf("Open() with wrong AD fails ? %v\n", err != nil)
}
