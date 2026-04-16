package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"golang.org/x/crypto/blake2s"
)

func main() {
	data := []byte("hello blake2s")

	// 创建 BLAKE2s-256（32字节）哈希器
	h, err := blake2s.New256(nil)
	if err != nil {
		log.Fatal(err)
	}

	h.Write(data)
	sum := h.Sum(nil)

	fmt.Println("input :", string(data))
	fmt.Println("hash  :", hex.EncodeToString(sum))
}
