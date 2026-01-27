/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/hmac"
	"crypto/rand"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
)

type CookieChecker struct {
	sync.RWMutex
	mac1 struct {
		key [blake2s.Size]byte
	}
	mac2 struct {
		secret        [blake2s.Size]byte
		secretSet     time.Time
		encryptionKey [chacha20poly1305.KeySize]byte
	}
}

type CookieGenerator struct {
	sync.RWMutex
	mac1 struct {
		key [blake2s.Size]byte
	}
	mac2 struct {
		cookie        [blake2s.Size128]byte
		cookieSet     time.Time
		hasLastMAC1   bool
		lastMAC1      [blake2s.Size128]byte
		encryptionKey [chacha20poly1305.KeySize]byte
	}
}

func (st *CookieChecker) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	// mac1 state

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelMAC1))
		hash.Write(pk[:])
		hash.Sum(st.mac1.key[:0])
	}()

	// mac2 state

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelCookie))
		hash.Write(pk[:])
		hash.Sum(st.mac2.encryptionKey[:0])
	}()

	st.mac2.secretSet = time.Time{}
}

func (st *CookieChecker) CheckMAC1(msg []byte) bool {
	st.RLock()
	defer st.RUnlock()

	size := len(msg)
	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	var mac1 [blake2s.Size128]byte

	mac, _ := blake2s.New128(st.mac1.key[:])
	mac.Write(msg[:smac1])
	mac.Sum(mac1[:0])

	return hmac.Equal(mac1[:], msg[smac1:smac2])
}

func (st *CookieChecker) CheckMAC2(msg, src []byte) bool {
	st.RLock()
	defer st.RUnlock()

	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		return false
	}

	// derive cookie key

	var cookie [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(st.mac2.secret[:])
		mac.Write(src)
		mac.Sum(cookie[:0])
	}()

	// calculate mac of packet (including mac1)

	smac2 := len(msg) - blake2s.Size128

	var mac2 [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(cookie[:])
		mac.Write(msg[:smac2])
		mac.Sum(mac2[:0])
	}()

	return hmac.Equal(mac2[:], msg[smac2:])
}

// CreateReply 构造一个 Cookie 回复包 (Type 3)。
// 当设备处于高负载 (Under Load) 状态时，会拒绝正常的握手并调用此方法给对方发个"小饼干"。
func (st *CookieChecker) CreateReply(
	msg []byte, // 原始握手请求包的内容
	recv uint32, // 对方的 Index
	src []byte, // 对方的 IP 地址 (Cookie 绑定的核心)
) (*MessageCookieReply, error) {
	st.RLock()

	// 1. 【Secret 定期轮换】
	// 为了安全性，接收端维护一个随机的 Secret，每隔 2 分钟刷新一次。
	// Cookie 的安全性完全基于这个 Secret。
	if time.Since(st.mac2.secretSet) > CookieRefreshTime {
		st.RUnlock()
		st.Lock()
		_, err := rand.Read(st.mac2.secret[:]) // 重新生成随机密钥
		if err != nil {
			st.Unlock()
			return nil, err
		}
		st.mac2.secretSet = time.Now()
		st.Unlock()
		st.RLock()
	}

	// 2. 【推导 Cookie 内容】
	// 无状态绑定：Cookie = MAC(key=Secret, input=SourceIP)
	// 这样我们就把令牌和对方的 IP 强行锁死在一起了。
	var cookie [blake2s.Size128]byte
	func() {
		mac, _ := blake2s.New128(st.mac2.secret[:])
		mac.Write(src)
		mac.Sum(cookie[:0])
	}()

	// 3. 【准备加密回复包】
	size := len(msg)
	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	reply := new(MessageCookieReply)
	reply.Type = MessageCookieReplyType // Type 3
	reply.Receiver = recv               // 对方的索引

	// 生成 24 字节长随机 Nonce (用于 XChaCha20)
	_, err := rand.Read(reply.Nonce[:])
	if err != nil {
		st.RUnlock()
		return nil, err
	}

	// 4. 【加密并加封】
	// Cookie 本身是敏感信息，不能明文发。
	// 使用 encryptionKey (由接收端公钥推导) 进行加密。
	// 将原包的 MAC1 字段作为关联数据 (AD)，确保这个 Cookie 只能对应刚才那个过期的请求。
	xchapoly, _ := chacha20poly1305.NewX(st.mac2.encryptionKey[:])
	xchapoly.Seal(reply.Cookie[:0], reply.Nonce[:], cookie[:], msg[smac1:smac2])

	st.RUnlock()

	return reply, nil
}

func (st *CookieGenerator) Init(pk NoisePublicKey) {
	st.Lock()
	defer st.Unlock()

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelMAC1))
		hash.Write(pk[:])
		hash.Sum(st.mac1.key[:0])
	}()

	func() {
		hash, _ := blake2s.New256(nil)
		hash.Write([]byte(WGLabelCookie))
		hash.Write(pk[:])
		hash.Sum(st.mac2.encryptionKey[:0])
	}()

	st.mac2.cookieSet = time.Time{}
}

func (st *CookieGenerator) ConsumeReply(msg *MessageCookieReply) bool {
	st.Lock()
	defer st.Unlock()

	if !st.mac2.hasLastMAC1 {
		return false
	}

	var cookie [blake2s.Size128]byte

	xchapoly, _ := chacha20poly1305.NewX(st.mac2.encryptionKey[:])
	_, err := xchapoly.Open(cookie[:0], msg.Nonce[:], msg.Cookie[:], st.mac2.lastMAC1[:])
	if err != nil {
		return false
	}

	st.mac2.cookieSet = time.Now()
	st.mac2.cookie = cookie
	return true
}

func (st *CookieGenerator) AddMacs(msg []byte) {
	size := len(msg)

	smac2 := size - blake2s.Size128
	smac1 := smac2 - blake2s.Size128

	mac1 := msg[smac1:smac2]
	mac2 := msg[smac2:]

	st.Lock()
	defer st.Unlock()

	// set mac1

	func() {
		mac, _ := blake2s.New128(st.mac1.key[:])
		mac.Write(msg[:smac1])
		mac.Sum(mac1[:0])
	}()
	copy(st.mac2.lastMAC1[:], mac1)
	st.mac2.hasLastMAC1 = true

	// set mac2

	if time.Since(st.mac2.cookieSet) > CookieRefreshTime {
		return
	}

	func() {
		mac, _ := blake2s.New128(st.mac2.cookie[:])
		mac.Write(msg[:smac2])
		mac.Sum(mac2[:0])
	}()
}
