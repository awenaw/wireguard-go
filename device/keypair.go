/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/replay"
)

/* Due to limitations in Go and /x/crypto there is currently
 * no way to ensure that key material is securely ereased in memory.
 *
 * Since this may harm the forward secrecy property,
 * we plan to resolve this issue; whenever Go allows us to do so.
 */

type Keypair struct {
	sendNonce    atomic.Uint64 // [发包计数器] 每次发包原子递增，作为 UDP 头显式发送，并参与加密 (作为 Nonce)。确保每个包唯一。
	send         cipher.AEAD   // [发包加密机] ChaCha20Poly1305 实例，绑定了握手协商出的 sendKey。
	receive      cipher.AEAD   // [收包解密机] ChaCha20Poly1305 实例，绑定了握手协商出的 recvKey。
	replayFilter replay.Filter // [收包防重放] 滑动窗口，记录在这个 Session 下对方用过的 Nonce，防止重放攻击。
	isInitiator  bool          // [身份标记] 记录我是握手发起方还是响应方。决定了谁负责 Rekey 以及新 Key 的生效策略。
	created      time.Time     // [诞生时间] 用于判断 Key 是否过期 (默认 120s 后 Rekey，180s 后 Reject)。
	localIndex   uint32        // [本地索引] 我分配给这个 Session 的 ID。对方发给我的包头里会填这个值，我用来查表找回这个 Keypair。
	remoteIndex  uint32        // [远端索引] 对方分配给这个 Session 的 ID。我发给对方的包头里会填这个值，供对方查表。
}

type Keypairs struct {
	sync.RWMutex
	current  *Keypair
	previous *Keypair
	next     atomic.Pointer[Keypair] // 为什么要用这种类型？
}

func (kp *Keypairs) Current() *Keypair {
	kp.RLock()
	defer kp.RUnlock()
	return kp.current
}

func (device *Device) DeleteKeypair(key *Keypair) {
	if key != nil {
		device.indexTable.Delete(key.localIndex)
	}
}
