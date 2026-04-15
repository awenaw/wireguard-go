/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"golang.zx2c4.com/wireguard/tai64n"
)

type handshakeState int

const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 148                                           // size of handshake initiation message
	MessageResponseSize        = 92                                            // size of response message
	MessageCookieReplySize     = 64                                            // size of cookie reply message
	MessageTransportHeaderSize = 16                                            // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                          // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                         // size of largest handshake related message
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral NoisePublicKey
	Static    [NoisePublicKeySize + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type      uint32
	Sender    uint32
	Receiver  uint32
	Ephemeral NoisePublicKey
	Empty     [poly1305.TagSize]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + poly1305.TagSize]byte
}

var errMessageLengthMismatch = errors.New("message length mismatch")

func (msg *MessageInitiation) unmarshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}

	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Ephemeral[:], b[8:])
	copy(msg.Static[:], b[8+len(msg.Ephemeral):])
	copy(msg.Timestamp[:], b[8+len(msg.Ephemeral)+len(msg.Static):])
	copy(msg.MAC1[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp):])
	copy(msg.MAC2[:], b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):])

	return nil
}

func (msg *MessageInitiation) marshal(b []byte) error {
	if len(b) != MessageInitiationSize {
		return errMessageLengthMismatch
	}

	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	copy(b[8:], msg.Ephemeral[:])
	copy(b[8+len(msg.Ephemeral):], msg.Static[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static):], msg.Timestamp[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp):], msg.MAC1[:])
	copy(b[8+len(msg.Ephemeral)+len(msg.Static)+len(msg.Timestamp)+len(msg.MAC1):], msg.MAC2[:])

	return nil
}

func (msg *MessageResponse) unmarshal(b []byte) error {
	if len(b) != MessageResponseSize {
		return errMessageLengthMismatch
	}

	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Sender = binary.LittleEndian.Uint32(b[4:])
	msg.Receiver = binary.LittleEndian.Uint32(b[8:])
	copy(msg.Ephemeral[:], b[12:])
	copy(msg.Empty[:], b[12+len(msg.Ephemeral):])
	copy(msg.MAC1[:], b[12+len(msg.Ephemeral)+len(msg.Empty):])
	copy(msg.MAC2[:], b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):])

	return nil
}

func (msg *MessageResponse) marshal(b []byte) error {
	if len(b) != MessageResponseSize { // 不满足响应包的固定长度要求，返回错误
		return errMessageLengthMismatch
	}

	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Sender)
	binary.LittleEndian.PutUint32(b[8:], msg.Receiver)
	copy(b[12:], msg.Ephemeral[:])
	copy(b[12+len(msg.Ephemeral):], msg.Empty[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty):], msg.MAC1[:])
	copy(b[12+len(msg.Ephemeral)+len(msg.Empty)+len(msg.MAC1):], msg.MAC2[:])

	return nil
}

func (msg *MessageCookieReply) unmarshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLengthMismatch
	}

	msg.Type = binary.LittleEndian.Uint32(b)
	msg.Receiver = binary.LittleEndian.Uint32(b[4:])
	copy(msg.Nonce[:], b[8:])
	copy(msg.Cookie[:], b[8+len(msg.Nonce):])

	return nil
}

func (msg *MessageCookieReply) marshal(b []byte) error {
	if len(b) != MessageCookieReplySize {
		return errMessageLengthMismatch
	}

	binary.LittleEndian.PutUint32(b, msg.Type)
	binary.LittleEndian.PutUint32(b[4:], msg.Receiver)
	copy(b[8:], msg.Nonce[:])
	copy(b[8+len(msg.Nonce):], msg.Cookie[:])

	return nil
}

type Handshake struct {
	state                     handshakeState
	mutex                     sync.RWMutex
	hash                      [blake2s.Size]byte       // hash  value
	chainKey                  [blake2s.Size]byte       // chain key
	presharedKey              NoisePresharedKey        // psk
	localEphemeral            NoisePrivateKey          // ephemeral secret key
	localIndex                uint32                   // used to clear hash-table
	remoteIndex               uint32                   // index for sending
	remoteStatic              NoisePublicKey           // long term key
	remoteEphemeral           NoisePublicKey           // ephemeral public key
	precomputedStaticStatic   [NoisePublicKeySize]byte // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

/* Do basic precomputations
 */
// device 包初始化时，init() 只执行一次，用来计算 Noise 协议的初始 chainKey 和 hash 。
// 每次都是一样的，前提是源码里的这两个常量没变：
// NoiseConstruction
// WGIdentifier
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

// Initiator 发起握手
// 此时的握手状态是 （handshakeInitiationCreated），生成 MessageInitiation 消息，准备发送给 Responder。
// 补充理解：这里不会直接发 UDP，而是先把第一条握手消息和本地握手现场准备好。
func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	// 这是一轮新握手的起点：先把 transcript（握手上下文） 重置为协议初始值，
	// 再生成本轮专用的本地临时密钥。
	var err error
	handshake.hash = InitialHash // 握手 transcript 的初始摘要种子
	handshake.chainKey = InitialChainKey
	handshake.localEphemeral, err = newPrivateKey() // 生成了本轮 ephemeral private key
	if err != nil {
		return nil, err
	}

	// 把对端静态公钥并入 transcript ，表示“我要和这个 peer 建立这轮握手”。
	handshake.mixHash(handshake.remoteStatic[:])

	// 先把第一条握手消息的明文字段搭出来：类型 + 我方临时公钥。
	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: handshake.localEphemeral.publicKey(),
	}

	// 把本轮临时公钥并入 transcript ；后续双方必须按同样顺序推进状态。
	handshake.mixKey(msg.Ephemeral[:])
	handshake.mixHash(msg.Ephemeral[:])

	// encrypt static key
	// 用本地临时私钥（localEphemeral）和对端静态公钥（remoteStatic）做 DH，派生出临时加密 key，
	// 再把我方静态公钥 密封 进 msg.Static（ 下面的aead.Seal那行） ，供对端识别发起方身份。
	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteStatic) // DH 计算出来的共享秘密材料（不是最终 session key，而是拿去喂给 KDF2，继续推进握手密钥状态）
	if err != nil {
		return nil, err
	}
	var key [chacha20poly1305.KeySize]byte
	// 这里把“旧的 chainKey”当作当前链式状态，把“上面那次 sharedSecret(...) 算出来的 ss”当作新材料，
	// 一起喂给 KDF2，导出两个结果：更新后的 chainKey，以及当前这一步专门拿来加密静态公钥的 key。
	KDF2(
		&handshake.chainKey,   // 输出 1：更新后的 chainKey，供后续握手步骤继续往下推导
		&key,                  // 输出 2：当前步骤的工作密钥，下面会立刻拿它创建 AEAD
		handshake.chainKey[:], // 输入 1：调用前的 chainKey，也就是握手当前的链式密钥状态
		ss[:],                 // 输入 2：上面那次 DH（localEphemeral x remoteStatic）产出的共享秘密 ss
	)
	// aead = 用当前步骤派生出来的 key，把某段数据安全封装成密文，并绑定到当前握手上下文。
	aead, _ := chacha20poly1305.New(key[:]) // 用上面 KDF2 导出的 key 实例化 AEAD，准备加密静态公钥了
	// 把我方静态公钥作为明文加密后写入 msg.Static，
	// 对端后续会解出这里的内容，用它确认发起方是谁。
	aead.Seal( // 把明文封起来，并盖上“防篡改封条”
		msg.Static[:0],                     // 输出目标：密文写到 msg.Static
		ZeroNonce[:],                       // nonce：这里固定使用全 0 nonce
		device.staticIdentity.publicKey[:], // 明文：我方静态公钥
		handshake.hash[:],                  // associated data：绑定当前握手 transcript，防止脱离上下文篡改
	)
	// 密文也要继续并入 transcript；对端解出后会按同样顺序推进。
	handshake.mixHash(msg.Static[:])

	// encrypt timestamp
	// 再用预计算好的 static-static 共享秘密派生出下一把 key，
	// 把时间戳加密进消息里，用来抵抗旧 initiation 的重放。
	if isZero(handshake.precomputedStaticStatic[:]) { // 如果 precomputedStaticStatic 是全 0，说明之前没有成功计算过 static-static 共享秘密，可能是因为对端公钥无效导致 DH 失败了。为了安全起见，这里直接拒绝发出 initiation。
		return nil, errInvalidPublicKey
	}
	KDF2(
		&handshake.chainKey,
		&key,
		handshake.chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	// 时间戳不明文发送，而是继续作为受 transcript 保护的密文载荷。
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])

	// assign index
	// 给这轮握手分配一个本地 sender index，方便对端后续回包时定位到这次握手。
	// 先删除旧 index，避免本地仍然残留上一轮握手的映射。
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	// 至此 initiation 已构造完成；本地保留好现场，等待 responder 的 response。
	// 时间戳密文是这条消息最后一个被纳入 transcript 的部分。
	handshake.mixHash(msg.Timestamp[:])
	// 状态推进到“initiation 已创建”，后续就应该等待并消费 response。
	handshake.state = handshakeInitiationCreated
	return &msg, nil
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	mixHash(&hash, &hash, msg.Ephemeral[:])
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])

	// decrypt static key
	var peerPK NoisePublicKey
	var key [chacha20poly1305.KeySize]byte
	ss, err := device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
	if err != nil {
		return nil
	}
	KDF2(&chainKey, &key, chainKey[:], ss[:])
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(peerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])

	// lookup peer

	peer := device.LookupPeer(peerPK)
	if peer == nil || !peer.isRunning.Load() {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	if isZero(handshake.precomputedStaticStatic[:]) {
		handshake.mutex.RUnlock()
		return nil
	}
	KDF2(
		&chainKey,
		&key,
		chainKey[:],
		handshake.precomputedStaticStatic[:],
	)
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

// 构建响应包

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}

	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	// create ephemeral key

	handshake.localEphemeral, err = newPrivateKey()
	if err != nil {
		return nil, err
	}
	msg.Ephemeral = handshake.localEphemeral.publicKey()
	handshake.mixHash(msg.Ephemeral[:])
	handshake.mixKey(msg.Ephemeral[:])

	ss, err := handshake.localEphemeral.sharedSecret(handshake.remoteEphemeral)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])
	ss, err = handshake.localEphemeral.sharedSecret(handshake.remoteStatic)
	if err != nil {
		return nil, err
	}
	handshake.mixKey(ss[:])

	// add preshared key

	var tau [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte

	KDF3(
		&handshake.chainKey,
		&tau,
		&key,
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:])

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	handshake.mixHash(msg.Empty[:])

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {
		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		// finish 3-way DH

		mixHash(&hash, &handshake.hash, msg.Ephemeral[:])
		mixKey(&chainKey, &handshake.chainKey, msg.Ephemeral[:])

		ss, err := handshake.localEphemeral.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		ss, err = device.staticIdentity.privateKey.sharedSecret(msg.Ephemeral)
		if err != nil {
			return false
		}
		mixKey(&chainKey, &chainKey, ss[:])
		setZero(ss[:])

		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte
		KDF3(
			&chainKey,
			&tau,
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)
		mixHash(&hash, &hash, tau[:])

		// authenticate transcript

		aead, _ := chacha20poly1305.New(key[:])
		_, err = aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}
		mixHash(&hash, &hash, msg.Empty[:])
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash
	handshake.chainKey = chainKey
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
// BeginSymmetricSession 根据当前握手状态派生新的 Keypair。
//
// 1. 派生 (Derive): 利用握手中的 chainKey，生成一对 send/recv 密钥。
// 2. 实例化 (Instantiate): 创建 Keypair 对象，初始化 ChaCha20Poly1305 AEAD。
// 3. 轮替 (Rotate): 根据是 Initiator 还是 Responder，决定新 Keypair 放在哪里 (Current 还是 Next)。
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys
	// [Key 派生]
	// 根据最后握手状态，决定谁是 Initiator，谁是 Responder。
	// 这决定了 sendKey 和 recvKey 的分配方向 (A发B收，还是B发A收)。

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == handshakeResponseConsumed {
		// 我是 Initiator (我收到了响应)
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		// 我是 Responder (我刚发出了响应)
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake
	// [握手复位]
	// 密钥已经拿到，握手状态可以清空了，为下一次握手做准备。
	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	// create AEAD instances
	// [构建 Keypair]
	// 初始化 ChaCha20-Poly1305 实例，从此刻起，数据包就可以被加解密了。
	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])    // 我发包时用它加密
	keypair.receive, _ = chacha20poly1305.New(recvKey[:]) // 我收包时用它解密

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index
	// [注册索引]
	// 告诉全局索引表：以后收到 index = localIndex 的包，就用这个 Keypair 处理。
	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs
	// [密钥安装与轮替]
	// 这是最关键的步骤：新生成的 Keypair 应该放在哪里？

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.next.Load()
	current := keypairs.current

	if isInitiator {
		// === 情况 A：我是 Initiator ===
		// “我很自信”。我收到了 Response，说明对方已经准备好了。
		// 所以我立刻把新 Key 设为 【Current】，马上开始用它发包。
		if next != nil {
			// 如果 Next 槽位里还有个没转正的备胎，直接丢弃（它已经过时了）。
			keypairs.next.Store(nil)
			keypairs.previous = next // 把它降级为 previous 稍微顶一顶乱序包
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous) // 更老的 Key 销毁
		keypairs.current = keypair
	} else {
		// === 情况 B：我是 Responder ===
		// “我很保守”。我虽然发了 Response，但不知道对方收到没。
		// 所以我先把新 Key 放在 【Next】 槽位（储君）。
		// 我继续用 Current (老国王) 发包，直到收到对方用新 Key 发来的包（ReceivedWithKeypair 触发转正）。
		keypairs.next.Store(keypair)
		device.DeleteKeypair(next) // 覆盖掉之前可能存在的 Next
		keypairs.previous = nil    // 此时不需要 Previous，因为 Current 还是原来的
		device.DeleteKeypair(previous)
	}

	return nil
}

// ReceivedWithKeypair 实现了接收方（responsor)的"被动转正"逻辑 (Key Confirmation)。
//
//  1. 为什么需要它？
//     作为响应方(Responder)，虽然我们在发送 Handshake Response 时就已经计算出了新 Keypair，
//     但我们不敢立刻使用它来加密发包。因为 UDP 是不可靠的，我们不知道发起方(Initiator)是否收到了这个 Response。
//     如果我们贸然切换到新 Key，而 Response 丢了，发起方还在用老 Key 解密，通信就会中断。
//     因此，我们把新 Key 暂存到 keypairs.next 中。
//
//  2. 什么时候触发？
//     当我们收到发起方用新 Key 加密过来的第一个数据包时！
//     这就证明发起方肯定收到了我们的 Response，并且已经切换到了新 Key。
//     此时，我们就可以放心地将 next 晋升为 current，完成转正。
func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	// [第一道防线：快速检查]
	// 大多数时候收到的都是用 current 加密的包。
	// 如果收到的包不是用 next 里的钥匙加密的，直接返回 false。
	// 这是一个高频路径，必须极快 (Atomic Load 无锁)。
	if keypairs.next.Load() != receivedKeypair {
		return false
	}

	// [第二道防线：加锁确认]
	// 既然发现这把钥匙竟然是 next 里的那把，说明转正时刻到了。
	// 加锁防止并发修改 (比如同时来了两个新 Key 的包)。
	keypairs.Lock()
	defer keypairs.Unlock()

	// Double-check: 防止在获取锁的瞬间 keypairs.next 已经被其他 goroutine 修改或清空了
	if keypairs.next.Load() != receivedKeypair {
		return false
	}

	// === 【被动转正核心动作 Key Rotation】 ===

	// 1. 老国王 (current) 退位，变成太上皇 (previous)
	//    保留它是为了在短时间内继续接收可能乱序到达的旧包 (Grace Period)。
	old := keypairs.previous
	keypairs.previous = keypairs.current

	// 2. 销毁更老的太上皇 (old)
	//    此时 keypairs.previous 指向了刚才的 current，
	//    那么原来那个 previous 就彻底没用了，从内存和索引表中抹除。
	peer.device.DeleteKeypair(old)

	// 3. 储君 (next) 登基，变成新国王 (current)
	//    从此以后，我们发包也开始用这把新钥匙了！
	keypairs.current = keypairs.next.Load()

	// 4. 清空储君位 (next = nil)
	//    在这个位置等待下一次握手产生的新 Key。
	keypairs.next.Store(nil)

	return true
}
