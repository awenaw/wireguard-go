/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

/* Outbound flow
 *
 * 1. TUN queue
 * 2. Routing (sequential)
 * 3. Nonce assignment (sequential)
 * 4. Encryption (parallel)
 * 5. Transmission (sequential)
 *
 * The functions in this file occur (roughly) in the order in
 * which the packets are processed.
 *
 * Locking, Producers and Consumers
 *
 * The order of packets (per peer) must be maintained,
 * but encryption of packets happen out-of-order:
 *
 * The sequential consumers will attempt to take the lock,
 * workers release lock when they have completed work (encryption) on the packet.
 *
 * If the element is inserted into the "encryption queue",
 * the content is preceded by enough "junk" to contain the transport header
 * (to allow the construction of transport messages in-place)
 */

type QueueOutboundElement struct {
	buffer  *[MaxMessageSize]byte // slice holding the packet data
	packet  []byte                // slice of "buffer" (always!)
	nonce   uint64                // nonce for encryption
	keypair *Keypair              // keypair for encryption
	peer    *Peer                 // related peer
}

// 加密顺序保障-每个peer的包必须按顺序加密（加密可乱序，发送必有序）
type QueueOutboundElementsContainer struct {
	sync.Mutex
	elems []*QueueOutboundElement
}

func (device *Device) NewOutboundElement() *QueueOutboundElement {
	elem := device.GetOutboundElement()
	elem.buffer = device.GetMessageBuffer()
	elem.nonce = 0
	// keypair and peer were cleared (if necessary) by clearPointers.
	return elem
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueOutboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.peer = nil
}

/* Queues a keepalive if no packets are queued for peer
 */
func (peer *Peer) SendKeepalive() { // 是否由定时器调用？
	if len(peer.queue.staged) == 0 && peer.isRunning.Load() {
		elem := peer.device.NewOutboundElement()
		elemsContainer := peer.device.GetOutboundElementsContainer()
		elemsContainer.elems = append(elemsContainer.elems, elem)
		select {
		case peer.queue.staged <- elemsContainer:
			peer.device.log.Verbosef("%v - Sending keepalive packet", peer)
		default:
			peer.device.PutMessageBuffer(elem.buffer)
			peer.device.PutOutboundElement(elem)
			peer.device.PutOutboundElementsContainer(elemsContainer)
		}
	}
	peer.SendStagedPackets()
}

// 当数据要发送，发现没密钥，则发送握手初始化方法
func (peer *Peer) SendHandshakeInitiation(isRetry bool) error {
	if !isRetry {
		peer.timers.handshakeAttempts.Store(0)
	}

	peer.handshake.mutex.RLock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.RUnlock()
		return nil
	}
	peer.handshake.mutex.RUnlock()

	peer.handshake.mutex.Lock()
	if time.Since(peer.handshake.lastSentHandshake) < RekeyTimeout {
		peer.handshake.mutex.Unlock()
		return nil
	}
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake initiation", peer)

	msg, err := peer.device.CreateMessageInitiation(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create initiation message: %v", peer, err)
		return err
	}

	packet := make([]byte, MessageInitiationSize)
	_ = msg.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake initiation: %v", peer, err)
	}
	peer.timersHandshakeInitiated()

	return err
}

func (peer *Peer) SendHandshakeResponse() error {
	peer.handshake.mutex.Lock()
	peer.handshake.lastSentHandshake = time.Now()
	peer.handshake.mutex.Unlock()

	peer.device.log.Verbosef("%v - Sending handshake response", peer)

	response, err := peer.device.CreateMessageResponse(peer)
	if err != nil {
		peer.device.log.Errorf("%v - Failed to create response message: %v", peer, err)
		return err
	}

	packet := make([]byte, MessageResponseSize)
	_ = response.marshal(packet)
	peer.cookieGenerator.AddMacs(packet)

	err = peer.BeginSymmetricSession()
	if err != nil {
		peer.device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
		return err
	}

	peer.timersSessionDerived()
	peer.timersAnyAuthenticatedPacketTraversal()
	peer.timersAnyAuthenticatedPacketSent()

	// TODO: allocation could be avoided
	err = peer.SendBuffers([][]byte{packet})
	if err != nil {
		peer.device.log.Errorf("%v - Failed to send handshake response: %v", peer, err)
	}
	return err
}

func (device *Device) SendHandshakeCookie(initiatingElem *QueueHandshakeElement) error {
	device.log.Verbosef("Sending cookie response for denied handshake message for %v", initiatingElem.endpoint.DstToString())

	sender := binary.LittleEndian.Uint32(initiatingElem.packet[4:8])
	reply, err := device.cookieChecker.CreateReply(initiatingElem.packet, sender, initiatingElem.endpoint.DstToBytes())
	if err != nil {
		device.log.Errorf("Failed to create cookie reply: %v", err)
		return err
	}

	packet := make([]byte, MessageCookieReplySize)
	_ = reply.marshal(packet)
	// TODO: allocation could be avoided
	device.net.bind.Send([][]byte{packet}, initiatingElem.endpoint)

	return nil
}

// aw: 每次发送完更新密钥，确保密钥有效
func (peer *Peer) keepKeyFreshSending() {
	keypair := peer.keypairs.Current()
	if keypair == nil {
		return
	}
	nonce := keypair.sendNonce.Load()
	if nonce > RekeyAfterMessages || (keypair.isInitiator && time.Since(keypair.created) > RekeyAfterTime) {
		peer.SendHandshakeInitiation(false)
	}
}

// aw-开荒: 隧道入口（上一站是内核）。设备接受外部传入的数据包
// 发包入口：内核 -> Go (读自 TUN)
// 在这个函数 RoutineReadFromTUN
// 命中时，你能看到最原始、还没被加工过的原始 IP 包。
// 如果你想在代码里改包的内容、或者做一些流量监控，这里就是第一战场。
// wggo 拿货的地方
func (device *Device) RoutineReadFromTUN() { // aw-开荒: [读取 TUN]-发包
	defer func() {
		device.log.Verbosef("Routine: TUN reader - stopped")
		device.state.stopping.Done()
		device.queue.encryption.wg.Done()
	}()

	device.log.Verbosef("Routine: TUN reader - started")

	var (
		batchSize   = device.BatchSize()
		readErr     error
		elems       = make([]*QueueOutboundElement, batchSize)
		bufs        = make([][]byte, batchSize)
		elemsByPeer = make(map[*Peer]*QueueOutboundElementsContainer, batchSize)
		count       = 0
		sizes       = make([]int, batchSize)
		offset      = MessageTransportHeaderSize
	)

	for i := range elems {
		elems[i] = device.NewOutboundElement()
		bufs[i] = elems[i].buffer[:]
	}

	defer func() {
		for _, elem := range elems {
			if elem != nil {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
		}
	}()

	for {
		// read packets
		// aw-在向内核“讨要”通过 utun 传过来的数据包
		count, readErr = device.tun.device.Read(bufs, sizes, offset)
		for i := 0; i < count; i++ {
			if sizes[i] < 1 {
				continue
			}

			elem := elems[i]
			elem.packet = bufs[i][offset : offset+sizes[i]]

			// aw-开荒: 打印发送的明文 IP 包
			device.log.Verbosef("[3. 出站] 内层IP包 (来自内核，准备加密) 大小: %d, IP版本: %d, 前20字节: %x", len(elem.packet), elem.packet[0]>>4, elem.packet[:min(20, len(elem.packet))])

			// lookup peer
			// aw-开荒: [物流分拣]
			// 这里根据目标 IP (10.166.0.2) 查路由表，决定把包给谁。
			var peer *Peer
			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				dst := elem.packet[IPv4offsetDst : IPv4offsetDst+net.IPv4len]
				peer = device.allowedips.Lookup(dst)
				if peer == nil {
					device.log.Verbosef("[路由丢弃] 目标 %d.%d.%d.%d 未在任何 Peer 的 AllowedIPs 中找到", dst[0], dst[1], dst[2], dst[3])
					continue
				}

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				dst := elem.packet[IPv6offsetDst : IPv6offsetDst+net.IPv6len]
				peer = device.allowedips.Lookup(dst)

			default:
				device.log.Verbosef("Received packet with unknown IP version (first byte: %x)", elem.packet[0])
			}

			if peer == nil {
				continue
			}
			elemsForPeer, ok := elemsByPeer[peer]
			if !ok {
				elemsForPeer = device.GetOutboundElementsContainer()
				elemsByPeer[peer] = elemsForPeer
			}
			elemsForPeer.elems = append(elemsForPeer.elems, elem)
			elems[i] = device.NewOutboundElement()
			bufs[i] = elems[i].buffer[:]
		}

		for peer, elemsForPeer := range elemsByPeer {
			if peer.isRunning.Load() {
				//peer.queue.staged 本身就是一个缓冲区。 💗
				//SendStagedPackets的工作就是排空这个缓冲区
				// 先 StagePackets（挂号排队），
				// 再 SendStagedPackets（叫号发货）。
				// 这保证了永远是最老的包最先尝试发送，新包永远排在旧包后面。
				peer.StagePackets(elemsForPeer) // 把包塞进 peer.queue.staged 队列里暂存
				peer.SendStagedPackets()        // 进入加密和发送流程💗
			} else {
				for _, elem := range elemsForPeer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutOutboundElement(elem)
				}
				device.PutOutboundElementsContainer(elemsForPeer)
			}
			delete(elemsByPeer, peer)
		}

		if readErr != nil {
			if errors.Is(readErr, tun.ErrTooManySegments) {
				// TODO: record stat for this
				// This will happen if MSS is surprisingly small (< 576)
				// coincident with reasonably high throughput.
				device.log.Verbosef("Dropped some packets from multi-segment read: %v", readErr)
				continue
			}
			if !device.isClosed() {
				if !errors.Is(readErr, os.ErrClosed) {
					device.log.Errorf("Failed to read packet from TUN device: %v", readErr)
				}
				go device.Close()
			}
			return
		}
	}
}

func (peer *Peer) StagePackets(elems *QueueOutboundElementsContainer) {
	for {
		// [非阻塞入队]
		// 这里使用 select + default 是 Go 实现"TrySend"的标准姿势。
		// 为什么不用 if len(q) < cap(q)？因为并发环境下，if 判断后的一瞬间，
		// 队列可能就被别人填满了，这时候再塞就会导致当前协程卡死(Block)。
		// select 保证了原子性：要么瞬间塞进去，要么瞬间走 default，绝不等待。
		select {
		case peer.queue.staged <- elems:
			return
		default:
		}

		// [队满策略：挤掉最老的]
		// 能走到这里，说明上面的入队失败了（队列满了）。
		// 为什么不把读写写在一个 select 里？因为 Go 的 select 是随机的！
		// 如果写在一起，队列没满的时候也可能随机走到"读出丢弃"的分支，那就乱套了。
		// 必须分开写，实现"优先入队，失败再丢包"的逻辑。
		select {
		case tooOld := <-peer.queue.staged:
			// "<-" 操作符会自动从 channel 头部弹出(Pop)数据。
			// 因为 channel 是先进先出(FIFO)的，所以弹出的这一个肯定是"最老的"。
			// 拿到它之后，我们不做处理直接回收内存，就等于把它"踢掉"了。
			for _, elem := range tooOld.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(tooOld)
		default:
		}
	}
}

// 发送暂存的包
func (peer *Peer) SendStagedPackets() {
top:
	// [阶段 1: 准备与检查 (Pre-flight Checks)]
	// 职责: 确保环境就绪，队列有货，设备在跑。
	if len(peer.queue.staged) == 0 || !peer.device.isUp() {
		return
	}

	// [握手检查 (Handshake Barrier)]
	// 职责: 拿钥匙。如果还没握手成功，或者钥匙过期了，坚决不发。
	// 1. 获取当前 Keypair。
	// 2. 如果 Key 无效，触发握手 (SendHandshakeInitiation)，并保持包在队列中等待。
	//    这是一个 Backpressure (背压) 机制，防止无密钥的空转加密。
	keypair := peer.keypairs.Current()
	if keypair == nil || keypair.sendNonce.Load() >= RejectAfterMessages || time.Since(keypair.created) >= RejectAfterTime {
		peer.SendHandshakeInitiation(false) // 会重新生成这个 peer 的 keypair
		return
	}

	// [阶段 2: 大循环出货 (The Loop)]
	// 职责: 只要队列里有包，就一直用当前 Key 发送，直到队列空或者 Key 耗尽。
	for {
		// elemsContainerOOO (Out-Of-Order) 是用来处理 "Key Exhaustion" (2^64-1 Nonce 用光) 的。
		// 在极端情况下，这批包的一部分可能用完了当前 Key 的 Nonce 配额，
		// 必须把剩下的包收集到 OOO 容器里，重新塞回 Staged 队列，等下一个 Key 协商好了再发。
		var elemsContainerOOO *QueueOutboundElementsContainer
		select {
		// [阶段 3: 出队 (De-queue)]
		// 职责: 从暂存区 (Staged) 拿出一个完整的 Batch (最多128个包)。
		case elemsContainer := <-peer.queue.staged:
			i := 0
			// [阶段 4: 遍历箱子与分配 (Iteration & Allocation)]
			// 职责:
			// 1. 绑定 Peer 和 Keypair。
			// 2. 分配唯一的 Nonce (Atomic Add)。这是保序发送的基石。
			// 3. 检查 Nonce 是否耗尽。
			for _, elem := range elemsContainer.elems {
				elem.peer = peer
				// [分配身份证 (Assign Nonce)]
				elem.nonce = keypair.sendNonce.Add(1) - 1

				// [Key 耗尽检查 (Key Exhaustion)]
				if elem.nonce >= RejectAfterMessages {
					keypair.sendNonce.Store(RejectAfterMessages)
					if elemsContainerOOO == nil {
						elemsContainerOOO = peer.device.GetOutboundElementsContainer()
					}
					// 当前 Key 已废，剩下的包先存起来，等下一班车
					elemsContainerOOO.elems = append(elemsContainerOOO.elems, elem)
					continue
				} else {
					// 正常分配
					elemsContainer.elems[i] = elem
					i++
				}

				elem.keypair = keypair
			}

			// [阶段 5: 锁定与回炉 (Lock & Reschedule)]
			// 职责:
			// 1. 对容器加锁 (Mutex Lock)。确保下游的 SequentialSender 必须等待 Encryption 完成。
			// 2. 裁剪掉被 OOO 剔除的元素。
			// 3. 如果有 OOO 包，重新入队 (Re-Stage)。
			elemsContainer.Lock()
			elemsContainer.elems = elemsContainer.elems[:i]

			if elemsContainerOOO != nil {
				peer.StagePackets(elemsContainerOOO) // Re-queue the stragglers
			}

			if len(elemsContainer.elems) == 0 {
				peer.device.PutOutboundElementsContainer(elemsContainer)
				goto top // 这个 Batch 全军覆没(都OOO了)，重来
			}

			// add to parallel and sequential queue
			// [阶段 6: 双通道分发 (Double Dispatch)]
			// 职责: 将同一个 Container 分发给两个并行的消费者。
			// 通道 1 (Outbound): 给 SequentialSender，它会由 Lock 阻塞，等加密完后负责按序物理发送。
			// 通道 2 (Encryption): 给 RoutineEncryption (Worker Pool)，它们负责并发、乱序地进行 ChaCha20Poly1305 加密。
			if peer.isRunning.Load() {
				peer.queue.outbound.c <- elemsContainer
				peer.device.queue.encryption.c <- elemsContainer
			} else {
				for _, elem := range elemsContainer.elems {
					peer.device.PutMessageBuffer(elem.buffer)
					peer.device.PutOutboundElement(elem)
				}
				peer.device.PutOutboundElementsContainer(elemsContainer)
			}

			if elemsContainerOOO != nil {
				goto top
			}
		default:
			return
		}
	}
}

func (peer *Peer) FlushStagedPackets() {
	for {
		select {
		case elemsContainer := <-peer.queue.staged:
			for _, elem := range elemsContainer.elems {
				peer.device.PutMessageBuffer(elem.buffer)
				peer.device.PutOutboundElement(elem)
			}
			peer.device.PutOutboundElementsContainer(elemsContainer)
		default:
			return
		}
	}
}

func calculatePaddingSize(packetSize, mtu int) int {
	lastUnit := packetSize
	if mtu == 0 {
		return ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1)) - lastUnit
	}
	if lastUnit > mtu {
		lastUnit %= mtu
	}
	paddedSize := ((lastUnit + PaddingMultiple - 1) & ^(PaddingMultiple - 1))
	if paddedSize > mtu {
		paddedSize = mtu
	}
	return paddedSize - lastUnit
}

/* Encrypts the elements in the queue
 * and marks them for sequential consumption (by releasing the mutex)
 *
 * Obs. One instance per core
 */
// aw-开荒: [加密工人工厂]
// 这是 WireGuard 的核心动力室。通常每一个 CPU 核心都会运行一个这样的协程。
// 它们从全局的加密队列里抢任务，利用多核优势并发计算 ChaCha20Poly1305。
func (device *Device) RoutineEncryption(id int) {
	var paddingZeros [PaddingMultiple]byte
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: encryption worker %d - stopped", id)
	device.log.Verbosef("Routine: encryption worker %d - started", id)

	// 不停地从队列里拿"一筐"待加密的包
	for elemsContainer := range device.queue.encryption.c {

		// 遍历这一筐里的每一个包
		for _, elem := range elemsContainer.elems {
			// populate header fields
			header := elem.buffer[:MessageTransportHeaderSize]

			fieldType := header[0:4]
			fieldReceiver := header[4:8]
			fieldNonce := header[8:16]

			// 1. 填写 UDP 头 (Type=4, ReceiverIndex, Nonce)
			// 注意：nonce 已经在入队前分配好了 (在 SendStagedPackets 里)，这里只是填进去。
			// ReceiverIndex 是告诉对方："这是发给你的第 [remoteIndex] 号连接的"。
			binary.LittleEndian.PutUint32(fieldType, MessageTransportType)
			binary.LittleEndian.PutUint32(fieldReceiver, elem.keypair.remoteIndex)
			binary.LittleEndian.PutUint64(fieldNonce, elem.nonce)

			// pad content to multiple of 16
			// 2. 填充数据 (Padding)
			// 为了对抗流量分析 (Traffic Analysis)，防止攻击者通过包大小猜测内容，
			// 将数据包长度对齐到 16 字节 (ChaCha20 的 Block Size)。
			paddingSize := calculatePaddingSize(len(elem.packet), int(device.tun.mtu.Load()))
			elem.packet = append(elem.packet, paddingZeros[:paddingSize]...)

			// encrypt content and release to consumer
			// 3. 核心加密 (Seal) !
			// 构造 12 字节的 Nonce: 前 4 字节为 0，后 8 字节为 Counter (sendNonce)。
			binary.LittleEndian.PutUint64(nonce[4:], elem.nonce)

			// 调用 ChaCha20-Poly1305 进行加密 + 认证
			// header 作为 Associated Data (AD) 参与认证，但不被加密。
			// 这保证了包头 (包括 Counter) 不能被篡改。
			elem.packet = elem.keypair.send.Seal(
				header,      // dst: 结果直接写回 header 后面 (In-place encryption)
				nonce[:],    // nonce
				elem.packet, // plaintext
				nil,         // additional data
			)
		}

		// 4. 交卷 (Unlock)
		// 解开这个容器的锁。
		// 在另一头死等这个锁的 'RoutineSequentialSender' 就会立刻苏醒，
		// 把已经加密好的数据发出去。
		elemsContainer.Unlock()
	}
}

// 严格按顺序发送IP包
// 每个 Peer 都有一个专门负责发货的协程。每个Peer 只有一个！
// 它的职责是按照 nonce 的顺序，将加密好的数据包通过 UDP 发送出去。
func (peer *Peer) RoutineSequentialSender(maxBatchSize int) {
	device := peer.device
	defer func() {
		defer device.log.Verbosef("%v - Routine: sequential sender - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential sender - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	// 死守 outbound 队列
	// 这个队列里的东西，是那边 Encrypt Worker 正在处理（或已处理完）的容器
	for elemsContainer := range peer.queue.outbound.c {
		bufs = bufs[:0]
		if elemsContainer == nil {
			return
		}
		if !peer.isRunning.Load() {
			// peer has been stopped; return re-usable elems to the shared pool.
			// This is an optimization only. It is possible for the peer to be stopped
			// immediately after this check, in which case, elem will get processed.
			// The timers and SendBuffers code are resilient to a few stragglers.
			// TODO: rework peer shutdown order to ensure
			// that we never accidentally keep timers alive longer than necessary.

			// 如果 Peer 停了，就只要回收资源，不发送
			elemsContainer.Lock()
			for _, elem := range elemsContainer.elems {
				device.PutMessageBuffer(elem.buffer)
				device.PutOutboundElement(elem)
			}
			device.PutOutboundElementsContainer(elemsContainer)
			continue
		}
		dataSent := false

		// 1. 等待加密完成 (Wait Lock)
		// 如果加密工人还没解开锁 (Unlock)，这里就会阻塞。
		// 这保证了即便加密是乱序并发的，发货一定是严格顺序的。
		elemsContainer.Lock()

		// aw-开荒: [出货口]
		// 能走到这里，说明锁拿到了，包已经是加密好的密文 (Ciphertext) 了。
		for _, elem := range elemsContainer.elems {
			// [判断是否为心跳包]
			// WireGuard 的 Keepalive 本质上就是一个 Payload 为 0 的加密数据包 (Type 4)。
			// 它的总长度 = Header(16) + Poly1305 Tag(16) = 32 字节 (MessageKeepaliveSize)。
			// 如果长度只有 32，说明它只是为了证明"我还活着且密钥有效"，不包含用户数据。
			// 如果大于 32，说明里面有真正的用户数据 (dataSent = true)。
			if len(elem.packet) != MessageKeepaliveSize {
				dataSent = true
			}
			bufs = append(bufs, elem.packet)

			// aw-开荒: 打印发出的加密 UDP 包
			if len(elem.packet) >= 4 {
				msgType := binary.LittleEndian.Uint32(elem.packet[:4])
				endpointStr := "unknown"
				if peer.endpoint.val != nil {
					endpointStr = peer.endpoint.val.DstToString()
				}
				var msgDesc string
				switch msgType {
				case MessageInitiationType: // 1 // 字节数组： [1, 0, 0, 0]（低位->高位）
					msgDesc = "(握手请求)"
				case MessageResponseType: // 2
					msgDesc = "(握手响应)"
				case MessageCookieReplyType: // 3
					msgDesc = "(Cookie回复)"
				case MessageTransportType: // 4
					msgDesc = "(加密数据)"
				default:
					msgDesc = "(未知类型)"
				}
				device.log.Verbosef("[4. 发送] 外层UDP包 %s 大小: %d, 类型: %d, 目标: %s", msgDesc, len(elem.packet), msgType, endpointStr)
			}
		}

		// 2. 更新计时器
		// 告诉系统：我发了个验证过的包，重置 keepalive 计时器
		peer.timersAnyAuthenticatedPacketTraversal()
		peer.timersAnyAuthenticatedPacketSent()

		// 3. 物理发送 (Send)
		// 调用底层的 Bind (UDP Socket) 把这一批密文射向公网
		err := peer.SendBuffers(bufs)
		if dataSent {
			peer.timersDataSent()
		}
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutOutboundElement(elem)
		}
		device.PutOutboundElementsContainer(elemsContainer)
		if err != nil {
			var errGSO conn.ErrUDPGSODisabled
			if errors.As(err, &errGSO) {
				device.log.Verbosef(err.Error())
				err = errGSO.RetryErr
			}
		}
		if err != nil {
			device.log.Errorf("%v - Failed to send data packets: %v", peer, err)
			continue
		}

		peer.keepKeyFreshSending()
	}
}
