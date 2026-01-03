/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.zx2c4.com/wireguard/conn"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint conn.Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	buffer   *[MaxMessageSize]byte
	packet   []byte
	counter  uint64
	keypair  *Keypair
	endpoint conn.Endpoint
}

type QueueInboundElementsContainer struct {
	sync.Mutex
	elems []*QueueInboundElement
}

// clearPointers clears elem fields that contain pointers.
// This makes the garbage collector's life easier and
// avoids accidentally keeping other objects around unnecessarily.
// It also reduces the possible collateral damage from use-after-free bugs.
func (elem *QueueInboundElement) clearPointers() {
	elem.buffer = nil
	elem.packet = nil
	elem.keypair = nil
	elem.endpoint = nil
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Load() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Since(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Store(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 * aw-开荒: [收发室 - 总分拣中心]
 * 核心逻辑：这个函数是 WireGuard 数据流入的第一站，负责从 UDP 端口高吞吐地收包。
 * 它不进行繁重的解密工作，只负责 IO 和分发，采用 Recv -> Sort -> Dispatch 三部曲：
 *
 * 1. [Recv] 收货: 调用 recv() 从内核批量收取 UDP 包 (Batching)
 * 2. [Sort] 分拣: 根据包类型 (Type) 和 Index，将加密数据包按 Peer 归类；将握手包单独处理。
 * 3. [Dispatch] 发货: 将分好类的加密包，批量推送到解密队列 (Decryption Queue) 供后台 Worker 并行处理。
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(maxBatchSize int, recv conn.ReceiveFunc) {
	recvName := recv.PrettyName()
	defer func() {
		device.log.Verbosef("Routine: receive incoming %s - stopped", recvName)
		device.queue.decryption.wg.Done()
		device.queue.handshake.wg.Done()
		device.net.stopping.Done()
	}()

	device.log.Verbosef("Routine: receive incoming %s - started", recvName)

	// receive datagrams until conn is closed
	// 持续循环收包，直到连接关闭
	var (
		bufsArrs    = make([]*[MaxMessageSize]byte, maxBatchSize) // 缓冲池指针数组 (存放这一批包的内存地址)
		bufs        = make([][]byte, maxBatchSize)                // 字节切片视图 (recv函数直接写入这里)
		err         error
		sizes       = make([]int, maxBatchSize) // 存放每个包的实际收到长度
		count       int
		endpoints   = make([]conn.Endpoint, maxBatchSize)                          // 存放来源 IP:Port
		deathSpiral int                                                            // 连续错误计数器 (用于指数退避)
		elemsByPeer = make(map[*Peer]*QueueInboundElementsContainer, maxBatchSize) // 临时分拣车: 按 Peer 归类的待处理包裹
	)

	for i := range bufsArrs {
		bufsArrs[i] = device.GetMessageBuffer() // [内存分配] 从 Pool 借 128 个空盘子
		bufs[i] = bufsArrs[i][:]
	}

	defer func() {
		for i := 0; i < maxBatchSize; i++ {
			if bufsArrs[i] != nil {
				device.PutMessageBuffer(bufsArrs[i]) // [内存回收] 退出也没忘还盘子
			}
		}
	}()

	for {
		// [Step 1: Recv] 调用内核 syscall 收包
		count, err = recv(bufs, sizes, endpoints)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			device.log.Verbosef("Failed to receive %s packet: %v", recvName, err)
			if neterr, ok := err.(net.Error); ok && !neterr.Temporary() {
				return
			}
			// 遇到错误进行简单的退避重试 (避免 CPU 空转)
			if deathSpiral < 10 {
				deathSpiral++
				time.Sleep(time.Second / 3)
				continue
			}
			return
		}
		deathSpiral = 0

		// handle each packet in the batch
		// [Step 2: Sort] 遍历这一批收到的每一个包
		for i, size := range sizes[:count] {
			if size < MinMessageSize {
				continue
			}

			// check size of packet

			packet := bufsArrs[i][:size]
			msgType := binary.LittleEndian.Uint32(packet[:4]) // 解析前4字节: 消息类型

			var msgDesc string
			switch msgType {
			case MessageInitiationType: // 1
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

			// aw-开荒: 打印收到的 UDP 包
			device.log.Verbosef("[1. 接收] 外层UDP包 %s 大小: %d, 类型: %d, 来源: %s", msgDesc, size, msgType, endpoints[i].DstToString())

			switch msgType {

			// check if transport
			// === 核心路径: 处理加密数据包 (Type 4) ===
			case MessageTransportType:

				// check size

				if len(packet) < MessageTransportSize {
					continue
				}

				// lookup key pair
				// 解析 Receiver Index (4字节) -> 用来去查 "这包是发给谁的?"
				receiver := binary.LittleEndian.Uint32(
					packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
				)
				// [查表] 根据 Index 找到对应的 Keypair (里面包含了 Peer 信息)
				value := device.indexTable.Lookup(receiver)
				keypair := value.keypair
				if keypair == nil {
					// 查无此人，直接丢弃 (可能是过期连接或攻击包)
					continue
				}

				// check keypair expiry

				if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
					continue // Keypair 过期，丢弃
				}

				// create inbound element
				// [入队准备] 找到是哪个 Peer 后，准备打包
				peer := value.peer
				elem := device.GetInboundElement() // 申请一个包装盒 struct
				elem.packet = packet
				elem.buffer = bufsArrs[i] // 转移 Buffer 所有权! (注意: 下面 bufsArrs[i] 会置 nil)
				elem.keypair = keypair
				elem.endpoint = endpoints[i]
				elem.counter = 0 // 计数器暂时留空 (解密时再处理)

				// group by peer
				// [分拣逻辑] 把属于同一个 Peer 的包，归拢到一个 Container 里
				// 这样可以减少 Channel 的锁竞争次数 (Batch Dispatch)
				elemsForPeer, ok := elemsByPeer[peer]
				if !ok {
					elemsForPeer = device.GetInboundElementsContainer()
					elemsForPeer.Lock()
					elemsByPeer[peer] = elemsForPeer
				}
				elemsForPeer.elems = append(elemsForPeer.elems, elem)

				// [关键指针重置] 因为 buffer 所有权已经交给 elem 了，
				// 这里必须置 nil，防止 Go Runtime 或下面的逻辑重复回收它。
				bufsArrs[i] = device.GetMessageBuffer() // 顺便为下一轮循环申请个新盘子
				bufs[i] = bufsArrs[i][:]
				continue

			// otherwise it is a fixed size & handshake related packet
			// === 辅助路径: 处理握手包 (Type 1, 2, 3) ===
			case MessageInitiationType:
				if len(packet) != MessageInitiationSize {
					continue
				}

			case MessageResponseType:
				if len(packet) != MessageResponseSize {
					continue
				}

			case MessageCookieReplyType:
				if len(packet) != MessageCookieReplySize {
					continue
				}

			default:
				device.log.Verbosef("Received message with unknown type")
				continue
			}

			// handoff to handshake goroutine
			// [VIP通道] 握手包不进解密队列，直接扔给握手协程
			// device.queue.handshake <- ...

			select {
			case device.queue.handshake.c <- QueueHandshakeElement{
				msgType:  msgType,
				buffer:   bufsArrs[i],
				packet:   packet,
				endpoint: endpoints[i],
			}:
				// [关键指针重置] 同上，Buffer 给别人了，这里要置空补新
				bufsArrs[i] = device.GetMessageBuffer()
				bufs[i] = bufsArrs[i][:]
			default:
				// [丢弃逻辑] 如果握手队列满了，直接丢弃该包，
				// 防止阻塞主收包流程 (RoutineReceiveIncoming 必须保持高速运转)
			}
		}

		// [Step 3: Dispatch] 批量派发
		for peer, elemsContainer := range elemsByPeer {
			if peer.isRunning.Load() {
				// [双重通知]
				// 1. peer.queue.inbound: 通知 Peer 专属队列 (用于保序/流控)
				// 2. device.queue.decryption: 扔进公用解密池 (Worker 开始并行解密)
				peer.queue.inbound.c <- elemsContainer
				device.queue.decryption.c <- elemsContainer
			} else {
				// 如果 Peer 已停止，即便收到了包也无法处理
				// [资源清理] 必须手动把 Container 里挂的所有 buffer 和 struct 都还回去
				for _, elem := range elemsContainer.elems {
					device.PutMessageBuffer(elem.buffer)
					device.PutInboundElement(elem)
				}
				device.PutInboundElementsContainer(elemsContainer)
			}
			delete(elemsByPeer, peer) // 清空分拣车，准备下一轮
		}
	}
}

func (device *Device) RoutineDecryption(id int) {
	var nonce [chacha20poly1305.NonceSize]byte

	defer device.log.Verbosef("Routine: decryption worker %d - stopped", id)
	device.log.Verbosef("Routine: decryption worker %d - started", id)

	for elemsContainer := range device.queue.decryption.c {
		for _, elem := range elemsContainer.elems {
			// split message into fields
			counter := elem.packet[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.packet[MessageTransportOffsetContent:]

			// decrypt and release to consumer
			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			// copy counter to nonce
			binary.LittleEndian.PutUint64(nonce[0x4:0xc], elem.counter)
			elem.packet, err = elem.keypair.receive.Open( //aw-解密
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.packet = nil
			}
		}
		elemsContainer.Unlock()
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake(id int) {
	defer func() {
		device.log.Verbosef("Routine: handshake worker %d - stopped", id)
		device.queue.encryption.wg.Done()
	}()
	device.log.Verbosef("Routine: handshake worker %d - started", id)

	for elem := range device.queue.handshake.c {

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			err := reply.unmarshal(elem.packet)
			if err != nil {
				device.log.Verbosef("Failed to decode cookie reply")
				goto skip
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				goto skip
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Load() {
				device.log.Verbosef("Receiving cookie response from %s", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					device.log.Verbosef("Could not decrypt invalid cookie response")
				}
			}

			goto skip

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				device.log.Verbosef("Received packet with invalid mac1")
				goto skip
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					goto skip
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					goto skip
				}
			}

		default:
			device.log.Errorf("Invalid packet ended up in the handshake queue")
			goto skip
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode initiation message")
				goto skip
			}

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid initiation message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake initiation", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			err := msg.unmarshal(elem.packet)
			if err != nil {
				device.log.Errorf("Failed to decode response message")
				goto skip
			}

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				device.log.Verbosef("Received invalid response message from %s", elem.endpoint.DstToString())
				goto skip
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			device.log.Verbosef("%v - Received handshake response", peer)
			peer.rxBytes.Add(uint64(len(elem.packet)))

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				device.log.Errorf("%v - Failed to derive keypair: %v", peer, err)
				goto skip
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
		}
	skip:
		device.PutMessageBuffer(elem.buffer)
	}
}

// 数据进入你系统的最后一道防线
// （是 “并行世界的收束点”。它像是一条流水线的最后一道工序，
// 把大家七手八脚做好的零件，按编号一个个装箱。）
func (peer *Peer) RoutineSequentialReceiver(maxBatchSize int) {
	device := peer.device
	defer func() {
		device.log.Verbosef("%v - Routine: sequential receiver - stopped", peer)
		peer.stopping.Done()
	}()
	device.log.Verbosef("%v - Routine: sequential receiver - started", peer)

	bufs := make([][]byte, 0, maxBatchSize)

	for elemsContainer := range peer.queue.inbound.c {
		if elemsContainer == nil {
			return
		}
		elemsContainer.Lock()
		validTailPacket := -1
		dataPacketReceived := false
		rxBytesLen := uint64(0)
		for i, elem := range elemsContainer.elems {
			if elem.packet == nil {
				// decryption failed
				continue
			}

			if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
				continue
			}

			validTailPacket = i
			if peer.ReceivedWithKeypair(elem.keypair) {
				peer.SetEndpointFromPacket(elem.endpoint)
				peer.timersHandshakeComplete()
				peer.SendStagedPackets()
			}
			rxBytesLen += uint64(len(elem.packet) + MinMessageSize)

			if len(elem.packet) == 0 {
				// 获取完整公钥
				peer.handshake.mutex.RLock()
				fullKey := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
				peer.handshake.mutex.RUnlock()
				// 获取 VPN IP (AllowedIPs)
				var vpnIPs []string
				device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
					vpnIPs = append(vpnIPs, prefix.String())
					return true
				})
				vpnIPStr := "unknown"
				if len(vpnIPs) > 0 {
					vpnIPStr = strings.Join(vpnIPs, ", ")
				}
				// 获取 UDP IP (Endpoint)
				peer.endpoint.Lock()
				udpIPStr := "unknown"
				if peer.endpoint.val != nil {
					udpIPStr = peer.endpoint.val.DstToString()
				}
				peer.endpoint.Unlock()
				// 获取备注名
				remark := peer.Remark
				if remark == "" {
					remark = "未命名"
				}
				device.log.Verbosef("[keepalive] 备注: %s, 公钥: %s, VPN: %s, UDP: %s, 时间: %s", remark, fullKey, vpnIPStr, udpIPStr, time.Now().Format("2006-01-02 15:04:05.000"))
				continue
			}
			dataPacketReceived = true

			// aw-开荒: 打印解密后的明文 IP 包
			device.log.Verbosef("[2. 进站] 内层IP包 (解密后，发给内核) 大小: %d, IP版本: %d, 前20字节: %x", len(elem.packet), elem.packet[0]>>4, elem.packet[:min(20, len(elem.packet))])

			switch elem.packet[0] >> 4 {
			case 4:
				if len(elem.packet) < ipv4.HeaderLen {
					continue
				}
				field := elem.packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
				length := binary.BigEndian.Uint16(field)
				if int(length) > len(elem.packet) || int(length) < ipv4.HeaderLen {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
				if device.allowedips.Lookup(src) != peer {
					// 如果 Peer A 寄过来一个声称源 IP 是 192.168.1.1 的包，
					// 但你的配置里 Peer A 只允许 10.166.0.0/24，
					// WireGuard 会在这行（483/500行）毫不犹豫地把包销毁：
					device.log.Verbosef("IPv4 packet with disallowed source address from %v", peer)
					continue
				}

			case 6:
				if len(elem.packet) < ipv6.HeaderLen {
					continue
				}
				field := elem.packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
				length := binary.BigEndian.Uint16(field)
				length += ipv6.HeaderLen
				if int(length) > len(elem.packet) {
					continue
				}
				elem.packet = elem.packet[:length]
				src := elem.packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
				if device.allowedips.Lookup(src) != peer {
					device.log.Verbosef("IPv6 packet with disallowed source address from %v", peer)
					continue
				}

			default:
				device.log.Verbosef("Packet with invalid IP version from %v", peer)
				continue
			}

			bufs = append(bufs, elem.buffer[:MessageTransportOffsetContent+len(elem.packet)])
		}

		peer.rxBytes.Add(rxBytesLen)
		if validTailPacket >= 0 {
			peer.SetEndpointFromPacket(elemsContainer.elems[validTailPacket].endpoint)
			peer.keepKeyFreshReceiving()                 // 检查密钥是否快过期，是否需要重新握手
			peer.timersAnyAuthenticatedPacketTraversal() // 记录：包穿过了防火墙
			peer.timersAnyAuthenticatedPacketReceived()
		}
		if dataPacketReceived {
			peer.timersDataReceived() // 只有包含实际数据的包（非空包）才触发这个计时(免去了频繁的 keepalive)
		}
		// aw-收包出口：Go -> 内核 (写往 TUN)
		if len(bufs) > 0 {
			_, err := device.tun.device.Write(bufs, MessageTransportOffsetContent)
			if err != nil && !device.isClosed() {
				device.log.Errorf("Failed to write packets to TUN device: %v", err)
			}
		}
		for _, elem := range elemsContainer.elems {
			device.PutMessageBuffer(elem.buffer)
			device.PutInboundElement(elem)
		}
		bufs = bufs[:0]
		device.PutInboundElementsContainer(elemsContainer)
	}
}
