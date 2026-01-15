/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"container/list"
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"unsafe"
)

// parentIndirection 封装了指向父节点指针的指针，以及该子节点是父节点的左子(0)还是右子(1)。
// 主要用于在删除节点时，能够方便地更新父节点的子节点指针。
type parentIndirection struct {
	parentBit     **trieEntry
	parentBitType uint8 // 0 for left child, 1 for right child
}

// trieEntry 是 Radix Trie 中的一个节点。
// 它通过路径压缩(Path Compression)技术，只在必须分叉(Critical Bit)的地方建立节点，极大地减少了树的高度。
type trieEntry struct {
	peer   *Peer             // 如果当前节点对应一个有效的网段(如 /24)，这里存储归属的 Peer；如果是中间路径节点，则为 nil。
	child  [2]*trieEntry     // 左右子节点指针。0: 代表该位为0的分支; 1: 代表该位为1的分支。
	parent parentIndirection // 父节点指针的封装，用于向上回溯 (主要用于删除操作)。
	cidr   uint8             // 有效的 CIDR 掩码长度 (例如 /24 中的 24)。仅当 peer != nil 时有意义。

	// 为了优化内存布局和计算速度，将 Critical Bit 的位置拆分为 "字节索引" 和 "位偏移"。
	// 例如：第 27 位 -> bitAtByte=3 (第3个字节), bitAtShift=4 (字节内的第4位)
	bitAtByte  uint8 // 关键分叉位所在的字节索引 (从0开始)
	bitAtShift uint8 // 关键分叉位在字节内的偏移量 (0-7, 高位为7)

	bits        []byte        // 路径压缩核心：存储从父节点到当前节点之间必须匹配的公共前缀位。
	perPeerElem *list.Element // 链表元素反向指针，用于快速从 Peer 对象反查到 Trie 节点 (O(1)删除)。
}

// commonBits 计算两个 IP 地址之间有多少个共同的比特位 (最长公共前缀长度)。
// 这是 Radix Trie 插入逻辑中的"尺子"，用于决定在哪里分裂节点。
func commonBits(ip1, ip2 []byte) uint8 {
	size := len(ip1)
	if size == net.IPv4len {
		a := binary.BigEndian.Uint32(ip1)
		b := binary.BigEndian.Uint32(ip2)
		x := a ^ b
		return uint8(bits.LeadingZeros32(x))
	} else if size == net.IPv6len {
		a := binary.BigEndian.Uint64(ip1)
		b := binary.BigEndian.Uint64(ip2)
		x := a ^ b
		if x != 0 {
			return uint8(bits.LeadingZeros64(x))
		}
		a = binary.BigEndian.Uint64(ip1[8:])
		b = binary.BigEndian.Uint64(ip2[8:])
		x = a ^ b
		return 64 + uint8(bits.LeadingZeros64(x))
	} else {
		panic("Wrong size bit string")
	}
}

func (node *trieEntry) addToPeerEntries() {
	node.perPeerElem = node.peer.trieEntries.PushBack(node)
}

func (node *trieEntry) removeFromPeerEntries() {
	if node.perPeerElem != nil {
		node.peer.trieEntries.Remove(node.perPeerElem)
		node.perPeerElem = nil
	}
}

func (node *trieEntry) choose(ip []byte) byte {
	return (ip[node.bitAtByte] >> node.bitAtShift) & 1
}

func (node *trieEntry) maskSelf() {
	mask := net.CIDRMask(int(node.cidr), len(node.bits)*8)
	for i := 0; i < len(mask); i++ {
		node.bits[i] &= mask[i]
	}
}

func (node *trieEntry) zeroizePointers() {
	// Make the garbage collector's life slightly easier
	node.peer = nil
	node.child[0] = nil
	node.child[1] = nil
	node.parent.parentBit = nil
}

// nodePlacement 在 Trie 树中查找给定 IP 和 CIDR 应该处于哪个位置
// 返回值:
//   - parent: 找到的最深层的匹配节点 (作为新节点的潜在父节点)
//   - exact: 是否精确匹配了现有的节点 (即 IP 和 CIDR 完全一致)
func (node *trieEntry) nodePlacement(ip []byte, cidr uint8) (parent *trieEntry, exact bool) {
	// 循环下钻：只要当前节点不为空，且当前节点的 CIDR 小于我们要找的 CIDR (说明我们还要往更深处走)，
	// 并且当前节点的前缀覆盖了我们的 IP，就继续往下找。
	for node != nil && node.cidr <= cidr && commonBits(node.bits, ip) >= node.cidr {
		parent = node
		// 如果 CIDR 也完全一样，那就是精确匹配！
		if parent.cidr == cidr {
			exact = true
			return
		}
		// 根据 IP 地址的位，决定往左走还是往右走
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return
}

// insert 将一个新的网段插入到 Trie 树中。如果需要，它会分裂现有的节点。
// 这是 Radix Trie 算法中最复杂的部分。
func (trie parentIndirection) insert(ip []byte, cidr uint8, peer *Peer) {
	// 情况 0: 树是空的
	if *trie.parentBit == nil {
		node := &trieEntry{
			peer:       peer,
			parent:     trie,
			bits:       ip,
			cidr:       cidr,
			bitAtByte:  cidr / 8,
			bitAtShift: 7 - (cidr % 8),
		}
		node.maskSelf() // 清除 CIDR 掩码位之后的脏数据
		node.addToPeerEntries()
		*trie.parentBit = node
		return
	}

	// 先尝试在现有的树里找位置
	node, exact := (*trie.parentBit).nodePlacement(ip, cidr)

	// 情况 1: 精确匹配 (Exact Match)
	// 找到了一个完全一样的网段，直接更新它的 Peer 指针即可。
	if exact {
		node.removeFromPeerEntries()
		node.peer = peer
		node.addToPeerEntries()
		return
	}

	// 准备创建一个新节点
	newNode := &trieEntry{
		peer:       peer,
		bits:       ip,
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	newNode.maskSelf()
	newNode.addToPeerEntries()

	// 确定我们将要从哪里开始插入 (down 节点)
	var down *trieEntry
	if node == nil {
		down = *trie.parentBit // 从根开始
	} else {
		// 决定是往左还是往右挂在新找到的 parent 下面
		bit := node.choose(ip)
		down = node.child[bit]

		// 情况 2: 作为叶子节点插入 (Simple Append)
		// 如果该方向没有子节点，直接挂上去完事。
		if down == nil {
			newNode.parent = parentIndirection{&node.child[bit], bit}
			node.child[bit] = newNode
			return
		}
	}

	// 此时 down 是我们潜在的竞争对手。我们需要看看我们要和它在哪里分道扬镳。
	// 计算新节点和现有 down 节点的最长公共前缀长度。
	common := commonBits(down.bits, ip)

	// 如果公共前缀比我们的 CIDR 短，说明我们的插入点应该在 down 节点的上方。
	if common < cidr {
		cidr = common
	}
	parent := node

	// 情况 3: 插入点恰好是新节点的位置 (newNode is parent of down)
	// 这种情况下，新节点成为了 down 节点的父节点。
	if newNode.cidr == cidr {
		bit := newNode.choose(down.bits)
		down.parent = parentIndirection{&newNode.child[bit], bit}
		newNode.child[bit] = down

		if parent == nil {
			newNode.parent = trie
			*trie.parentBit = newNode
		} else {
			bit := parent.choose(newNode.bits)
			newNode.parent = parentIndirection{&parent.child[bit], bit}
			parent.child[bit] = newNode
		}
		return
	}

	// 情况 4: 需要分裂 (Split)
	// 公共前缀比 down 短，也比 newNode 短。
	// 这意味着我们需要创建一个中间节点 (Glue Node) 来连接 newNode 和 down。
	node = &trieEntry{
		bits:       append([]byte{}, newNode.bits...),
		cidr:       cidr, // Split 点的 CIDR
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	node.maskSelf()

	// 挂载 down 节点
	bit := node.choose(down.bits)
	down.parent = parentIndirection{&node.child[bit], bit}
	node.child[bit] = down

	// 挂载 newNode 节点
	bit = node.choose(newNode.bits)
	newNode.parent = parentIndirection{&node.child[bit], bit}
	node.child[bit] = newNode

	// 将新的中间节点挂载到树上
	if parent == nil {
		node.parent = trie
		*trie.parentBit = node
	} else {
		bit := parent.choose(node.bits)
		node.parent = parentIndirection{&parent.child[bit], bit}
		parent.child[bit] = node
	}
}

// lookup 在 Trie 树中查找负责给定 IP 的 Peer。
// 这是数据平面(Data Plane)最频繁调用的函数，必须极致高效。
// 返回值: 找到的 Peer 指针，如果没有匹配则返回 nil。
func (node *trieEntry) lookup(ip []byte) *Peer {
	var found *Peer
	size := uint8(len(ip))
	// 核心循环：沿着树向下跳跃
	// 条件:
	// 1. node != nil (还没到底)
	// 2. commonBits(...) >= node.cidr (路径上的公共前缀必须匹配，否则路走错了)
	for node != nil && commonBits(node.bits, ip) >= node.cidr {
		// 如果当前节点是一个有效网段 (peer != nil)，记录它。
		// 注意：我们不会break，而是继续往下找，因为可能存在更长的前缀匹配 (Longest Prefix Match)。
		// 例如：虽然匹配了 10.0.0.0/16，但底下可能还有一个更精确的 10.0.0.5/32。
		if node.peer != nil {
			found = node.peer
		}

		// 如果已经匹配到了叶子节点的最深处 (例如 /32)，就不需要再往下走了。
		if node.bitAtByte == size {
			break
		}

		// 决定下一步跳左还是跳右
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return found
}

type AllowedIPs struct {
	IPv4  *trieEntry
	IPv6  *trieEntry
	mutex sync.RWMutex
}

// EntriesForPeer 遍历属于指定 Peer 的所有网段。
// cb 回调函数对每个网段执行操作。
func (table *AllowedIPs) EntriesForPeer(peer *Peer, cb func(prefix netip.Prefix) bool) {
	table.mutex.RLock()
	defer table.mutex.RUnlock()

	// 直接遍历 peer 维护的反向索引链表，避免全树扫描，效率极高。
	for elem := peer.trieEntries.Front(); elem != nil; elem = elem.Next() {
		node := elem.Value.(*trieEntry)
		a, _ := netip.AddrFromSlice(node.bits)
		if !cb(netip.PrefixFrom(a, int(node.cidr))) {
			return
		}
	}
}

// remove 从树中删除一个节点，并尝试压缩树结构 (合并空闲路径)。
func (node *trieEntry) remove() {
	node.removeFromPeerEntries()
	node.peer = nil

	// 情况 1: 该节点还有两个孩子
	// 即使删除了 peer，这个节点还得留着作为路标，不能删。
	if node.child[0] != nil && node.child[1] != nil {
		return
	}

	// 接下来逻辑是：如果节点删空了，就要把它从树里摘掉，并把它的孤儿孩子过继给爷爷。
	bit := 0
	if node.child[0] == nil {
		bit = 1
	}
	child := node.child[bit]

	// 更新孙子节点的祖父指针
	if child != nil {
		child.parent = node.parent
	}

	// 让爷爷直接指向孙子 (跳过当前节点)
	*node.parent.parentBit = child

	// 如果爷爷节点也变空了(没孩子了)或者不需要存在了，递归向上尝试压缩。
	if node.child[0] != nil || node.child[1] != nil || node.parent.parentBitType > 1 {
		node.zeroizePointers()
		return
	}

	// 获取父节点对象 (通过 unsafe 指针偏移计算，因为 parentIndirection 不直接持有 parent 对象的指针)
	// 这段 unsafe 代码是为了省内存，避免在每个节点里多存一个 *trieEntry 指针。
	parent := (*trieEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(node.parent.parentBit)) - unsafe.Offsetof(node.child) - unsafe.Sizeof(node.child[0])*uintptr(node.parent.parentBitType)))

	if parent.peer != nil {
		node.zeroizePointers()
		return
	}

	// 父节点也是空的，继续合并
	child = parent.child[node.parent.parentBitType^1]
	if child != nil {
		child.parent = parent.parent
	}
	*parent.parent.parentBit = child
	node.zeroizePointers()
	parent.zeroizePointers()
}

// Remove 从路由表中删除指定的网段
func (table *AllowedIPs) Remove(prefix netip.Prefix, peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()
	var node *trieEntry
	var exact bool

	if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		node, exact = table.IPv6.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		node, exact = table.IPv4.nodePlacement(ip[:], uint8(prefix.Bits()))
	} else {
		panic(errors.New("removing unknown address type"))
	}

	// 只有找到精确匹配且归属 Peer 正确的节点才删除
	if !exact || node == nil || peer != node.peer {
		return
	}
	node.remove()
}

// RemoveByPeer 删除指定 Peer 拥有的所有网段 (例如 Peer 断开连接时)
func (table *AllowedIPs) RemoveByPeer(peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	var next *list.Element
	// 遍历 peer 自己的链表，逐个删除。
	for elem := peer.trieEntries.Front(); elem != nil; elem = next {
		next = elem.Next()
		elem.Value.(*trieEntry).remove()
	}
}

// Insert 向路由表中添加一个新的网段
func (table *AllowedIPs) Insert(prefix netip.Prefix, peer *Peer) {
	table.mutex.Lock()
	defer table.mutex.Unlock()

	if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		parentIndirection{&table.IPv6, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		parentIndirection{&table.IPv4, 2}.insert(ip[:], uint8(prefix.Bits()), peer)
	} else {
		panic(errors.New("inserting unknown address type"))
	}
}

// Lookup 对外暴露的查找接口
func (table *AllowedIPs) Lookup(ip []byte) *Peer {
	table.mutex.RLock()
	defer table.mutex.RUnlock()
	switch len(ip) {
	case net.IPv6len:
		return table.IPv6.lookup(ip)
	case net.IPv4len:
		return table.IPv4.lookup(ip)
	default:
		panic(errors.New("looking up unknown address type"))
	}
}
