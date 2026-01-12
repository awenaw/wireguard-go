package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.zx2c4.com/wireguard/device"
)

// 本示例用于可视化 device.AllowedIPs 的内部 Radix Trie 结构。
// 它通过不安全的指针转换访问 device 包内的私有字段，
// 直观地展示了路由表的动态修改过程。
//
// 注意：本代码依赖于 device.trieEntry 的内部内存布局。
// 如果上游结构发生变化，本演示代码可能需要更新。

func main() {
	// 创建一个路由表
	var table device.AllowedIPs

	// 在没有 device 包内部权限的情况下，我们创建几个空的 Peer 占位符
	peer1 := &device.Peer{}
	peer2 := &device.Peer{}
	peer3 := &device.Peer{}

	fmt.Println("=== 1. 插入 192.168.1.0/24 (Peer A) ===")
	// 期望：树中只有一个根节点 192.168.1.0/24
	table.Insert(netip.MustParsePrefix("192.168.1.0/24"), peer1)
	printAllowedIPsTree(&table)

	fmt.Println("\n=== 2. 插入 192.168.1.128/25 (Peer B - A 的子网) ===")
	// 预期结果：192.168.1.0/24 保持为根节点，新增一个右子节点指向 192.168.1.128/25
	// 192.168.1.128 的第 25 位是 1 (二进制 ...10000000)，因此作为右子节点挂载。
	table.Insert(netip.MustParsePrefix("192.168.1.128/25"), peer2)
	printAllowedIPsTree(&table)

	fmt.Println("\n=== 3. 插入 192.168.2.0/24 (Peer C - 兄弟网段) ===")
	// 预期结果：树结构发生分裂。
	// 192.168.1.0 (A) 和 192.168.2.0 (C) 的前 22 位相同 (192.168.0...)。
	// 它们在第 23 位出现分歧：A 为 0，C 为 1。
	// 将创建一个新的 "粘合节点" (Glue Node) 192.168.0.0/22 作为父节点，A 为左子节点，C 为右子节点。
	table.Insert(netip.MustParsePrefix("192.168.2.0/24"), peer3)
	printAllowedIPsTree(&table)

	fmt.Println("\n=== 4. 插入 10.0.0.1/32 (不相关 IP) ===")
	// 预期结果：由于首位即不同，分裂点将上移至根层级 (0.0.0.0/0)。
	table.Insert(netip.MustParsePrefix("10.0.0.1/32"), peer3)
	printAllowedIPsTree(&table)
}

// -------------------------------------------------------------
// 辅助函数：通过不安全指针反射访问私有 Trie 结构
// -------------------------------------------------------------

func printAllowedIPsTree(table *device.AllowedIPs) {
	// 指针运算：device.AllowedIPs 的第一个字段通常是 IPv4 (*trieEntry)。
	// 直接将 *device.AllowedIPs 转换为 **mockTrieEntry。
	ptr := unsafe.Pointer(table)
	rootIPv4Ptr := (**mockTrieEntry)(ptr)
	root := *rootIPv4Ptr

	if root == nil {
		fmt.Println("(empty tree)")
		return
	}

	printMockTree(root, "", true)
}

// mockTrieEntry 映射了私有结构 device.trieEntry 的内存布局。
// 必须与原始结构定义保持严格一致。
type parentIndirection struct {
	parentBit     uintptr // **trieEntry
	parentBitType uint8
}

type mockTrieEntry struct {
	peer        uintptr // *Peer
	child       [2]*mockTrieEntry
	parent      parentIndirection
	cidr        uint8
	bitAtByte   uint8
	bitAtShift  uint8
	bits        []byte
	perPeerElem uintptr // *list.Element
}

func (n *mockTrieEntry) String() string {
	if n == nil {
		return "<nil>"
	}
	var ipStr string
	if len(n.bits) == 4 {
		ipStr = fmt.Sprintf("%d.%d.%d.%d", n.bits[0], n.bits[1], n.bits[2], n.bits[3])
	} else {
		// 为了简洁，此处仅显示 IPv4 长度
		ipStr = fmt.Sprintf("len=%d", len(n.bits))
	}

	state := "glue"
	if n.peer != 0 {
		state = "PEER"
	}

	// 打印关键信息：IP/CIDR 和节点类型
	return fmt.Sprintf("[%s/%d] (%s)", ipStr, n.cidr, state)
}

func printMockTree(node *mockTrieEntry, prefix string, isLeft bool) {
	if node == nil {
		return
	}
	fmt.Printf("%s", prefix)
	if isLeft {
		fmt.Printf("├── 0: ") // child[0]
	} else {
		fmt.Printf("└── 1: ") // child[1]
	}
	fmt.Printf("%s\n", node.String())

	newPrefix := prefix
	if isLeft {
		newPrefix += "│   "
	} else {
		newPrefix += "    "
	}

	if node.child[0] != nil || node.child[1] != nil {
		printMockTree(node.child[0], newPrefix, true)
		printMockTree(node.child[1], newPrefix, false)
	}
}

// 工具函数
func commonBits(ip1, ip2 []byte) uint8 {
	a := binary.BigEndian.Uint32(ip1)
	b := binary.BigEndian.Uint32(ip2)
	x := a ^ b
	if x == 0 {
		return 32
	}
	return uint8(32 - bitLen(x))
}

func bitLen(x uint32) int {
	n := 0
	for x > 0 {
		x >>= 1
		n++
	}
	return n
}
