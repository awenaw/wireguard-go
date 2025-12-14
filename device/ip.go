/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Package device 包含 WireGuard 协议的核心实现。
//
// ip.go 文件定义了 IPv4 和 IPv6 数据包头部的关键字段偏移量。
//
// WireGuard 为了追求极致的转发性能，在数据面（Data Plane）处理时，
// 并不使用标准库对整个 IP 包进行完整的结构体解析（Unmarshal），
// 而是直接通过硬编码的字节偏移量（Offset）来快速访问必须的字段。
//
// 这种设计使得 WireGuard 在进行以下操作时能够实现"零拷贝"和"零内存分配"：
// 1. Cryptokey Routing：快速读取源 IP 地址，用于查表校验 Peer 权限。
// 2. 长度校验：快速读取 IP 包总长度，用于分包和边界检查。
//
// 本文件中定义的常量严格遵循 RFC 791 (IPv4) 和 RFC 8200 (IPv6) 标准。

package device

import (
	"net"
)

// IPv4 头部结构 (最小 20 字节):
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         | <--- IPv4offsetTotalLength (2)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          | <--- IPv4offsetSrc (12)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        | <--- IPv4offsetDst (16)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
const (
	IPv4offsetTotalLength = 2                           // IPv4 包总长度字段偏移量 (2字节)
	IPv4offsetSrc         = 12                          // IPv4 源地址字段偏移量 (4字节)
	IPv4offsetDst         = IPv4offsetSrc + net.IPv4len // IPv4 目的地址字段偏移量 (16)
)

// IPv6 头部结构 (固定 40 字节):
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |           Flow Label                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Payload Length        |  Next Header  |   Hop Limit   | <--- IPv6offsetPayloadLength (4)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                         Source Address                        + <--- IPv6offsetSrc (8)
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                                                               |
// +                      Destination Address                      + <--- IPv6offsetDst (24)
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
const (
	IPv6offsetPayloadLength = 4                           // IPv6 载荷长度字段偏移量 (2字节)
	IPv6offsetSrc           = 8                           // IPv6 源地址字段偏移量 (16字节)
	IPv6offsetDst           = IPv6offsetSrc + net.IPv6len // IPv6 目的地址字段偏移量 (24)
)
