/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"encoding/base64"
	"fmt"
	"net/netip"
)

// ========= Device 暴露接口 =========

func (d *Device) GetLogger() *Logger {
	return d.log
}

func (d *Device) GetPublicKey() string {
	d.staticIdentity.RLock()
	defer d.staticIdentity.RUnlock()
	return base64.StdEncoding.EncodeToString(d.staticIdentity.publicKey[:])
}

func GeneratePrivateKey() string {
	sk, _ := newPrivateKey()
	return base64.StdEncoding.EncodeToString(sk[:])
}

func GetPublicKeyFromPrivateKey(privKeyBase64 string) (string, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
	if err != nil || len(keyBytes) != NoisePrivateKeySize {
		return "", fmt.Errorf("invalid private key")
	}
	var sk NoisePrivateKey
	copy(sk[:], keyBytes)
	pk := sk.publicKey()
	return base64.StdEncoding.EncodeToString(pk[:]), nil
}

func (d *Device) GetListenPort() uint16 {
	d.net.RLock()
	defer d.net.RUnlock()
	return d.net.port
}

func (d *Device) ForEachPeer(fn func(*Peer)) {
	d.peers.RLock()
	defer d.peers.RUnlock()
	for _, peer := range d.peers.keyMap {
		fn(peer)
	}
}

func (d *Device) GetAllowedIPs() *AllowedIPs {
	return &d.allowedips
}

// ========= Peer 暴露接口 =========

func (p *Peer) GetPublicKey() string {
	p.handshake.mutex.RLock()
	defer p.handshake.mutex.RUnlock()
	return base64.StdEncoding.EncodeToString(p.handshake.remoteStatic[:])
}

func (p *Peer) GetAllowedIPList() []string {
	var ips []string
	p.device.allowedips.EntriesForPeer(p, func(prefix netip.Prefix) bool {
		ips = append(ips, prefix.String())
		return true
	})
	return ips
}

func (p *Peer) GetEndpoint() string {
	p.endpoint.Lock()
	defer p.endpoint.Unlock()
	if p.endpoint.val == nil {
		return "unknown"
	}
	return p.endpoint.val.DstToString()
}

func (p *Peer) GetLastHandshakeNano() int64 {
	return p.lastHandshakeNano.Load()
}

func (p *Peer) GetTrafficStats() (tx, rx uint64) {
	return p.txBytes.Load(), p.rxBytes.Load()
}

func (p *Peer) GetIsRunning() bool {
	return p.isRunning.Load()
}

func (p *Peer) GetKeepaliveInterval() uint32 {
	return p.persistentKeepaliveInterval.Load()
}
