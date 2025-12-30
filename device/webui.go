/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// webui.go - WireGuard Web UI 服务器
// 提供 HTTP API 和 Web 页面，用于查看 WireGuard 设备状态

package device

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// PeerInfo 对等体信息结构，用于 JSON 序列化
type PeerInfo struct {
	Remark            string   `json:"remark"`             // 备注名
	PublicKey         string   `json:"public_key"`         // 公钥 (Base64)
	Endpoint          string   `json:"endpoint"`           // UDP 端点
	AllowedIPs        []string `json:"allowed_ips"`        // VPN IP 列表
	LastHandshake     string   `json:"last_handshake"`     // 最后握手时间
	TxBytes           uint64   `json:"tx_bytes"`           // 发送字节数
	RxBytes           uint64   `json:"rx_bytes"`           // 接收字节数
	IsRunning         bool     `json:"is_running"`         // 是否运行中
	KeepaliveInterval uint32   `json:"keepalive_interval"` // 保活间隔
}

// DeviceInfo 设备信息结构，用于 JSON 序列化
type DeviceInfo struct {
	PublicKey  string     `json:"public_key"`  // 设备公钥
	ListenPort uint16     `json:"listen_port"` // 监听端口
	Peers      []PeerInfo `json:"peers"`       // 对等体列表
	PeerCount  int        `json:"peer_count"`  // 对等体数量
}

// WebUI HTTP 服务器
type WebUI struct {
	device *Device
	server *http.Server
}

// NewWebUI 创建 Web UI 服务器
func NewWebUI(device *Device, addr string) *WebUI {
	ui := &WebUI{device: device}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", ui.handleStatus)
	mux.HandleFunc("/api/peers", ui.handlePeers)
	mux.HandleFunc("/", ui.handleIndex)

	ui.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return ui
}

// Start 启动 Web UI 服务器
func (ui *WebUI) Start() error {
	ui.device.log.Verbosef("WebUI server starting on %s", ui.server.Addr)
	go func() {
		if err := ui.server.ListenAndServe(); err != http.ErrServerClosed {
			ui.device.log.Errorf("WebUI server error: %v", err)
		}
	}()
	return nil
}

// Stop 停止 Web UI 服务器
func (ui *WebUI) Stop() error {
	return ui.server.Close()
}

// handleStatus 返回设备状态 JSON
func (ui *WebUI) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	info := ui.getDeviceInfo()
	json.NewEncoder(w).Encode(info)
}

// handlePeers 返回对等体列表 JSON
func (ui *WebUI) handlePeers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	info := ui.getDeviceInfo()
	json.NewEncoder(w).Encode(info.Peers)
}

// getDeviceInfo 获取设备完整信息
func (ui *WebUI) getDeviceInfo() DeviceInfo {
	device := ui.device

	// 获取设备公钥
	device.staticIdentity.RLock()
	publicKey := base64.StdEncoding.EncodeToString(device.staticIdentity.publicKey[:])
	device.staticIdentity.RUnlock()

	// 获取监听端口
	device.net.RLock()
	listenPort := device.net.port
	device.net.RUnlock()

	// 获取所有对等体信息
	var peers []PeerInfo
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peerInfo := ui.getPeerInfo(peer)
		peers = append(peers, peerInfo)
	}
	device.peers.RUnlock()

	return DeviceInfo{
		PublicKey:  publicKey,
		ListenPort: listenPort,
		Peers:      peers,
		PeerCount:  len(peers),
	}
}

// getPeerInfo 获取单个对等体信息
func (ui *WebUI) getPeerInfo(peer *Peer) PeerInfo {
	// 获取公钥
	peer.handshake.mutex.RLock()
	publicKey := base64.StdEncoding.EncodeToString(peer.handshake.remoteStatic[:])
	peer.handshake.mutex.RUnlock()

	// 获取 AllowedIPs
	var allowedIPs []string
	ui.device.allowedips.EntriesForPeer(peer, func(prefix netip.Prefix) bool {
		allowedIPs = append(allowedIPs, prefix.String())
		return true
	})

	// 获取 Endpoint
	peer.endpoint.Lock()
	endpoint := "unknown"
	if peer.endpoint.val != nil {
		endpoint = peer.endpoint.val.DstToString()
	}
	peer.endpoint.Unlock()

	// 获取最后握手时间
	lastHandshakeNano := peer.lastHandshakeNano.Load()
	lastHandshake := "从未"
	if lastHandshakeNano > 0 {
		t := time.Unix(0, lastHandshakeNano)
		lastHandshake = t.Format("2006-01-02 15:04:05")
	}

	// 获取备注
	remark := peer.Remark
	if remark == "" {
		remark = "未命名"
	}

	return PeerInfo{
		Remark:            remark,
		PublicKey:         publicKey,
		Endpoint:          endpoint,
		AllowedIPs:        allowedIPs,
		LastHandshake:     lastHandshake,
		TxBytes:           peer.txBytes.Load(),
		RxBytes:           peer.rxBytes.Load(),
		IsRunning:         peer.isRunning.Load(),
		KeepaliveInterval: peer.persistentKeepaliveInterval.Load(),
	}
}

// handleIndex 返回 Web 页面
func (ui *WebUI) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WireGuard 状态监控</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            color: #00d4ff;
            text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
        }
        .device-info {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .device-info h2 { color: #00d4ff; margin-bottom: 15px; }
        .info-row { display: flex; margin-bottom: 10px; }
        .info-label { color: #888; width: 120px; }
        .info-value { color: #fff; font-family: monospace; }
        .peers-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
        }
        .peer-card {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .peer-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.2);
        }
        .peer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 10px;
        }
        .peer-name { font-size: 1.2em; font-weight: bold; color: #00d4ff; }
        .peer-status {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.8em;
        }
        .status-online { background: rgba(0, 255, 100, 0.2); color: #00ff64; }
        .status-offline { background: rgba(255, 100, 100, 0.2); color: #ff6464; }
        .peer-detail { margin-bottom: 8px; font-size: 0.9em; }
        .peer-detail .label { color: #888; }
        .peer-detail .value { color: #fff; font-family: monospace; word-break: break-all; }
        .traffic {
            display: flex;
            justify-content: space-around;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }
        .traffic-item { text-align: center; }
        .traffic-label { color: #888; font-size: 0.8em; }
        .traffic-value { color: #00d4ff; font-size: 1.1em; font-weight: bold; }
        .refresh-info {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 WireGuard 状态监控</h1>
        <div class="device-info" id="device-info">
            <h2>设备信息</h2>
            <div id="device-content">加载中...</div>
        </div>
        <div class="peers-grid" id="peers-grid">
            <!-- Peers will be loaded here -->
        </div>
        <div class="refresh-info">每 3 秒自动刷新</div>
    </div>

    <script>
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function updateStatus() {
            fetch('/api/status')
                .then(res => res.json())
                .then(data => {
                    // Update device info
                    document.getElementById('device-content').innerHTML = ` + "`" + `
                        <div class="info-row">
                            <span class="info-label">公钥:</span>
                            <span class="info-value">${data.public_key}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">监听端口:</span>
                            <span class="info-value">${data.listen_port}</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">对等体数量:</span>
                            <span class="info-value">${data.peer_count}</span>
                        </div>
                    ` + "`" + `;

                    // Update peers
                    const peersHtml = data.peers.map(peer => ` + "`" + `
                        <div class="peer-card">
                            <div class="peer-header">
                                <span class="peer-name">${peer.remark}</span>
                                <span class="peer-status ${peer.is_running ? 'status-online' : 'status-offline'}">
                                    ${peer.is_running ? '在线' : '离线'}
                                </span>
                            </div>
                            <div class="peer-detail">
                                <span class="label">公钥: </span>
                                <span class="value">${peer.public_key.substring(0, 20)}...</span>
                            </div>
                            <div class="peer-detail">
                                <span class="label">VPN IP: </span>
                                <span class="value">${peer.allowed_ips ? peer.allowed_ips.join(', ') : 'N/A'}</span>
                            </div>
                            <div class="peer-detail">
                                <span class="label">UDP 端点: </span>
                                <span class="value">${peer.endpoint}</span>
                            </div>
                            <div class="peer-detail">
                                <span class="label">最后握手: </span>
                                <span class="value">${peer.last_handshake}</span>
                            </div>
                            <div class="traffic">
                                <div class="traffic-item">
                                    <div class="traffic-label">↑ 发送</div>
                                    <div class="traffic-value">${formatBytes(peer.tx_bytes)}</div>
                                </div>
                                <div class="traffic-item">
                                    <div class="traffic-label">↓ 接收</div>
                                    <div class="traffic-value">${formatBytes(peer.rx_bytes)}</div>
                                </div>
                            </div>
                        </div>
                    ` + "`" + `).join('');
                    document.getElementById('peers-grid').innerHTML = peersHtml;
                })
                .catch(err => console.error('Error:', err));
        }

        updateStatus();
        setInterval(updateStatus, 3000);
    </script>
</body>
</html>`

	fmt.Fprint(w, html)
}
