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
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
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
	mux.HandleFunc("/api/peer/add", ui.handlePeerAdd)
	mux.HandleFunc("/api/peer/remove", ui.handlePeerRemove)
	mux.HandleFunc("/api/config", ui.handleConfig)
	mux.HandleFunc("/api/hello", ui.handleHello)
	mux.HandleFunc("/docs", ui.handleDocs)
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

	// 启动 UDP Echo Server (用于测试 UDP 连通性)
	go func() {
		addr, err := net.ResolveUDPAddr("udp", ":8090")
		if err != nil {
			ui.device.log.Errorf("UDP Echo define addr error: %v", err)
			return
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			ui.device.log.Errorf("UDP Echo listen error: %v", err)
			return
		}
		defer conn.Close()
		ui.device.log.Verbosef("UDP Echo Server listening on :8090")

		buf := make([]byte, 1024)
		for {
			_, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			// 回复固定的 Hello 消息
			conn.WriteToUDP([]byte("hello,from udp!"), remoteAddr)
		}
	}()

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

	// 按备注名排序
	sort.Slice(peers, func(i, j int) bool {
		return peers[i].Remark < peers[j].Remark
	})

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
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #f1f5f9;
            min-height: 100vh;
            padding: 40px 20px;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
        }
        h1 {
            font-size: 24px;
            color: #38bdf8;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .device-info {
	            background: #1e293b;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 30px;
            border: 1px solid #334155;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        .info-card h3 {
            font-size: 12px;
            text-transform: uppercase;
            color: #94a3b8;
            margin-bottom: 8px;
            letter-spacing: 0.05em;
        }
        .info-card p {
            font-family: 'JetBrains Mono', monospace;
            font-size: 16px;
            color: #f8fafc;
            word-break: break-all;
        }
        .peer-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        .peer-row {
            background: #1e293b;
            border-radius: 12px;
            padding: 16px 24px;
            border: 1px solid #334155;
            display: grid;
            grid-template-columns: 1.5fr 2fr 1.5fr 1fr 1.5fr;
            align-items: center;
            gap: 20px;
            transition: all 0.2s ease;
        }
        .peer-row:hover {
            border-color: #38bdf8;
            background: #24324d;
            transform: scale(1.01);
        }
        .peer-main {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }
        .status-dot.online { background: #22c55e; box-shadow: 0 0 10px #22c55e; }
        .status-dot.offline { background: #94a3b8; }
        .peer-name {
            font-weight: 600;
            font-size: 16px;
            color: #f8fafc;
        }
        .peer-ips {
            font-size: 13px;
            color: #94a3b8;
            font-family: monospace;
        }
        .label-small {
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            margin-bottom: 4px;
        }
        .value-small {
            font-size: 13px;
            color: #cbd5e1;
            font-family: monospace;
        }
        .traffic-group {
            display: flex;
            gap: 16px;
        }
        .traffic-box {
            display: flex;
            flex-direction: column;
        }
        .traffic-val {
            font-size: 13px;
            color: #38bdf8;
            font-weight: 500;
        }
        .handshake-time {
            font-size: 12px;
            color: #94a3b8;
        }
        .refresh-tag {
            text-align: center;
            margin-top: 30px;
            color: #475569;
            font-size: 12px;
        }
        @media (max-width: 900px) {
            .peer-row {
                grid-template-columns: 1fr 1fr;
                gap: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span>🛡️</span> WireGuard Controller</h1>
        </header>

        <div class="device-info">
            <div class="info-card">
                <h3>服务端公钥</h3>
                <p id="dev-pubkey">-</p>
            </div>
            <div class="info-card">
                <h3>UDP端口</h3>
                <p id="dev-port">-</p>
            </div>
            <div class="info-card">
                <h3>已连接设备</h3>
                <p id="dev-count">-</p>
            </div>
        </div>

        <div class="peer-list" id="peer-list">
            <!-- Peers will be loaded here -->
        </div>
        
        <div class="refresh-tag">每 3 秒自动同步数据</div>
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
                    document.getElementById('dev-pubkey').innerText = data.public_key;
                    document.getElementById('dev-port').innerText = data.listen_port;
                    document.getElementById('dev-count').innerText = data.peer_count;

                    const listHtml = data.peers.map(peer => ` + "`" + `
                        <div class="peer-row">
                            <div class="peer-main">
                                <div class="status-dot ${peer.is_running ? 'online' : 'offline'}"></div>
                                <div>
                                    <div class="peer-name">${peer.remark}</div>
                                    <div class="peer-ips">${peer.allowed_ips ? peer.allowed_ips.join(', ') : '-'}</div>
                                </div>
                            </div>
                            <div>
                                <div class="label-small">对等体公钥</div>
                                <div class="value-small">${peer.public_key.substring(0, 24)}...</div>
                            </div>
                            <div>
                                <div class="label-small">UDP 端点</div>
                                <div class="value-small">${peer.endpoint}</div>
                            </div>
                            <div class="traffic-group">
                                <div class="traffic-box">
                                    <div class="label-small">发送</div>
                                    <div class="traffic-val">↑ ${formatBytes(peer.tx_bytes)}</div>
                                </div>
                                <div class="traffic-box">
                                    <div class="label-small">接收</div>
                                    <div class="traffic-val">↓ ${formatBytes(peer.rx_bytes)}</div>
                                </div>
                            </div>
                            <div>
                                <div class="label-small">最后活跃</div>
                                <div class="handshake-time">${peer.last_handshake}</div>
                            </div>
                        </div>
                    ` + "`" + `).join('');
                    document.getElementById('peer-list').innerHTML = listHtml;
                })
                .catch(err => console.error('Sync Error:', err));
        }

        updateStatus();
        setInterval(updateStatus, 3000);
    </script>
</body>
</html>`

	fmt.Fprint(w, html)
}

// handleDocs 返回 API 文档页面
func (ui *WebUI) handleDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>API 文档 - WireGuard Controller</title>
    <style>
        body { font-family: 'Inter', sans-serif; background: #0f172a; color: #f1f5f9; padding: 40px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 10px; }
        .endpoint { background: #1e293b; border-radius: 8px; padding: 20px; margin-top: 20px; border: 1px solid #334155; }
        .method { background: #0ea5e9; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 14px; margin-right: 10px; }
        .path { font-family: monospace; font-size: 18px; color: #f8fafc; }
        .desc { margin-top: 10px; color: #94a3b8; }
        pre { background: #000; padding: 15px; border-radius: 6px; overflow-x: auto; color: #10b981; font-size: 13px; margin-top: 10px; }
        .back { display: inline-block; margin-bottom: 20px; color: #38bdf8; text-decoration: none; font-size: 14px; }
        .back:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" class="back">← 返回控制面板</a>
        <h1>📖 接口文档 (API Documentation)</h1>
        
        <div class="endpoint">
            <div><span class="method">GET</span><span class="path">/api/status</span></div>
            <p class="desc">获取设备的完整状态信息，包括核心公钥、端口以及所有对等体的详细统计。</p>
            <pre>{
  "public_key": "...",
  "listen_port": 38200,
  "peer_count": 5,
  "peers": [
    {
      "remark": "Debian",
      "public_key": "...",
      "endpoint": "10.0.0.3:51820",
      "allowed_ips": ["10.166.0.3/32"],
      "tx_bytes": 1024,
      "rx_bytes": 2048,
      "last_handshake": "2025-12-30 10:00:00"
    }
  ]
}</pre>
        </div>

        <div class="endpoint">
            <div><span class="method">GET</span><span class="path">/api/peers</span></div>
            <p class="desc">仅返回对等体（Peers）列表数组，适用于轻量级的数据更新。</p>
            <pre>[
  { "remark": "iPhone", "public_key": "...", ... },
  { "remark": "wg-study", "public_key": "...", ... }
]</pre>
        </div>

        <div class="endpoint">
            <div><span class="method">GET</span><span class="path">/docs</span></div>
            <p class="desc">返回当前你正在阅读的这份文档页面。</p>
        </div>
    </div>
</body>
</html>`
	fmt.Fprint(w, html)
}

// ========== 配置类 API ==========

// PeerAddRequest 添加 Peer 请求体
type PeerAddRequest struct {
	PublicKey  string   `json:"public_key"`
	AllowedIPs []string `json:"allowed_ips"`
	Endpoint   string   `json:"endpoint,omitempty"`
	Keepalive  int      `json:"persistent_keepalive,omitempty"`
}

// handlePeerAdd 添加 Peer
// POST /api/peer/add
func (ui *WebUI) handlePeerAdd(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed, use POST"})
		return
	}

	var req PeerAddRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	// 构建 UAPI 配置字符串
	var config strings.Builder
	config.WriteString("public_key=" + req.PublicKey + "\n")
	if req.Endpoint != "" {
		config.WriteString("endpoint=" + req.Endpoint + "\n")
	}
	if req.Keepalive > 0 {
		config.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", req.Keepalive))
	}
	for _, ip := range req.AllowedIPs {
		config.WriteString("allowed_ip=" + ip + "\n")
	}

	// 调用 IpcSet
	if err := ui.device.IpcSet(config.String()); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Peer added successfully"})
}

// PeerRemoveRequest 删除 Peer 请求体
type PeerRemoveRequest struct {
	PublicKey string `json:"public_key"`
}

// handlePeerRemove 删除 Peer
// POST /api/peer/remove
func (ui *WebUI) handlePeerRemove(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed, use POST"})
		return
	}

	var req PeerRemoveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	// 构建 UAPI 配置字符串
	config := fmt.Sprintf("public_key=%s\nremove=true\n", req.PublicKey)

	// 调用 IpcSet
	if err := ui.device.IpcSet(config); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Peer removed successfully"})
}

// ConfigRequest 批量配置请求体
type ConfigRequest struct {
	Config string `json:"config"` // 原始 UAPI 格式的配置字符串
}

// handleConfig 批量配置（相当于 IpcSet）
// POST /api/config
func (ui *WebUI) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed, use POST"})
		return
	}

	var req ConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	// 调用 IpcSet
	if err := ui.device.IpcSet(req.Config); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Config applied successfully"})
}

// handleHello 简单的 Hello World 接口
// GET /api/hello
func (ui *WebUI) handleHello(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	response := map[string]interface{}{
		"code": 200,
		"data": map[string]string{
			"content": "hello,wireguard!",
		},
	}
	json.NewEncoder(w).Encode(response)
}
