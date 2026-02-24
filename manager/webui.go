/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// webui.go - WireGuard Web UI 服务器
// 提供 HTTP API 和 Web 页面，用于查看 WireGuard 设备状态

package manager

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const sessionCookieName = "wg_ui_session"

// PeerInfo 对等体信息结构，用于 JSON 序列化
type PeerInfo struct {
	Remark            string   `json:"remark"`             // 备注名
	PublicKey         string   `json:"public_key"`         // 公钥 (Base64)
	Endpoint          string   `json:"endpoint"`           // UDP 端点
	AllowedIPs        []string `json:"allowed_ips"`        // VPN IP 列表
	LastHandshake     string   `json:"last_handshake"`     // 最后握手时间
	TxBytes           uint64   `json:"tx_bytes"`           // 发送字节数
	RxBytes           uint64   `json:"rx_bytes"`           // 接收字节数
	TotalBytes        uint64   `json:"total_bytes"`        // 累计总流量
	IsRunning         bool     `json:"is_running"`         // 是否运行中
	IsOnline          bool     `json:"is_online"`          // 是否在线 (基于握手时间)
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
	device       *device.Device
	config       *Config
	server       *http.Server
	passwordHash [32]byte
	sessionToken string
}

// NewWebUI 创建 Web UI 服务器
func NewWebUI(dev *device.Device, conf *Config, addr string) *WebUI {
	password := os.Getenv("WEBUI_PASSWORD")
	if password == "" {
		password = "admin" // 生产环境请务必设置环境变量
	}

	ui := &WebUI{
		device:       dev,
		config:       conf,
		passwordHash: sha256.Sum256([]byte(password)),
		sessionToken: fmt.Sprintf("%x", sha256.Sum256([]byte(time.Now().String()+password))),
	}

	mux := http.NewServeMux()

	// 公共接口
	// 公共接口
	mux.HandleFunc("/login", ui.handleLogin)
	mux.HandleFunc("/join/", ui.handleJoin)

	// 受保护接口 (包装中间件)
	mux.HandleFunc("/api/status", ui.authMiddleware(ui.handleStatus))
	mux.HandleFunc("/api/peers", ui.authMiddleware(ui.handlePeers))
	mux.HandleFunc("/api/peer/add", ui.authMiddleware(ui.handlePeerAdd))
	mux.HandleFunc("/api/peer/remove", ui.authMiddleware(ui.handlePeerRemove))
	mux.HandleFunc("/api/config", ui.authMiddleware(ui.handleConfig))
	mux.HandleFunc("/api/invites/generate", ui.authMiddleware(ui.handleInviteGenerate))
	mux.HandleFunc("/api/invites/list", ui.authMiddleware(ui.handleInviteList))
	mux.HandleFunc("/api/invites/remove", ui.authMiddleware(ui.handleInviteRemove))
	mux.HandleFunc("/api/system/config", ui.authMiddleware(ui.handleSystemConfig))
	mux.HandleFunc("/api/enroll", ui.authMiddleware(ui.handleEnroll))
	mux.HandleFunc("/api/register", ui.handleRegister) // 公开接口，通过 Token 鉴权
	mux.HandleFunc("/api/hello", ui.authMiddleware(ui.handleHello))
	mux.HandleFunc("/docs", ui.authMiddleware(ui.handleDocs))
	mux.HandleFunc("/", ui.authMiddleware(ui.handleIndex))

	ui.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	return ui
}

// authMiddleware 认证中间件
func (ui *WebUI) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie.Value != ui.sessionToken {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// Start 启动 Web UI 服务器
func (ui *WebUI) Start() error {
	ui.device.GetLogger().Verbosef("WebUI server starting on %s", ui.server.Addr)

	// 启动 UDP Echo Server (用于测试 UDP 连通性)
	go func() {
		addr, err := net.ResolveUDPAddr("udp", ":8090")
		if err != nil {
			ui.device.GetLogger().Errorf("UDP Echo define addr error: %v", err)
			return
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			ui.device.GetLogger().Errorf("UDP Echo listen error: %v", err)
			return
		}
		defer conn.Close()
		ui.device.GetLogger().Verbosef("UDP Echo Server listening on :8090")

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
			ui.device.GetLogger().Errorf("WebUI server error: %v", err)
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
	dev := ui.device

	// 获取设备公钥
	publicKey := dev.GetPublicKey()

	// 获取监听端口
	listenPort := dev.GetListenPort()

	// 获取所有对等体信息
	var peers []PeerInfo
	dev.ForEachPeer(func(p *device.Peer) {
		peerInfo := ui.getPeerInfo(p)
		peers = append(peers, peerInfo)
	})

	// 动态排序：优先按在线状态(降序)，再按备注名(升序)
	sort.Slice(peers, func(i, j int) bool {
		if peers[i].IsOnline != peers[j].IsOnline {
			return peers[i].IsOnline // true (在线) 排在前面
		}
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
func (ui *WebUI) getPeerInfo(peer *device.Peer) PeerInfo {
	// 获取公钥
	publicKey := peer.GetPublicKey()

	// 获取 AllowedIPs
	allowedIPs := peer.GetAllowedIPList()

	// 获取 Endpoint
	endpoint := peer.GetEndpoint()

	// 获取最后握手时间
	lastHandshakeNano := peer.GetLastHandshakeNano()
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

	tx, rx := peer.GetTrafficStats()

	// 计算是否在线：最后握手在 135 秒内 (WireGuard 默认握手超时约 2 分钟)
	isOnline := false
	if lastHandshakeNano > 0 {
		since := time.Since(time.Unix(0, lastHandshakeNano))
		if since < time.Second*135 {
			isOnline = true
		}
	}

	return PeerInfo{
		Remark:            remark,
		PublicKey:         publicKey,
		Endpoint:          endpoint,
		AllowedIPs:        allowedIPs,
		LastHandshake:     lastHandshake,
		TxBytes:           tx,
		RxBytes:           rx,
		TotalBytes:        tx + rx,
		IsRunning:         peer.GetIsRunning(),
		IsOnline:          isOnline,
		KeepaliveInterval: peer.GetKeepaliveInterval(),
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
    <script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
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
            padding-bottom: 20px;
            border-bottom: 1px solid #1e293b;
        }
        header h1 {
            font-size: 24px;
            font-weight: 800;
            letter-spacing: -0.5px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        header h1 span { color: #38bdf8; }
        .nav-tabs {
            display: flex;
            gap: 10px;
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
        .tab-btn {
            background: #1e293b;
            border: 1px solid #334155;
            color: #94a3b8;
            padding: 10px 20px;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            margin-right: 8px;
        }
        .tab-btn.active {
            background: #38bdf8;
            color: #0f172a;
            border-color: #38bdf8;
        }
        .tab-btn:hover:not(.active) {
            background: #2d3e5a;
            color: #f8fafc;
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
        .status-dot.offline { background: transparent; border: 1px solid #475569; }
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
        /* QR Modal Styles */
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.8);
            backdrop-filter: blur(8px);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .qr-modal {
            background: #1e293b;
            padding: 30px;
            border-radius: 24px;
            border: 1px solid #334155;
            text-align: center;
            max-width: 350px;
            width: 90%;
        }
        .qr-modal h3 { margin-bottom: 20px; color: #f8fafc; }
        .qr-modal #qr-container { 
            background: white; 
            padding: 15px; 
            border-radius: 12px; 
            display: inline-block;
            margin-bottom: 20px;
        }
        .qr-modal #qr-container img { display: block; }
        .qr-modal .btn-close {
            background: #334155;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 10px;
            cursor: pointer;
            width: 100%;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1><span>🛡️</span> WireGuard Controller</h1>
            <div class="nav-tabs">
                <button class="tab-btn active" id="tab-status" onclick="switchTab('status')">状态概览</button>
                <button class="tab-btn" id="tab-peers" onclick="switchTab('peers')">设备列表</button>
                <button class="tab-btn" id="tab-invites" onclick="switchTab('invites')">邀请管理</button>
                <button class="tab-btn" id="tab-enroll" onclick="switchTab('enroll')" style="background:rgba(16,185,129,0.1); color:#10b981; border-color:rgba(16,185,129,0.2)">客户端入驻</button>
            </div>
        </header>

        <section id="sec-status">
            <div class="device-info">
                <div class="info-card">
                    <h3>服务端公钥</h3>
                    <p id="dev-pubkey">-</p>
                </div>
                <div class="info-card">
                    <h3>UDP 端口</h3>
                    <p id="dev-port">-</p>
                </div>
                <div class="info-card">
                    <h3>已连接设备</h3>
                    <p id="dev-count">-</p>
                </div>
            </div>
            <div style="background: rgba(255,255,255,0.02); padding: 40px; border-radius: 20px; border: 1px solid var(--border); text-align: center; color: #64748b;">
                <p>母舰运行状态正常。所有配置已持久化至 JSON。</p>
            </div>
        </section>

        <section id="sec-peers" style="display:none">
            <div class="peer-list" id="peer-list">
                <!-- Peers go here -->
            </div>
        </section>

        <section id="sec-invites" style="display:none">
            <div style="background: rgba(16,185,129,0.05); padding: 24px; border-radius: 16px; border: 1px solid rgba(16,185,129,0.1); margin-bottom: 24px;">
                <h3 style="margin-bottom: 16px; font-size: 16px; color:#10b981;">🌐 全局分发设置</h3>
                <div style="display: grid; grid-template-columns: 2fr 1fr 2fr 1fr 1fr auto; gap: 12px; align-items: flex-end;">
                    <div>
                        <label style="color:#94a3b8; font-size:12px; margin-bottom:8px; display:block;">WireGuard Host</label>
                        <input type="text" id="sys-pub-host" placeholder="1.2.3.4" style="width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white;">
                    </div>
                    <div>
                        <label style="color:#94a3b8; font-size:12px; margin-bottom:8px; display:block;">Port</label>
                        <input type="number" id="sys-pub-port" placeholder="51820" style="width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white;">
                    </div>
                    <div>
                        <label style="color:#94a3b8; font-size:12px; margin-bottom:8px; display:block;">Web Portal Host</label>
                        <input type="text" id="sys-web-host" placeholder="vpn.com" style="width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white;">
                    </div>
                    <div>
                        <label style="color:#94a3b8; font-size:12px; margin-bottom:8px; display:block;">Port</label>
                        <input type="number" id="sys-web-port" placeholder="8080" style="width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white;">
                    </div>
                    <div>
                        <label style="color:#94a3b8; font-size:12px; margin-bottom:8px; display:block;">Keepalive</label>
                        <input type="number" id="sys-keepalive" placeholder="25" style="width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white;">
                    </div>
                    <button class="btn" style="margin-top:0; width: auto; padding: 12px 24px; background:#10b981;" onclick="saveSystemConfig()">保存</button>
                </div>
                <p style="color:#64748b; font-size:12px; margin-top:10px;">地址与端口已分离。Keepalive 为新注册客户端的默认保活间隔(秒)，推荐 25。</p>
            </div>

            <div style="background: rgba(255,255,255,0.05); padding: 24px; border-radius: 16px; border: 1px solid rgba(255,255,255,0.1); margin-bottom: 24px;">
                <h3 style="margin-bottom: 16px; font-size: 16px;">🔑 生成新邀请</h3>
                <div style="display: flex; gap: 12px; align-items: flex-end;">
                    <div style="flex: 2;">
                        <input type="text" id="invite-remark" placeholder="备注 (如：老王的手机)" style="width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white;">
                    </div>
                    <div style="width: 100px;">
                        <input type="number" id="invite-duration" value="24" style="width: 100%; padding: 12px; border-radius: 10px; border: 1px solid #334155; background: #0f172a; color: white;">
                    </div>
                    <button class="btn" style="margin-top:0; width: auto; padding: 12px 24px;" onclick="generateInvite()">生成邀请码</button>
                </div>
            </div>
            <div class="peer-list" id="invite-list">
                <!-- Invites here -->
            </div>
        </section>

        <section id="sec-enroll" style="display:none">
            <div style="max-width: 500px; margin: 30px auto; background: rgba(255,255,255,0.05); padding: 40px; border-radius: 24px; border: 1px solid rgba(255,255,255,0.1); text-align: center;">
                <h2 style="font-size: 24px; margin-bottom: 20px;">🚀 客户端入驻</h2>
                <div style="text-align: left; background: rgba(0,0,0,0.2); padding: 15px; border-radius: 12px; margin-bottom: 20px; border: 1px solid rgba(255,255,255,0.05);">
                    <p style="color:#38bdf8; font-size:13px; font-weight:600; margin-bottom:8px;">💡 操作指南</p>
                    <p style="color:#94a3b8; font-size:12px; line-height:1.6;">直接粘贴入网链接即可自动解析，或手动输入邀请码和服务器地址。</p>
                </div>

                <div style="text-align:left; margin-bottom:20px; padding:15px; background:rgba(56,189,248,0.05); border-radius:12px; border:1px solid rgba(56,189,248,0.1);">
                    <label style="color:#38bdf8; font-size:13px; font-weight:600;">快捷解析链接</label>
                    <div style="display:flex; gap:10px; margin-top:8px;">
                        <input type="text" id="enroll-link-input" placeholder="粘贴 http://.../join/... 链接" style="flex:1; padding:12px; border-radius:10px; border:1px solid #334155; background: #0f172a; color: white;">
                        <button class="tab-btn" style="margin:0; background:#38bdf8; color:#0f172a; border:none; padding:0 15px;" onclick="parseEnrollLink()">解析</button>
                    </div>
                </div>

                <div style="height:1px; background:rgba(255,255,255,0.05); margin-bottom:20px;"></div>

                <div style="text-align:left; margin-bottom:15px;">
                    <label style="color:#94a3b8; font-size:13px; font-weight:600;">邀请码</label>
                    <input type="text" id="enroll-token" placeholder="示例: ABCD-1234-XYZ" style="width: 100%; padding: 14px; border-radius: 12px; border: 1px solid #334155; background: #0f172a; color: white; margin-top:8px;">
                </div>
                
                <div style="text-align:left; margin-bottom:25px;">
                    <label style="color:#94a3b8; font-size:13px; font-weight:600;">服务端地址</label>
                    <input type="text" id="enroll-server" placeholder="例如: 1.2.3.4:8080 或 http://vpn.example.com:8080" style="width: 100%; padding: 14px; border-radius: 12px; border: 1px solid #334155; background: #0f172a; color: white; margin-top:8px;">
                </div>

                <div style="text-align:left; margin-bottom:25px;">
                    <label style="color:#94a3b8; font-size:13px; font-weight:600;">服务器 Endpoint</label>
                    <input type="text" id="enroll-endpoint" placeholder="可选，例如: 1.2.3.4:51820（留空则由服务端下发）" style="width: 100%; padding: 14px; border-radius: 12px; border: 1px solid #334155; background: #0f172a; color: white; margin-top:8px;">
                </div>
                
                <button class="btn" style="margin-top:0;" onclick="goToEnroll()">立即自动入驻</button>
            </div>
        </section>
        
        <div class="refresh-tag">每 3 秒自动同步数据</div>
    </div>

    <div class="modal-overlay" id="qr-modal-overlay">
        <div class="qr-modal">
            <h3 id="qr-modal-title">邀请入网二维码</h3>
            <div id="qr-container"></div>
            <p style="color:#94a3b8; font-size:12px; margin-bottom:20px;">请使用手机 WireGuard 客户端扫码，或浏览器访问链接</p>
            <button class="btn-close" onclick="closeQRModal()">关闭</button>
        </div>
    </div>

    <script>
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        async function initSystemSettings() {
            try {
                const res = await fetch('/api/system/config');
                const config = await res.json();
                
                // 仅更新 input，不干扰此时可能正在输入的 activeElement
                const fields = {
                    'sys-pub-host': config.public_host || '',
                    'sys-pub-port': config.public_port || '',
                    'sys-web-host': config.web_host || '',
                    'sys-web-port': config.web_port || '',
                    'sys-keepalive': config.default_keepalive || 25
                };
                Object.keys(fields).forEach(id => {
                    const el = document.getElementById(id);
                    if (el && document.activeElement !== el) {
                        el.value = fields[id];
                    }
                });

                // 挂载全局配置供渲染邀请链接使用
                window._sysConfig = config;
            } catch (e) {
                console.error('Failed to load system config', e);
            }
        }

        function updateStatus() {
            // 1. 同步设备状态与对等体流量
            fetch('/api/status')
                .then(res => res.json())
                .then(data => {
                    document.getElementById('dev-pubkey').innerText = data.public_key;
                    document.getElementById('dev-port').innerText = data.listen_port;
                    document.getElementById('dev-count').innerText = data.peer_count;

                    const listHtml = data.peers.map(peer => ` + "`" + `
                        <div class="peer-row" style="grid-template-columns: 1.5fr 2fr 1.5fr 1fr 1fr 1.5fr;">
                            <div class="peer-main">
                                <div class="status-dot ${peer.is_online ? 'online' : 'offline'}"></div>
                                <div>
                                    <div class="peer-name">${peer.remark || '未命名设备'}</div>
                                    <div class="peer-ips">${peer.allowed_ips ? peer.allowed_ips.join(', ') : '-'}</div>
                                </div>
                            </div>
                            <div>
                                <div class="label-small">对等体公钥</div>
                                <div class="value-small" title="${peer.public_key}">${peer.public_key.substring(0, 12)}...</div>
                                <div class="label-small" style="margin-top:8px;">实时 Endpoint</div>
                                <div class="value-small" style="color:#10b981;">${peer.endpoint || '未连接'}</div>
                            </div>
                            <div class="traffic-group">
                                <div class="traffic-box">
                                    <div class="label-small">发送</div>
                                    <div class="traffic-val">↑ ${formatBytes(peer.tx_bytes)}</div>
                                </div>
                                <div class="traffic-box">
                                    <div class="label-small">下载</div>
                                    <div class="traffic-val" style="color:#22c55e;">↓ ${formatBytes(peer.rx_bytes)}</div>
                                </div>
                                <div class="traffic-box">
                                    <div class="label-small">累计总计</div>
                                    <div class="traffic-val" style="color:#f8fafc; font-weight:700; border-top:1px solid rgba(255,255,255,0.1); margin-top:4px; padding-top:4px;">∑ ${formatBytes(peer.total_bytes)}</div>
                                </div>
                            </div>
                            <div>
                                <div class="label-small">Keepalive</div>
                                <div style="display:flex; align-items:center; gap:4px;">
                                    <input type="number" id="ka-${peer.public_key.substring(0,8)}" value="${peer.keepalive_interval}" min="0" max="65535" style="width:50px; padding:4px; border-radius:6px; border:1px solid #334155; background:#0f172a; color:white; font-size:12px; text-align:center;">
                                    <span style="color:#64748b; font-size:11px;">秒</span>
                                    <button class="tab-btn" style="padding:3px 8px; font-size:10px; margin:0; background:rgba(56,189,248,0.1); color:#38bdf8; border-color:rgba(56,189,248,0.2);" onclick="setKeepalive('${peer.public_key}', document.getElementById('ka-${peer.public_key.substring(0,8)}').value)">设</button>
                                </div>
                            </div>
                            <div>
                                <div class="label-small">最后活跃</div>
                                <div class="handshake-time">${peer.last_handshake}</div>
                            </div>
                            <div style="text-align:right">
                                <button class="tab-btn" style="background:#ef4444; color:white; border:none; padding:6px 12px; margin:0;" onclick="deletePeer('${peer.public_key}')">移除</button>
                            </div>
                        </div>
                    ` + "`" + `).join('');
                    document.getElementById('peer-list').innerHTML = listHtml;
                });

            // 2. 同步邀请码列表 (只更新列表，不碰配置输入框)
            fetch('/api/invites/list')
                .then(res => res.json())
                .then(invites => {
                    const config = window._sysConfig || {};
                    let webBase = window.location.origin;
                    if (config.web_host) {
                        webBase = (window.location.protocol === 'https:' ? 'https://' : 'http://') + config.web_host;
                        if (config.web_port && config.web_port !== 80 && config.web_port !== 443) {
                            webBase += ':' + config.web_port;
                        }
                    }

                    const listHtml = (invites || []).map(inv => ` + "`" + `
                        <div class="peer-row" style="grid-template-columns: 1.5fr 3.5fr 1fr 0.5fr;">
                            <div>
                                <div class="peer-name">${inv.remark}</div>
                                <div class="label-small">${new Date(inv.created_at).toLocaleDateString()} 创建</div>
                            </div>
                            <div>
                                <div class="label-small">一键入网链接</div>
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <div class="value-small" style="color:#38bdf8; cursor:pointer; font-size:12px; flex:1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; background: rgba(56,189,248,0.05); padding: 4px 8px; border-radius: 6px;" onclick="copyLink('${webBase}/join/${inv.token}')">${webBase}/join/${inv.token}</div>
                                    <button class="tab-btn" style="padding:4px 8px; font-size:11px; margin:0; background:rgba(56,189,248,0.1); color:#38bdf8; border-color:rgba(56,189,248,0.2);" onclick="copyLink('${webBase}/join/${inv.token}')">复制</button>
                                    <button class="tab-btn" style="padding:4px 8px; font-size:11px; margin:0; background:rgba(56,189,248,0.1); color:#38bdf8; border-color:rgba(56,189,248,0.2);" onclick="showInviteQR('${webBase}/join/${inv.token}', '${inv.remark}')">二维码</button>
                                </div>
                            </div>
                            <div>
                                <div class="label-small">有效至 (24小时内)</div>
                                <div class="handshake-time" style="color:#f8fafc;">${new Date(inv.expires_at).toLocaleString('zh-CN', {month:'numeric', day:'numeric', hour:'2-digit', minute:'2-digit', second:'2-digit'})}</div>
                            </div>
                            <div style="text-align:right">
                                <button class="tab-btn" style="background:#475569; color:white; border:none; padding:6px 12px; margin:0;" onclick="deleteInvite('${inv.token}')">撤回</button>
                            </div>
                        </div>
                    ` + "`" + `).join('');
                    document.getElementById('invite-list').innerHTML = listHtml || '<div style="text-align:center; color:#475569; padding:40px;">暂无有效邀请码</div>';
                });
        }

        function parseEnrollLink() {
            const link = document.getElementById('enroll-link-input').value.trim();
            if (!link) return;
            try {
                const url = new URL(link);
                // 1. 提取服务端地址 (Scheme + Host)
                const serverAddr = url.origin;
                document.getElementById('enroll-server').value = serverAddr;

                // 2. 提取 Token (Path 的最后一部分)
                const parts = url.pathname.split('/');
                const token = parts[parts.length - 1];
                if (token) {
                    document.getElementById('enroll-token').value = token;
                }

                // 3. 处理可选的 Endpoint 参数
                const endpoint = url.searchParams.get('endpoint');
                if (endpoint) {
                    document.getElementById('enroll-endpoint').value = endpoint;
                }

                document.getElementById('enroll-link-input').value = '';
            } catch (e) {
                alert('链接格式不正确，请确保是完整的 http/https 链接');
            }
        }

        async function goToEnroll() {
            const token = document.getElementById('enroll-token').value.trim();
            const server = document.getElementById('enroll-server').value.trim();
            const endpoint = document.getElementById('enroll-endpoint').value.trim();
            if(!token) return alert('请填入邀请码');
            if(!server) return alert('请填入服务端地址');

            try {
                const res = await fetch('/api/enroll', {
                    method: 'POST',
                    body: JSON.stringify({ token, server, endpoint })
                });
                const data = await res.json();
                if (data.error) throw new Error(data.error);

                alert('自动入驻成功\nIP: ' + data.config.address + '\nEndpoint: ' + data.config.endpoint);
                updateStatus();
            } catch (e) {
                alert('自动入驻失败: ' + e.message);
            }
        }

        function showInviteQR(url, remark) {
            const qr = qrcode(0, 'M');
            qr.addData(url);
            qr.make();
            document.getElementById('qr-container').innerHTML = qr.createImgTag(6);
            document.getElementById('qr-modal-title').innerText = remark + ' 的邀请二维码';
            document.getElementById('qr-modal-overlay').style.display = 'flex';
        }

        function closeQRModal() {
            document.getElementById('qr-modal-overlay').style.display = 'none';
        }

        function switchTab(tab) {
            ['status', 'peers', 'invites', 'enroll'].forEach(t => {
                const sec = document.getElementById('sec-' + t);
                const btn = document.getElementById('tab-' + t);
                if(sec) sec.style.display = (t === tab ? 'block' : 'none');
                if(btn) btn.classList.toggle('active', t === tab);
            });
            if(tab === 'invites') initSystemSettings();
        }


        async function deletePeer(pubkey) {
            if (!confirm('确定要移除此设备吗？其连接将被立即断开。')) return;
            const res = await fetch('/api/peer/remove', {
                method: 'POST',
                body: JSON.stringify({ public_key: pubkey })
            });
            if (res.ok) updateStatus();
        }

        async function deleteInvite(token) {
            const res = await fetch('/api/invites/remove', {
                method: 'POST',
                body: JSON.stringify({ token: token })
            });
            if (res.ok) updateStatus();
        }

        async function saveSystemConfig() {
            const pubHost = document.getElementById('sys-pub-host').value.trim();
            const pubPort = parseInt(document.getElementById('sys-pub-port').value);
            const webHost = document.getElementById('sys-web-host').value.trim();
            const webPort = parseInt(document.getElementById('sys-web-port').value);
            const keepalive = parseInt(document.getElementById('sys-keepalive').value);
            
            const res = await fetch('/api/system/config', {
                method: 'POST',
                body: JSON.stringify({ 
                    public_host: pubHost,
                    public_port: pubPort || 51820,
                    web_host: webHost,
                    web_port: webPort || 8080,
                    default_keepalive: keepalive || 25
                })
            });
            if (res.ok) {
                alert('设置已保存');
                initSystemSettings();
                updateStatus();
            }
        }

        async function generateInvite() {
            const remark = document.getElementById('invite-remark').value;
            const duration = parseInt(document.getElementById('invite-duration').value);
            if (!remark) return alert('请填写备注');

            const res = await fetch('/api/invites/generate', {
                method: 'POST',
                body: JSON.stringify({ remark, duration_hours: duration || 24 })
            });
            if (res.ok) {
                document.getElementById('invite-remark').value = '';
                updateStatus();
                alert('邀请码生成完成！');
            }
        }

        function copyLink(link) {
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(link).then(() => {
                    alert('链接已复制到剪贴板');
                }).catch(err => {
                    console.error('Clipboard API failed, using fallback:', err);
                    fallbackCopy(link);
                });
            } else {
                fallbackCopy(link);
            }
        }

        function fallbackCopy(text) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.left = "-9999px";
            textArea.style.top = "0";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
                alert('链接已复制到剪贴板');
            } catch (err) {
                alert('复制失败，请手动选择复制');
            }
            document.body.removeChild(textArea);
        }

        async function setKeepalive(pubkey, val) {
            const interval = parseInt(val) || 0;
            const hexKey = Array.from(atob(pubkey), c => c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
            const config = 'public_key=' + hexKey + '\npersistent_keepalive_interval=' + interval + '\n';
            try {
                const res = await fetch('/api/config', {
                    method: 'POST',
                    body: JSON.stringify({ config })
                });
                if (res.ok) updateStatus();
                else alert('设置失败');
            } catch(e) { alert('请求失败: ' + e.message); }
        }

        initSystemSettings();
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

	// 持久化改动 (Phase 2)
	ui.config.SyncFromDevice(ui.device)
	if err := SaveConfig(ui.config); err != nil {
		ui.device.GetLogger().Errorf("Failed to save config after adding peer: %v", err)
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

	// 持久化改动 (Phase 2)
	ui.config.SyncFromDevice(ui.device)
	if err := SaveConfig(ui.config); err != nil {
		ui.device.GetLogger().Errorf("Failed to save config after removing peer: %v", err)
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

// handleSystemConfig 处理系统配置的 GET/POST
func (ui *WebUI) handleSystemConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(ui.config.System)
		return
	}

	if r.Method == http.MethodPost {
		var newSys SystemConfig
		if err := json.NewDecoder(r.Body).Decode(&newSys); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		ui.config.System.PublicHost = newSys.PublicHost
		ui.config.System.PublicPort = newSys.PublicPort
		ui.config.System.WebHost = newSys.WebHost
		ui.config.System.WebPort = newSys.WebPort
		ui.config.System.DefaultKeepalive = newSys.DefaultKeepalive
		if err := SaveConfig(ui.config); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
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

// InviteGenerateRequest 生成邀请码请求
type InviteGenerateRequest struct {
	Remark   string `json:"remark"`
	Duration int    `json:"duration_hours"` // 有效期（小时）
}

// handleInviteGenerate 生成邀请码
// POST /api/invites/generate
func (ui *WebUI) handleInviteGenerate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed, use POST"})
		return
	}

	var req InviteGenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	// 彻底修正：确保 Duration 至少为 24 小时，且优先解析 JSON 字段
	if req.Duration <= 0 {
		req.Duration = 24
	}

	token, err := ui.config.GenerateInvite(req.Remark, time.Duration(req.Duration)*time.Hour)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// 立即保存
	if err := SaveConfig(ui.config); err != nil {
		ui.device.GetLogger().Errorf("Failed to save config after generating invite: %v", err)
	}

	json.NewEncoder(w).Encode(map[string]string{
		"token": token,
		"url":   fmt.Sprintf("http://%s/join/%s", r.Host, token),
	})
}

// handleInviteList 获取邀请码列表
// GET /api/invites/list
func (ui *WebUI) handleInviteList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	json.NewEncoder(w).Encode(ui.config.Invites)
}

// handleInviteRemove 撤回邀请码
// POST /api/invites/remove
func (ui *WebUI) handleInviteRemove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ui.config.RemoveInvite(req.Token)
	SaveConfig(ui.config)
	w.WriteHeader(http.StatusOK)
}

// RegisterRequest 注册请求
type RegisterRequest struct {
	Token     string `json:"token"`
	Server    string `json:"server,omitempty"`     // 可选，客户端模式用于指定远端注册服务地址
	PublicKey string `json:"public_key,omitempty"` // 可选，由客户端自生
	Endpoint  string `json:"endpoint,omitempty"`   // 可选，手动覆盖 Endpoint
}

// EnrollRequest 客户端自动入驻请求
type EnrollRequest struct {
	Token    string `json:"token"`
	Server   string `json:"server"`
	Endpoint string `json:"endpoint,omitempty"`
}

// RegisterResponse 注册成功返回的配置
type RegisterResponse struct {
	Status string `json:"status"`
	Config struct {
		PrivateKey string   `json:"private_key,omitempty"` // 如果代生了则返回
		Address    string   `json:"address"`               // 分配的内网 IP
		PublicKey  string   `json:"public_key"`            // 服务端公钥
		Endpoint   string   `json:"endpoint"`              // 服务端地址
		AllowedIPs []string `json:"allowed_ips"`           // 允许的网段
	} `json:"config"`
}

// handleEnroll 客户端自动入驻（受保护接口）
// POST /api/enroll
func (ui *WebUI) handleEnroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Use POST"})
		return
	}

	var req EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	resp, status, err := ui.remoteEnrollToServer(req.Server, req.Token, req.Endpoint)
	if err != nil {
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(resp)
}

func (ui *WebUI) remoteEnrollToServer(serverRaw, tokenRaw, endpointRaw string) (RegisterResponse, int, error) {
	var resp RegisterResponse

	token := strings.TrimSpace(tokenRaw)
	if token == "" {
		return resp, http.StatusBadRequest, fmt.Errorf("token is required")
	}

	serverBase, err := normalizeEnrollServer(serverRaw)
	if err != nil {
		return resp, http.StatusBadRequest, fmt.Errorf("invalid server address: %w", err)
	}

	joinURL := fmt.Sprintf("%s/join/%s", serverBase, url.PathEscape(token))
	if endpoint := strings.TrimSpace(endpointRaw); endpoint != "" {
		joinURL += "?endpoint=" + url.QueryEscape(endpoint)
	}

	if err := ui.config.RemoteEnroll(joinURL); err != nil {
		return resp, http.StatusBadGateway, fmt.Errorf("remote enroll failed: %w", err)
	}

	if err := ui.config.ApplyToDevice(ui.device); err != nil {
		return resp, http.StatusInternalServerError, fmt.Errorf("apply enrolled config failed: %w", err)
	}

	ifaceName, err := ui.device.GetInterfaceName()
	if err != nil {
		return resp, http.StatusInternalServerError, fmt.Errorf("get interface name failed: %w", err)
	}
	if err := ui.config.ConfigureInterface(ifaceName); err != nil {
		return resp, http.StatusInternalServerError, fmt.Errorf("configure interface failed: %w", err)
	}
	if err := ui.device.Up(); err != nil {
		return resp, http.StatusInternalServerError, fmt.Errorf("bring device up failed: %w", err)
	}

	if len(ui.config.Peers) == 0 {
		return resp, http.StatusInternalServerError, fmt.Errorf("remote enroll succeeded but peer data is empty")
	}

	resp = RegisterResponse{Status: "ok"}
	resp.Config.PrivateKey = ui.config.Identity.PrivateKey
	resp.Config.Address = ui.config.System.InternalSubnet
	resp.Config.PublicKey = ui.config.Peers[0].PublicKey
	resp.Config.Endpoint = ui.config.Peers[0].Endpoint
	resp.Config.AllowedIPs = ui.config.Peers[0].AllowedIPs
	return resp, http.StatusOK, nil
}

// handleRegister 处理客户端入网注册
// POST /api/register
func (ui *WebUI) handleRegister(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]string{"error": "Use POST"})
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request"})
		return
	}

	// 客户端入驻：由本机转发到用户指定的远端服务端执行真实注册
	if strings.TrimSpace(req.Server) != "" {
		resp, status, err := ui.remoteEnrollToServer(req.Server, req.Token, req.Endpoint)
		if err != nil {
			w.WriteHeader(status)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(resp)
		return
	}

	// 1. 校验 Token
	invite, ok := ui.config.ValidateInvite(req.Token)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid or expired invitation token"})
		return
	}

	// 2. 分配 IP
	assignedIP, err := ui.config.GetNextAvailableIP()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "IP Allocation failed: " + err.Error()})
		return
	}

	// 3. 密钥处理
	var clientPriv, clientPub string
	if req.PublicKey != "" {
		clientPub = req.PublicKey
	} else {
		// 服务端代生 (对小白极度友好)
		clientPriv = device.GeneratePrivateKey()
		clientPub, _ = device.GetPublicKeyFromPrivateKey(clientPriv)
	}

	// 4. 执行 IpcSet 注入内核
	uapi := fmt.Sprintf("public_key=%s\nallowed_ip=%s\n", b64ToHex(clientPub), assignedIP)
	// 注入默认的 PersistentKeepalive（防止 NAT 断连）
	keepalive := ui.config.System.DefaultKeepalive
	if keepalive <= 0 {
		keepalive = 25 // 安全默认值
	}
	uapi += fmt.Sprintf("persistent_keepalive_interval=%d\n", keepalive)
	if err := ui.device.IpcSet(uapi); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to inject into network: " + err.Error()})
		return
	}

	// 5. 设置备注
	ui.device.ForEachPeer(func(p *device.Peer) {
		if p.GetPublicKey() == clientPub {
			p.Remark = invite.Remark
		}
	})

	// 6. 持久化并销毁邀请码
	ui.config.RemoveInvite(req.Token)
	ui.config.SyncFromDevice(ui.device)
	SaveConfig(ui.config)

	// 7. 返回响应
	resp := RegisterResponse{Status: "ok"}
	resp.Config.PrivateKey = clientPriv
	resp.Config.Address = assignedIP
	resp.Config.PublicKey = ui.device.GetPublicKey()
	resp.Config.Endpoint = req.Endpoint
	if resp.Config.Endpoint == "" {
		if ui.config.System.PublicHost != "" {
			port := ui.config.System.PublicPort
			if port == 0 {
				port = 51820
			}
			resp.Config.Endpoint = fmt.Sprintf("%s:%d", ui.config.System.PublicHost, port)
		}
		if resp.Config.Endpoint == "" {
			// fallback 保持不变...
			// 如果没填，尝试从请求 Host 猜一个
			host, _, _ := net.SplitHostPort(r.Host)
			port := ui.config.System.ListenPort
			if port == 0 {
				port = 51207
			}
			resp.Config.Endpoint = fmt.Sprintf("%s:%d", host, port)
		}
	}
	allowedIPs := ui.config.System.InternalSubnet
	if allowedIPs == "" {
		allowedIPs = "10.0.0.0/24"
	}
	resp.Config.AllowedIPs = []string{allowedIPs}

	json.NewEncoder(w).Encode(resp)
}

func normalizeEnrollServer(raw string) (string, error) {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return "", fmt.Errorf("empty server")
	}
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return "", err
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
	u.Path = ""
	u.RawQuery = ""
	u.Fragment = ""
	return fmt.Sprintf("%s://%s", u.Scheme, u.Host), nil
}

// handleJoin 处理邀请入网引导页
// GET /join/{token}
func (ui *WebUI) handleJoin(w http.ResponseWriter, r *http.Request) {
	// 1. 精准提取
	token := strings.TrimPrefix(r.URL.Path, "/join/")
	token = strings.Trim(token, " /")
	serverOverride := r.URL.Query().Get("server")

	// 2. 校验
	inviteRemark := "远端服务端"
	if strings.TrimSpace(serverOverride) == "" {
		invite, ok := ui.config.ValidateInvite(token)
		if !ok {
			ui.device.GetLogger().Errorf("邀请码无效或已过期: [%s]", token)
			ui.renderErrorPage(w, "邀请无效", "该邀请码已过期、已被使用或根本不存在。")
			return
		}
		inviteRemark = invite.Remark
	}

	html := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>加入网络 - WireGuard</title>
    <script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
    <style>
        :root {
            --primary: #00d2ff;
            --bg: #0f172a;
            --glass: rgba(255, 255, 255, 0.05);
            --border: rgba(255, 255, 255, 0.1);
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', system-ui, sans-serif; }
        body { background: var(--bg); color: white; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .glass-card { background: var(--glass); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: 24px; padding: 40px; width: 100%; max-width: 500px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); text-align: center; }
        .logo { font-size: 32px; font-weight: 800; margin-bottom: 10px; background: linear-gradient(45deg, #00d2ff, #3a7bd5); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .remark { color: #94a3b8; margin-bottom: 30px; font-size: 14px; }
        .btn { background: linear-gradient(45deg, #00d2ff, #3a7bd5); color: white; border: none; padding: 14px 28px; border-radius: 12px; font-weight: 600; cursor: pointer; transition: 0.3s; width: 100%; margin-top: 20px; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0, 210, 255, 0.3); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .config-box { background: rgba(0,0,0,0.3); border-radius: 12px; padding: 20px; margin-top: 30px; text-align: left; display: none; border: 1px solid var(--border); }
        .config-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .qr-area { display: flex; justify-content: center; margin: 20px 0; background: white; padding: 15px; border-radius: 12px; }
        pre { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin-top: 15px; border-top: 1px solid var(--border); padding-top: 15px; }
        .tab-nav { display: flex; gap: 10px; margin-bottom: 15px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
        .tab-item { cursor: pointer; color: #64748b; font-size: 14px; padding: 5px 10px; border-radius: 6px; }
        .tab-item.active { color: var(--primary); background: rgba(0, 210, 255, 0.1); }
    </style>
</head>
<body>
    <div class="glass-card">
        <div class="logo">WireGuard</div>
        <div class="remark">您受邀加入网络：<strong>` + inviteRemark + `</strong></div>
        
        <div id="action-area">
            <p style="color: #94a3b8; font-size: 14px; line-height: 1.6;">点击下方按钮，母舰将为您自动生成私钥并分配内网 IP。注册成功后，您将获得完整的 WireGuard 配置。</p>
            <button class="btn" id="reg-btn" onclick="register()">立即加入网络</button>
        </div>

        <div id="config-area" class="config-box">
            <div class="config-header">
                <span style="font-weight: 600; color: var(--primary);">入网配置已就绪</span>
                <button onclick="copyConf()" style="background:none; border:none; color:#94a3b8; cursor:pointer; font-size:12px;">复制文本</button>
            </div>
            
            <div class="tab-nav">
                <div class="tab-item active" onclick="showTab('qr', event)">手机扫码</div>
                <div class="tab-item" onclick="showTab('text', event)">手动配置</div>
            </div>

            <div id="tab-qr" class="qr-area">
                <div id="qrcode"></div>
            </div>
            
            <div id="tab-text" style="display:none">
                <pre id="conf-text"></pre>
            </div>

            <p style="margin-top: 15px; font-size: 12px; color: #64748b;">请妥善保管您的私钥，由于服务器不存储私钥，丢失后需联系管理员重新注销并入驻。</p>
        </div>
    </div>

    <script>
        let configData = null;

        async function register() {
            const btn = document.getElementById('reg-btn');
            btn.disabled = true;
            btn.innerText = '正在入驻...';

            try {
                const params = new URLSearchParams(window.location.search);
                const payload = { token: '` + token + `' };
                const server = (params.get('server') || '').trim();
                const endpoint = (params.get('endpoint') || '').trim();
                if (server) payload.server = server;
                if (endpoint) payload.endpoint = endpoint;

                const res = await fetch('/api/register', {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                
                if (data.error) throw new Error(data.error);
                
                configData = data.config;
                renderResult();
            } catch (e) {
                alert('注册失败: ' + e.message);
                btn.disabled = false;
                btn.innerText = '立即加入网络';
            }
        }

        function renderResult() {
            document.getElementById('action-area').style.display = 'none';
            document.getElementById('config-area').style.display = 'block';
            
            const conf = "[Interface]\n" +
                         "PrivateKey = " + configData.private_key + "\n" +
                         "Address = " + configData.address + "\n" +
                         "DNS = 114.114.114.114\n\n" +
                         "[Peer]\n" +
                         "PublicKey = " + configData.public_key + "\n" +
                         "Endpoint = " + configData.endpoint + "\n" +
                         "AllowedIPs = " + configData.allowed_ips.join(', ') + "\n" +
                         "PersistentKeepalive = 25";
            
            document.getElementById('conf-text').innerText = conf;

            // 生成二维码
            const qr = qrcode(0, 'M');
            qr.addData(conf);
            qr.make();
            document.getElementById('qrcode').innerHTML = qr.createImgTag(5);
        }

        function showTab(tab, event) {
            document.getElementById('tab-qr').style.display = tab === 'qr' ? 'flex' : 'none';
            document.getElementById('tab-text').style.display = tab === 'text' ? 'block' : 'none';
            document.querySelectorAll('.tab-item').forEach(el => el.classList.remove('active'));
            event.target.classList.add('active');
        }

        function copyConf() {
            const text = document.getElementById('conf-text').innerText;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('已复制到剪贴板');
                }).catch(() => fallbackCopy(text));
            } else {
                fallbackCopy(text);
            }
        }

        function fallbackCopy(text) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.left = "-9999px";
            textArea.style.top = "0";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            try {
                document.execCommand('copy');
                alert('已复制到剪贴板');
            } catch (err) {
                alert('复制失败，请手动选择复制');
            }
            document.body.removeChild(textArea);
        }
    </script>
</body>
</html>
`
	fmt.Fprint(w, html)
}

// renderErrorPage 渲染美化的错误页
func (ui *WebUI) renderErrorPage(w http.ResponseWriter, title, msg string) {
	html := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>发生错误 - WireGuard</title>
    <style>
        body { background: #0f172a; color: white; height: 100vh; display: flex; align-items: center; justify-content: center; font-family: system-ui; }
        .card { background: rgba(255,255,255,0.05); padding: 40px; border-radius: 20px; border: 1px solid rgba(255,255,255,0.1); text-align: center; }
        h1 { color: #ef4444; margin-bottom: 20px; }
        p { color: #94a3b8; }
    </style>
</head>
<body>
    <div class="card">
        <h1>` + title + `</h1>
        <p>` + msg + `</p>
    </div>
</body>
</html>
`
	fmt.Fprint(w, html)
}

// handleLogin 处理登录逻辑和显示登录页
func (ui *WebUI) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		password := r.FormValue("password")
		hash := sha256.Sum256([]byte(password))

		if subtle.ConstantTimeCompare(hash[:], ui.passwordHash[:]) == 1 {
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    ui.sessionToken,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   86400 * 7, // 7 天有效
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/login?error=1", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorMsg := ""
	if r.URL.Query().Get("error") != "" {
		errorMsg = `<div style="background:rgba(239, 68, 68, 0.1); color:#ef4444; padding:12px; border-radius:8px; margin-bottom:20px; font-size:14px; text-align:center; border:1px solid rgba(239, 68, 68, 0.2);">密码错误，请重试</div>`
	}

	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - WireGuard Controller</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: #0f172a;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #f1f5f9;
        }
        .login-card {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(12px);
            padding: 40px;
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        h2 { text-align: center; margin-bottom: 8px; color: #38bdf8; font-size: 24px; }
        p.subtitle { text-align: center; color: #64748b; font-size: 14px; margin-bottom: 30px; }
        input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(15, 23, 42, 0.5);
            border: 1px solid #334155;
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
            margin-bottom: 20px;
            outline: none;
            transition: border-color 0.2s;
        }
        input:focus { border-color: #38bdf8; }
        button {
            width: 100%;
            padding: 12px;
            background: #0ea5e9;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover { background: #0284c7; }
        .footer { text-align: center; margin-top: 24px; font-size: 12px; color: #475569; }
    </style>
</head>
<body>
    <div class="login-card">
        <h2>🛡️ 身份验证</h2>
        <p class="subtitle">请输入访问密码以继续</p>
        `+errorMsg+`
        <form method="POST">
            <input type="password" name="password" placeholder="访问密码" autofocus required>
            <button type="submit">立即登录</button>
        </form>
        <div class="footer">Userspace WireGuard Controller</div>
    </div>
</body>
</html>`)
}

// renderJoinPortal 渲染通用的入驻门户页面 (不带 Token)
func (ui *WebUI) renderJoinPortal(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>入驻门户 - WireGuard 母舰</title>
    <style>
        :root { --primary: #00d2ff; --bg: #0f172a; --glass: rgba(255, 255, 255, 0.05); }
        body { background: var(--bg); color: white; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; font-family: system-ui; }
        .glass-card { background: var(--glass); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 24px; padding: 40px; width: 100%; max-width: 450px; text-align: center; }
        .title { font-size: 28px; font-weight: 800; margin-bottom: 30px; }
        input { width: 100%; padding: 14px; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); background: rgba(0,0,0,0.2); color: white; font-size: 16px; margin-bottom: 20px; text-align: center; letter-spacing: 2px; }
        .btn { background: linear-gradient(45deg, #00d2ff, #3a7bd5); color: white; border: none; padding: 14px; border-radius: 12px; font-weight: 600; cursor: pointer; width: 100%; transition: 0.3s; }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(0, 210, 255, 0.3); }
    </style>
</head>
<body>
    <div class="glass-card">
        <div class="title">🚀 欢迎加入网络</div>
        
        <div style="text-align: left; background: rgba(0,0,0,0.2); padding: 15px; border-radius: 12px; margin-bottom: 25px; border: 1px solid rgba(255,255,255,0.05);">
            <p style="color:#38bdf8; font-size:13px; font-weight:600; margin-bottom:8px;">💡 使用说明</p>
            <ol style="color:#94a3b8; font-size:12px; padding-left:18px; line-height:1.6;">
                <li>请输入管理员发放的 <strong>12 位邀请码</strong>。</li>
                <li><strong>服务器地址</strong> 必须手动填写 (格式如 <code>ip:51820</code>)。</li>
                <li>提交后将自动为您生成 WireGuard 配置信息。</li>
            </ol>
        </div>

        <p style="color:#94a3b8; font-size:13px; margin-bottom:10px; font-weight:600;">邀请码</p>
        <input type="text" id="token" placeholder="示例: ABCD-1234-XYZ" autocomplete="off">
        
        <p style="color:#94a3b8; font-size:13px; margin-top:10px; margin-bottom:10px; font-weight:600;">服务器公网地址 (Endpoint)</p>
        <input type="text" id="endpoint" placeholder="例如: 1.2.3.4:51820" autocomplete="off">
        
        <button class="btn" onclick="go()">立即入驻网络</button>
    </div>
    <script>
        function go() {
            const token = document.getElementById('token').value.trim();
            const endpoint = document.getElementById('endpoint').value.trim();
            if(!token) return alert('请填入邀请码');
            if(!endpoint) return alert('请填入服务器 Endpoint 地址');
            
            let url = '/join/' + token;
            url += '?endpoint=' + encodeURIComponent(endpoint);
            window.location.href = url;
        }
        document.getElementById('token').onkeypress = (e) => e.key === 'Enter' && go();
        document.getElementById('endpoint').onkeypress = (e) => e.key === 'Enter' && go();
    </script>
</body>
</html>`
	fmt.Fprint(w, html)
}
