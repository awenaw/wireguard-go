package manager

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// Config 核心配置结构
type Config struct {
	System   SystemConfig   `json:"system"`
	Identity IdentityConfig `json:"identity"`
	Peers    []PeerRecord   `json:"peers"`
	Invites  []Invite       `json:"invites"`
}

// SystemConfig 系统级网络设置
type SystemConfig struct {
	PublicHost       string `json:"public_host"`       // WireGuard 公网 Host (IP 或域名)
	PublicPort       uint16 `json:"public_port"`       // WireGuard 对外端口
	WebHost          string `json:"web_host"`          // Web 门户 Host (如 vpn.com)
	WebPort          uint16 `json:"web_port"`          // Web 门户端口
	InternalSubnet   string `json:"internal_subnet"`   // 内网网段 (如 10.0.0.1/24)
	ListenPort       uint16 `json:"listen_port"`       // UDP 本地监听端口
	IsClient         bool   `json:"is_client"`         // 标记是否为客户端
	DefaultKeepalive int    `json:"default_keepalive"` // 新 Peer 默认的 PersistentKeepalive (秒)
}

// IdentityConfig 服务端身份
type IdentityConfig struct {
	PrivateKey string `json:"private_key"` // 服务端私钥 (Base64)
}

// PeerRecord 已注册的对等体记录
type PeerRecord struct {
	PublicKey           string   `json:"public_key"`           // 对等体公钥 (Base64)
	Remark              string   `json:"remark"`               // 备注
	AllowedIPs          []string `json:"allowed_ips"`          // 分配的内网 IP
	Endpoint            string   `json:"endpoint"`             // 如果是连接上游，需要带端口
	PersistentKeepalive int      `json:"persistent_keepalive"` // 持久保活间隔 (秒)，0 为关闭
}

// Invite 邀请码记录
type Invite struct {
	Token     string    `json:"token"`      // 随机令牌
	Remark    string    `json:"remark"`     // 预设备注
	ExpiresAt time.Time `json:"expires_at"` // 过期时间
	CreatedAt time.Time `json:"created_at"` // 创建时间
}

// EnsureIdentity 确保服务端身份存在，如果不存在则生成并保存
func (c *Config) EnsureIdentity() bool {
	configLock.Lock()
	defer configLock.Unlock() // Ensure unlock happens
	if c.Identity.PrivateKey == "" {
		c.Identity.PrivateKey = device.GeneratePrivateKey()
		return true // 标识有变动，需要保存
	}
	return false
}

var (
	configLock sync.RWMutex
	dataPath   = "wg_data/config.json"
)

// LoadConfig 从磁盘加载配置，如果文件不存在则创建一个空的初始化配置
func LoadConfig() (*Config, error) {
	configLock.RLock()
	defer configLock.RUnlock()

	// 确保目录存在
	dir := filepath.Dir(dataPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.MkdirAll(dir, 0755)
	}

	// 如果文件不存在，返回一个默认初始结构
	if _, err := os.Stat(dataPath); os.IsNotExist(err) {
		return &Config{
			System: SystemConfig{
				ListenPort:     51820,
				InternalSubnet: "10.0.0.1/24",
			},
			Peers: []PeerRecord{},
		}, nil
	}

	data, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var conf Config
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &conf, nil
}

// SaveConfig 将配置原子性地保存到磁盘
func SaveConfig(conf *Config) error {
	configLock.Lock()
	defer configLock.Unlock()

	data, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return err
	}

	// 原子写入：先写临时文件，再重命名
	tmpPath := dataPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpPath, dataPath)
}

// b64ToHex 将 Base64 编码的密钥转换为 UAPI 要求的 Hex 编码
func b64ToHex(b64Str string) string {
	data, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(data)
}

// ApplyToDevice 将当前的配置通过 UAPI 注入到 WireGuard 设备中
func (c *Config) ApplyToDevice(dev *device.Device) error {
	var uapi strings.Builder

	// 1. 处理系统与身份配置
	if c.Identity.PrivateKey != "" {
		uapi.WriteString(fmt.Sprintf("private_key=%s\n", b64ToHex(c.Identity.PrivateKey)))
	}
	if c.System.ListenPort != 0 {
		uapi.WriteString(fmt.Sprintf("listen_port=%d\n", c.System.ListenPort))
	}

	// 2. 处理 Peers
	for _, peer := range c.Peers {
		uapi.WriteString(fmt.Sprintf("public_key=%s\n", b64ToHex(peer.PublicKey)))
		for _, ip := range peer.AllowedIPs {
			uapi.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip))
		}
		if peer.Endpoint != "" {
			uapi.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint))
		}
		if peer.PersistentKeepalive > 0 {
			uapi.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive))
		}
	}

	// 3. 执行注入
	if uapi.Len() > 0 {
		return dev.IpcSet(uapi.String())
	}
	return nil
}

// ConfigureInterface 自动化配置系统网卡 (针对 macOS/Linux)
func (c *Config) ConfigureInterface(interfaceName string) error {
	ip := c.System.InternalSubnet
	if ip == "" {
		ip = "10.0.0.1/24"
	}
	directIP := strings.Split(ip, "/")[0]

	if runtime.GOOS == "darwin" {
		// 1. 系统清理：先解绑 lo0 上的别名
		_ = exec.Command("ifconfig", "lo0", "-alias", directIP).Run()

		// 2. 挂载网卡：设置 P2P 模式，让 10.0.0.1 属于 utun 接口
		if err := exec.Command("ifconfig", interfaceName, directIP, directIP, "netmask", "255.255.255.0", "up").Run(); err != nil {
			return fmt.Errorf("ifconfig %s failed: %w", interfaceName, err)
		}

		// 3. 路由修正：清理会覆盖隧道路由的旧 host 路由。
		// 场景：本机曾作为服务端(10.x.x.1 -> lo0)，切换为客户端后若不删除该 host 路由，
		// 访问 10.x.x.1 仍会命中 lo0 而不是 utun。
		subnet := strings.Join(strings.Split(directIP, ".")[:3], ".") + ".0/24"
		gateway := strings.Join(strings.Split(directIP, ".")[:3], ".") + ".1"
		_ = exec.Command("route", "-q", "delete", "-host", directIP).Run()
		_ = exec.Command("route", "-q", "delete", "-host", gateway).Run()

		// 服务端模式保留本机 host route 补丁，客户端模式不应回指 lo0。
		if !c.System.IsClient {
			if err := exec.Command("route", "-q", "add", "-host", directIP, "127.0.0.1").Run(); err != nil {
				return fmt.Errorf("add host route failed: %w", err)
			}
		}

		// 4. 子网路由：确保 10.x.x.0/24 走隧道
		_ = exec.Command("route", "-q", "delete", "-net", subnet).Run()
		if err := exec.Command("route", "-q", "add", "-net", subnet, "-interface", interfaceName).Run(); err != nil {
			return fmt.Errorf("add subnet route failed: %w", err)
		}

		return nil
	}

	if runtime.GOOS == "linux" {
		// Linux 逻辑非常直接
		// 1. 赋予 IP (ip addr add ...)
		if err := exec.Command("ip", "addr", "replace", ip, "dev", interfaceName).Run(); err != nil {
			return fmt.Errorf("ip addr replace failed: %w", err)
		}
		// 2. 启动网卡 (ip link set up ...)
		if err := exec.Command("ip", "link", "set", "up", "dev", interfaceName).Run(); err != nil {
			return fmt.Errorf("ip link up failed: %w", err)
		}
		return nil
	}

	if runtime.GOOS == "windows" {
		// Windows 逻辑：使用 netsh 配置静态 IP
		mask := "255.255.255.0"
		if strings.Contains(ip, "/") {
			if strings.HasSuffix(ip, "/32") {
				mask = "255.255.255.255"
			}
		}
		// 执行 netsh 设置地址
		// 命令: netsh interface ipv4 set address name="wg0" static 10.0.0.x 255.255.255.x
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "address", "name="+interfaceName, "static", directIP, mask)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("netsh set address failed: %w", err)
		}
		return nil
	}
	return nil
}

// SyncFromDevice 从设备当前状态同步到 Config 对象，用于持久化运行时的改动
func (c *Config) SyncFromDevice(dev *device.Device) {
	configLock.Lock()
	defer configLock.Unlock()

	// 1. 同步身份与系统设置
	// 注意：私钥无法通过 Get 接口获取（为了安全），
	// 但如果 JSON 里已经有了，我们就保留它。
	c.System.ListenPort = dev.GetListenPort()

	// 2. 同步 Peers
	var newPeers []PeerRecord
	dev.ForEachPeer(func(p *device.Peer) {
		newPeers = append(newPeers, PeerRecord{
			PublicKey:           p.GetPublicKey(),
			Remark:              p.Remark,
			AllowedIPs:          p.GetAllowedIPList(),
			Endpoint:            p.GetEndpoint(),
			PersistentKeepalive: int(p.GetKeepaliveInterval()),
		})
	})
	c.Peers = newPeers
}

// GetNextAvailableIP 查找下一个可用的内网 IP (Phase 3)
func (c *Config) GetNextAvailableIP() (string, error) {
	configLock.RLock()
	defer configLock.RUnlock()

	prefix, err := netip.ParsePrefix(c.System.InternalSubnet)
	if err != nil {
		return "", fmt.Errorf("invalid subnet: %w", err)
	}

	// 收集已使用的 IP
	usedIPs := make(map[string]bool)
	for _, p := range c.Peers {
		for _, ipRange := range p.AllowedIPs {
			// 假设 AllowedIPs 格式为 10.0.0.x/32
			if ip, err := netip.ParsePrefix(ipRange); err == nil {
				usedIPs[ip.Addr().String()] = true
			}
		}
	}

	// 遍历子网 (跳过网关 .1)
	addr := prefix.Addr()
	for {
		addr = addr.Next()
		if !prefix.Contains(addr) {
			break
		}
		// 跳过 .1
		if addr.As4()[3] == 1 {
			continue
		}
		if !usedIPs[addr.String()] {
			return addr.String() + "/32", nil
		}
	}

	return "", fmt.Errorf("no available IPs in subnet")
}

// GenerateInvite 生成一个新的邀请码 (Phase 3)
func (c *Config) GenerateInvite(remark string, duration time.Duration) (string, error) {
	configLock.Lock()
	defer configLock.Unlock()

	// 生成 12 位随机 Token
	b := make([]byte, 9)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := strings.ToUpper(fmt.Sprintf("%x", b))

	invite := Invite{
		Token:     token,
		Remark:    remark,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(duration),
	}

	c.Invites = append(c.Invites, invite)
	return token, nil
}

// ValidateInvite 校验邀请码是否有效
func (c *Config) ValidateInvite(token string) (*Invite, bool) {
	configLock.RLock()
	defer configLock.RUnlock()

	cleanToken := strings.ToUpper(strings.TrimSpace(token))
	for _, inv := range c.Invites {
		if strings.ToUpper(inv.Token) == cleanToken {
			// 终极修复：给足 24 小时的额外宽限，彻底解决时钟漂移和 0 秒过期问题
			if time.Now().Before(inv.ExpiresAt.Add(24 * time.Hour)) {
				return &inv, true
			}
		}
	}
	return nil, false
}

// RemoveInvite 消耗/删除邀请码
func (c *Config) RemoveInvite(token string) {
	configLock.Lock()
	defer configLock.Unlock()

	for i, inv := range c.Invites {
		if inv.Token == token {
			c.Invites = append(c.Invites[:i], c.Invites[i+1:]...)
			return
		}
	}
}

// RemoteEnroll 通过邀请链接或 Token 远程注册入网
func (c *Config) RemoteEnroll(joinURL string) error {
	var token, apiBase, endpointOverride string

	if strings.Contains(joinURL, "/join/") {
		parsed, err := url.Parse(joinURL)
		if err != nil {
			return fmt.Errorf("invalid join URL: %w", err)
		}
		parts := strings.Split(parsed.Path, "/join/")
		if len(parts) < 2 {
			return fmt.Errorf("invalid join URL format")
		}
		token = parts[1]
		endpointOverride = parsed.Query().Get("endpoint")
		apiBase = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	} else {
		return fmt.Errorf("please provide a full join URL (e.g., http://server:8080/join/TOKEN)")
	}

	fmt.Printf("🚀 正在尝试加入网络: %s\n", apiBase)

	// 准备注册请求
	payload := map[string]string{
		"token": token,
	}
	if strings.TrimSpace(endpointOverride) != "" {
		payload["endpoint"] = endpointOverride
	}
	reqBody, _ := json.Marshal(payload)

	resp, err := http.Post(apiBase+"/api/register", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error (status %d)", resp.StatusCode)
	}

	var reg struct {
		Config struct {
			PrivateKey string   `json:"private_key"`
			Address    string   `json:"address"`
			PublicKey  string   `json:"public_key"`
			Endpoint   string   `json:"endpoint"`
			AllowedIPs []string `json:"allowed_ips"`
		} `json:"config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&reg); err != nil {
		return fmt.Errorf("failed to decode server response: %w", err)
	}

	// 将获取到的配置写入本地 Config
	c.Identity.PrivateKey = reg.Config.PrivateKey
	c.System.InternalSubnet = reg.Config.Address // 客户端保存自己的 IP
	c.System.IsClient = true
	c.Peers = []PeerRecord{
		{
			PublicKey:  reg.Config.PublicKey,
			AllowedIPs: reg.Config.AllowedIPs, // 通常是 10.0.0.0/24
			Remark:     "UPSTREAM_SERVER",
			Endpoint:   reg.Config.Endpoint,
		},
	}

	fmt.Printf("✅ 注册成功！分配 IP: %s\n", reg.Config.Address)
	fmt.Printf("📡 服务端地址: %s\n", reg.Config.Endpoint)

	// 保存配置
	return SaveConfig(c)
}
