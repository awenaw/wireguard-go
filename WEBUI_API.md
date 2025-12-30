# WireGuard Controller Web UI & API Documentation

本文档介绍了为 `wireguard-go` 开发的内嵌 Web UI 及其配套的 HTTP API。

## 1. 概述

为了方便在 IoT 场景下对受控终端进行可视化管理，我们在 `wireguard-go` 内部集成了一个轻量级的 Web 服务器。它不仅提供美观的状态展示界面，还暴露了跨越式的 JSON API，方便集成到其他管理平台中。

## 2. 访问方式

- **默认地址**：`http://localhost:8080`
- **文档页面**：`http://localhost:8080/docs`

## 3. UI 功能特性

- **现代列表布局**：采用类似专业运维工具（如 ZeroTier/wg-easy）的纵向列表布局。
- **自动对齐排序**：设备列表自动按备注名（Remark）升序排列。
- **实时状态感知**：呼吸灯样式的在线/离线状态指示，每 3 秒自动刷新。
- **流量统计**：实时显示每个 Peer 的上传和下载字节数。
- **响应式设计**：支持多端查看。

## 4. API 接口详解

### 4.1 获取设备完整状态
- **Endpoint**: `GET /api/status`
- **描述**: 返回设备的核心配置及所有 Peer 的详细列表。
- **返回示例**:
```json
{
  "public_key": "f4uHssl...",
  "listen_port": 38200,
  "peer_count": 5,
  "peers": [
    {
      "remark": "Debian",
      "public_key": "d/bLS0a...",
      "endpoint": "10.0.0.3:51820",
      "allowed_ips": ["10.166.0.3/32"],
      "last_handshake": "2025-12-30 10:45:00",
      "tx_bytes": 1048576,
      "rx_bytes": 524288,
      "is_running": true
    }
  ]
}
```

### 4.2 仅获取对等体列表
- **Endpoint**: `GET /api/peers`
- **描述**: 仅返回对等体数组，适用于轻量级定时刷新。

## 5. 核心定制开发 (路线 B - 坚实一步)

我们在源代码中进行了以下深度定制，以支持更高级的运维需求：

- **Peer 结构体增强**：在 `device/peer.go` 中添加了 `Remark` 字段。
- **自动身份映射**：在 `device/peer.go` 的 `NewPeer` 阶段，通过公钥自动关联设备名称，解决了 WireGuard 原生 UAPI 不支持备注的问题。
- **CORS 跨域支持**：API 默认开启跨域支持，可直接被外部 Web 页面通过 `fetch` 调用。

## 6. 未来演进：边缘可编程架构 (Lua Integration)

为了解决 10,000 台设备频繁升级版本的问题，我们计划引入 **Lua 脚本引擎**：

1. **逻辑驱动**：Go 提供原子能力（锁屏、网络排查、状态读取）。
2. **脚本下发**：云端通过类似 `/api/script` 接口下发 `.lua` 逻辑。
3. **热生效**：客户端 Agent 无需升级重启，即可通过热加载 Lua 脚本更新操作逻辑。
4. **硬件指纹锚点**：利用 SMBIOS UUID 实现“重装不丢身份”的自动化运维。

---
*Created by Antigravity Assistant.*
