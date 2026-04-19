# WireGuard Controller HTTP API 文档

本文档介绍了为 `wireguard-go` 开发的内嵌 Web UI 及其配套的 HTTP API。

## 1. 概述

为了方便在 IoT 场景下对受控终端进行可视化管理，我们在 `wireguard-go` 内部集成了一个轻量级的 HTTP 服务器。它不仅提供美观的状态展示界面，还暴露了标准的 JSON API，方便集成到其他管理平台中。

**基础地址：** `http://localhost:8080`

## 2. 接口清单

### 2.1 查询类接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/status` | 获取完整状态（设备 + 所有 Peer） |
| `GET` | `/api/peers` | 仅获取 Peer 列表 |
| `GET` | `/docs` | API 文档页面（HTML） |
| `GET` | `/` | Web UI 主页 |

### 2.2 配置类接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/peer/add` | 添加 Peer |
| `POST` | `/api/peer/remove` | 删除 Peer |
| `POST` | `/api/config` | 批量配置（UAPI 格式） |

## 3. 接口详解

### 3.1 GET /api/status

获取设备的完整状态信息，包括核心配置及所有 Peer 的详细统计。

**返回示例：**
```json
{
  "public_key": "f4uHssluh2IT2O/4wOt0Lv73f4Fl8P3plAanQxsIHgM=",
  "listen_port": 38200,
  "peer_count": 5,
  "peers": [
    {
      "remark": "Debian",
      "public_key": "d/bLS0aD77K6N5tv9PqywHn3w8djtuouK6i86dT2mXs=",
      "endpoint": "10.0.0.104:38561",
      "allowed_ips": ["10.166.0.3/32"],
      "last_handshake": "2026-01-01 22:30:00",
      "tx_bytes": 1048576,
      "rx_bytes": 524288,
      "is_running": true
    }
  ]
}
```

### 3.2 GET /api/peers

仅返回对等体数组，适用于轻量级定时刷新。

**返回示例：**
```json
[
  {"remark": "iPhone", "public_key": "...", "endpoint": "...", ...},
  {"remark": "wg-study", "public_key": "...", "endpoint": "...", ...}
]
```

### 3.3 POST /api/peer/add

添加一个新的 Peer。

**请求体：**
```json
{
  "public_key": "d2fb4b534068efb3a6379b6f3d3e89c3632a3b8e106ac2c9776c38b41d36",
  "allowed_ips": ["10.166.0.100/32"],
  "endpoint": "1.2.3.4:51820",
  "persistent_keepalive": 25
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `public_key` | string | ✅ | Peer 的公钥（Hex 格式） |
| `allowed_ips` | string[] | ✅ | 允许的 IP 地址列表 |
| `endpoint` | string | ❌ | Peer 的 UDP 端点 |
| `persistent_keepalive` | int | ❌ | 心跳间隔（秒） |

**成功响应：**
```json
{"status": "ok", "message": "Peer added successfully"}
```

### 3.4 POST /api/peer/remove

删除一个 Peer。

**请求体：**
```json
{
  "public_key": "d2fb4b534068efb3a6379b6f3d3e89c3632a3b8e106ac2c9776c38b41d36"
}
```

**成功响应：**
```json
{"status": "ok", "message": "Peer removed successfully"}
```

### 3.5 POST /api/config

批量配置，直接使用 UAPI 格式的配置字符串。

**请求体：**
```json
{
  "config": "public_key=d2fb4b534068efb3...\nallowed_ip=10.166.0.100/32\npersistent_keepalive_interval=25\n"
}
```

**成功响应：**
```json
{"status": "ok", "message": "Config applied successfully"}
```

## 4. 错误响应

所有接口在发生错误时返回统一格式：

```json
{
  "error": "错误描述信息"
}
```

常见错误码：
- `400 Bad Request` - 请求参数错误
- `405 Method Not Allowed` - HTTP 方法错误（应使用 POST）
- `500 Internal Server Error` - 服务器内部错误

## 5. CORS 支持

所有 API 接口默认开启跨域支持（`Access-Control-Allow-Origin: *`），可直接被外部 Web 页面通过 `fetch` 调用。

## 6. 与 UAPI 的关系

HTTP API 是对原生 Unix Socket UAPI 的封装：

| 特性 | Unix Socket UAPI | HTTP API |
|------|------------------|----------|
| 访问方式 | 本地 Socket 文件 | 任意 HTTP 客户端 |
| 权限控制 | 文件权限 (root) | 可加 Token 认证 |
| 跨网络访问 | ❌ 只能本地 | ✅ 可远程调用 |
| Java/Python 调用 | 需要特殊库 | 标准 HTTP 请求 |

## 7. 使用示例

### cURL

```bash
# 获取状态
curl http://localhost:8080/api/status

# 添加 Peer
curl -X POST http://localhost:8080/api/peer/add \
  -H "Content-Type: application/json" \
  -d '{"public_key": "abc123...", "allowed_ips": ["10.0.0.1/32"]}'

# 删除 Peer
curl -X POST http://localhost:8080/api/peer/remove \
  -H "Content-Type: application/json" \
  -d '{"public_key": "abc123..."}'
```

### Java (OkHttp)

```java
OkHttpClient client = new OkHttpClient();

// GET 状态
Request request = new Request.Builder()
    .url("http://localhost:8080/api/status")
    .build();
Response response = client.newCall(request).execute();
String json = response.body().string();

// POST 添加 Peer
String body = "{\"public_key\":\"abc...\",\"allowed_ips\":[\"10.0.0.1/32\"]}";
Request postRequest = new Request.Builder()
    .url("http://localhost:8080/api/peer/add")
    .post(RequestBody.create(body, MediaType.parse("application/json")))
    .build();
client.newCall(postRequest).execute();
```

### JavaScript

```javascript
// 获取状态
fetch('/api/status')
  .then(res => res.json())
  .then(data => console.log(data));

// 添加 Peer
fetch('/api/peer/add', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    public_key: 'abc123...',
    allowed_ips: ['10.0.0.1/32']
  })
});
```

---
*Created by Antigravity Assistant.*
