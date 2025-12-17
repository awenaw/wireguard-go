# 📜 关卡一通关档案：指令漂流记 (Story of a Command)

> 这是一个关于“控制”的故事。当我们敲下键盘时，WireGuard 内部到底发生了什么？
> 本文档基于我们在 `device/uapi.go` 中插下的 "aw-开荒" 旗帜整理而成。

## 🎬 序幕：Socket 的震动

一切始于外部。Agent 或管理员通过 `wg set` 发起连接。
Linux/Mac 下连接 `/var/run/wireguard/utunX.sock`。

## 📍 第一幕：守门人 (General Loop)

**代码位置**: `device/uapi.go` -> `IpcHandle` (aw-开荒)

守护进程在死循环中醒来。
```go
func (device *Device) IpcHandle(socket net.Conn) {
    for {
        op, _ := buffered.ReadString('\n')
        switch op {
            case "set=1\n": // <--- 故事的开始
                device.IpcSetOperation(buffered.Reader)
        }
    }
}
```
它识别出这是一个“写入”操作，于是把控制权移交。

## 📍 第二幕：流式解析与上下文切换 (Context Switch)

**代码位置**: `device/uapi.go` -> `IpcSetOperation`

文本配置像流水一样进来。代码利用了一个状态机变量 `key == "public_key"` 来判断什么时候切换对象。

```go
for scanner.Scan() {
    // 每次遇到 public_key，就意味着“上一个 Peer 聊完了，还是聊下一个吧”
    if key == "public_key" {  // <--- aw-开荒
        peer.handlePostConfig() // 保存上一个 Peer
        device.NewPeer(value)   // 创建新 Peer
    }
}
```
这种设计非常巧妙，它不需要一次性把几兆的配置文件读进内存，而是边读边配，极其高效。

## 📍 第三幕：手术刀 (The Injection)

**代码位置**: `device/uapi.go` -> `handlePeerLine` -> `case "allowed_ip"`

这是改变流量走向的最终时刻。

```go
case "allowed_ip": // <--- aw-开荒
    // 将 IP  -> Peer 的映射关系写入内存中的 Trie 树
    device.allowedips.Insert(prefix, peer.Peer)
```

**结局**：
指令处理完毕，Socket 关闭。
WireGuard 并没有重启，但它的“脑子”（路由表和密钥库）已经被我们换掉了。
这就是“无感热更新”的真相。

---

*Mission Clear: Level 1 - Command Center*
*Documented by Commander & Antigravity*
