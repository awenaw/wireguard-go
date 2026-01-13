# SimpleLink 客户端技术架构设计文档

## 1. 核心设计理念

SimpleLink 客户端采用 **"UI 与核心分离" (Separation of Concerns)** 的架构模式。
核心网络层由 Go 语言负责，确保高性能和跨平台一致性；用户界面层采用 Web 技术栈，确保界面美观和开发效率。

**核心原则：**
*   **Web 保底**：无论在什么环境下（无头服务器、Win7 老旧系统），用户都可以通过浏览器访问本地服务来管理 VPN。
*   **Electron 提效**：在主流桌面环境（Win10/11, macOS）下，通过 Electron 封装提供原生级的系统交互体验（托盘、通知、开机自启）。

---

## 2. 技术栈选型 (Tech Stack)

### 2.1 核心层 (Daemon / Core)
*   **语言**: Golang (1.21+)
*   **基础库**: `wireguard-go` (修改版，增加动态配置能力)
*   **接口协议**: Localhost HTTP REST API
*   **嵌入资源**: 使用 `embed` 特性将 Vue 编译后的静态文件打包进 Go 二进制文件中，实现"单文件运行"。

### 2.2 界面层 (Frontend UI)
*   **框架**: Vue 3 + TypeScript
*   **组件库**: Element Plus / Tailwind CSS
*   **构建工具**: Vite
*   **形态**:
    1.  **Web Mode**: 编译为纯 HTML/JS，由 Go Core 的内置 Web Server 托管。
    2.  **Desktop Mode**: 嵌入 Electron 容器中运行。

### 2.3 宿主层 (Shell)
*   **主流平台 (Win10+, macOS, Linux Desktop)**:
    *   **方案**: Electron (推荐 v28+)
    *   **模式**: Sidecar 模式（Electron 启动并管理 Go Core 子进程）。
*   **存量平台 (Windows 7 / Server)**:
    *   **方案**: Headless Go Binary (CLI / Web)
    *   **运行**: 用户直接运行 Go 程序，通过系统默认浏览器访问 `http://127.0.0.1:58000`。
    *   **构建约束**: 针对 Win7 单独编译 Legacy 版本 (需 Golang 1.20)。

---

## 3. 系统架构图

```mermaid
graph TD
    subgraph "前端 (Vue 3)"
        UI[界面交互 (App.vue)]
        Store[状态管理 (Pinia)]
        API_Client[API Client (Axios)]
    end

    subgraph "宿主容器 (Shell)"
        Electron[Electron 主进程]
        Browser[系统浏览器 (Win7/Server)]
    end

    subgraph "后端核心 (Go Daemon)"
        WebServer[内置 Web Server (Gin)]
        Controller[业务逻辑控制]
        Config[配置管理 (SQLite/JSON)]
        WG[WireGuard 本地协议栈]
    end

    Electron -- 启动子进程 --> 后端核心
    Browser -- 访问 localhost --> WebServer
    
    UI -- IPC/HTTP --> Electron
    API_Client -- HTTP REST --> WebServer
    
    Controller -- 控制 --> WG
    WG -- UDP 隧道 --> Internet
```

---

## 4. 关键功能设计

### 4.1 多网络支持 (Multi-Network)
*   **需求**: 允许用户同时保存多个服务端的配置（如：公司内网、家庭实验室、客户现场）。
*   **实现**: 
    *   客户端支持 Profile Switching（配置文件切换）。
    *   UI 左侧增加 "Network Bar" 侧边栏，支持一键切换当前激活的网络环境。

### 4.2 注册与生命周期 (Lifecycle)
*   **注册流程**: 
    *   输入 Server URL 和 Device Name。
    *   客户端生成公私钥对。
    *   向服务端发起 CSR (Certificate Signing Request) 式的注册请求。
*   **状态机**:
    *   `NEW` -> `PENDING` (等待管理员审批，显示 Device ID) -> `APPROVED` (获取配置连接)
    *   `REJECTED` (被拒，显示拒绝原因，允许修改重试)
    *   `EXPIRED` (密钥过期，强制重置密钥)

### 4.3 兼容性策略 (Compatibility)
| 操作系统 | 推荐交互方式 | 技术实现 |
| :--- | :--- | :--- |
| **Windows 10 / 11** | Native App | Electron + Go Core |
| **macOS (Intel/M1)** | Native App | Electron + Go Core |
| **Linux (Ubuntu/Arch)** | Native App | Electron + Go Core |
| **Windows 7** | Web UI / CLI | Go Core (Built with Go 1.20) |
| **Headless Linux** | CLI / Web UI | Go Core |

---

## 5. 开发路线图 (Roadmap)

1.  **Phase 1: 核心改造**
    *   基于 `wireguard-go` 封装 `Device` 控制逻辑。
    *   实现 Localhost API (Connect/Disconnect/Status)。
    *   实现配置文件的本地加密存储。

2.  **Phase 2: Web UI 开发**
    *   使用 Vue 3 实现所有界面原型（注册、连接、设置）。
    *   联调 Go API，实现基础 VPN 功能。

3.  **Phase 3: Electron 封装**
    *   集成托盘图标、系统通知、开机自启。
    *   实现 Sidecar 进程保活机制。

4.  **Phase 4: 多平台编译与分发**
    *   配置 GitHub Actions 自动构建 Win/Mac/Linux 安装包。
    *   产出 Win7 专用 Legacy 包。
