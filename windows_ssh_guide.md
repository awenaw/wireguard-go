# Windows IoT SSH 配置指南 (踩坑实录)

本文档记录了如何在 Windows 10 IoT (及普通版) 上配置 OpenSSH Server，并实现从 macOS 客户端进行免密登录的最佳实践。

## 1. 核心目标
建立一个稳定、无密码、无乱码的 SSH 通道，用于远程管理 Windows IoT 设备。

## 2. 关键坑点总结
在配置过程中，我们主要解决了以下几个“Windows 特色”的阻碍：

1.  **用户混淆**：SSH 登录的用户 (`admin_ssh`) 与 Windows 桌面当前登录的用户 (`hiot`) 可能是不同的。
2.  **权限地狱**：OpenSSH 对 `authorized_keys` 文件的权限要求极高，多一个用户都不行。
3.  **管理员特殊待遇**：Windows 默认配置强制管理员组的 Key 必须放在 `ProgramData` 下，而不是用户目录。
4.  **编码乱码**：Windows CMD/PowerShell 默认 GBK 编码与 SSH (UTF-8) 冲突。

---

## 3. 服务端配置 (Windows)

### 3.1 用户准备
建议创建一个专门用于 SSH 的管理员账户（例如 `admin_ssh`），避免干扰日常使用的 `hiot` 账户。
```cmd
net user admin_ssh <StrongPassword> /add
net localgroup administrators admin_ssh /add
```

### 3.2 修正 sshd_config (至关重要)
默认配置会阻止管理员使用 `~/.ssh/authorized_keys`。必须修改配置文件。

**文件路径**: `C:\ProgramData\ssh\sshd_config`

**修改操作** (PowerShell 管理员模式):
```powershell
# 1. 备份
Copy-Item C:\ProgramData\ssh\sshd_config C:\ProgramData\ssh\sshd_config.bak

# 2. 注释掉默认的 Match Group Administrators 规则
# (这一步让管理员和普通用户一样，去读自己目录下的 key)
$content = Get-Content C:\ProgramData\ssh\sshd_config
$newContent = $content -replace 'Match Group Administrators', '# Match Group Administrators'
$newContent = $newContent -replace 'AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys', '# AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'

# 3. 确保 StrictModes 关闭 (可选，但在测试期很有用)
$newContent = $newContent -replace '#StrictModes yes', 'StrictModes no'

# 4. 保存并重启
$newContent | Set-Content C:\ProgramData\ssh\sshd_config
Restart-Service sshd
```

### 3.3 部署公钥与权限修复
**这是最容易翻车的一步**。

1.  **创建目录**: `C:\Users\admin_ssh\.ssh\`
2.  **创建文件**: `authorized_keys` (注意无后缀名！)
3.  **写入公钥**: 将 Mac 的 `id_rsa.pub` 或 `id_ed25519.pub` 内容粘贴进去。
    *   *注意*: 公钥文件必须是 **UTF-8 无 BOM** 格式，切勿使用 Windows 记事本直接保存，推荐用 `echo` 或 `scp`。

4.  **权限清洗 (必做)**:
    `authorized_keys` 文件**只能**拥有以下权限，其他组（如 Users, Authenticated Users）必须删除：
    *   SYSTEM (Full Control)
    *   Administrators (Full Control)
    *   admin_ssh (Full Control)

---

## 4. 客户端配置 (macOS)

### 4.1 SSH Config 配置
为了避免每次输入 IP 和指定 Key，编辑 `~/.ssh/config`：

```text
Host hiot
    HostName 10.0.0.111
    User admin_ssh
    IdentityFile ~/.ssh/hzw  # 指定特定的私钥
```

### 4.2 免密连接测试
```bash
ssh hiot
```
如果直接进入命令行，说明配置成功。

### 4.3 解决乱码问题
默认连接后，执行中文命令可能乱码。解决方案：
1.  **交互式**: 你的终端 (iTerm/Terminal) 通常能自动处理。
2.  **单行命令**: 强制分配 TTY (`-t`)。

```bash
# 正确姿势 (显示中文正常)
ssh -t hiot "dir C:\"

# 或者查看“嘎嘎”目录
ssh -t hiot "dir C:\Users\admin_ssh\prj"
```

---

## 5. 基于此通道的开发流程
现在我们拥有了完美的测试通道：

1.  **传文件**: `scp`
    ```bash
    scp wireguard.exe hiot:prj/
    ```
2.  **远程执行**: `ssh`
    ```bash
    ssh -t hiot "cd prj && wireguard.exe"
    ```

此环境为后续开发 Windows 版 WireGuard 客户端奠定了坚实基础。
