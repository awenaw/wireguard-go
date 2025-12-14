<#
.SYNOPSIS
    Windows RDP 并发会话环境配置脚本 (Pre-flight for RDP Wrapper)
    
.DESCRIPTION
    此脚本用于准备 Windows IoT 设备以支持并发 RDP 会话。
    它会配置注册表、防火墙，并输出 termsrv.dll 的版本信息以便匹配 RDP Wrapper 配置。
    注意：此脚本不包含 RDP Wrapper 二进制文件，仅做环境准备。

.NOTES
    运行环境: PowerShell (管理员权限)
    目标系统: Windows 10/11 IoT/Enterprise
#>

$ErrorActionPreference = "Stop"

Write-Host "=== Windows RDP 并发会话环境配置 ===" -ForegroundColor Cyan

# 1. 开启远程桌面 (RDP)
Write-Host "`n[1/4] 开启远程桌面服务..."
try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Write-Host "  Success: RDP 已开启" -ForegroundColor Green
} catch {
    Write-Host "  Error: 无法修改注册表，请确保以管理员身份运行" -ForegroundColor Red
    exit 1
}

# 2. 配置并发会话注册表项 (为 RDP Wrapper 做准备)
Write-Host "`n[2/4] 配置并发会话注册表项..."
$TSPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

# 允许并发连接
try {
    # 核心设置：每用户允许多个会话 (0 = 允许)
    # 注意：在未破解的 termsrv.dll 上此项可能无效，但必须先设置好
    New-ItemProperty -Path $TSPath -Name "fSingleSessionPerUser" -Value 0 -PropertyType DWORD -Force | Out-Null
    
    # 策略设置：最大连接数 (999999 = 无限制)
    if (!(Test-Path $PolicyPath)) { New-Item -Path $PolicyPath -Force | Out-Null }
    New-ItemProperty -Path $PolicyPath -Name "MaxInstanceCount" -Value 999999 -PropertyType DWORD -Force | Out-Null
    
    Write-Host "  Success: 注册表并发项已配置" -ForegroundColor Green
} catch {
    Write-Host "  Error: 注册表配置失败: $_" -ForegroundColor Red
}

# 3. 配置防火墙
Write-Host "`n[3/4] 配置防火墙允许 RDP (TCP 3389)..."
try {
    # 尝试启用内置规则组
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    
    # 双保险：添加显式规则
    New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  Success: 防火墙规则已添加" -ForegroundColor Green
} catch {
    Write-Host "  Warning: 防火墙配置遇到问题 (可能是由组策略管理)" -ForegroundColor Yellow
}

# 4. 检测 termsrv.dll 版本 (核心步骤)
Write-Host "`n[4/4] 检测 termsrv.dll 版本..."
$DllPath = "$env:SystemRoot\System32\termsrv.dll"
if (Test-Path $DllPath) {
    $Version = (Get-Item $DllPath).VersionInfo.FileVersion
    Write-Host "  Current Version: $Version" -ForegroundColor Yellow
    Write-Host "`n=== 下一步行动指南 ===" -ForegroundColor Cyan
    Write-Host "1. 您需要下载 RDP Wrapper (https://github.com/stascorp/rdpwrap/releases)"
    Write-Host "2. 使用配套的 rdpwrap.ini 覆盖配置"
    Write-Host "3. 确保 rdpwrap.ini 中包含 [$Version] 的 Patch 数据"
    Write-Host "4. 运行 'RDPWInst.exe -i' 安装服务"
} else {
    Write-Host "  Error: 找不到 termsrv.dll，系统可能异常" -ForegroundColor Red
}

Write-Host "`n配置完成。"
