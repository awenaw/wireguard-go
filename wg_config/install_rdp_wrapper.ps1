<#
.SYNOPSIS
    RDP Wrapper 自动安装脚本 (Auto-Installer)
    
.DESCRIPTION
    1. 配置 Windows Defender 排除项
    2. 下载 RDP Wrapper 1.6.2 安装包
    3. 下载最新的 rdpwrap.ini 配置文件 (适配 Win10 21H2)
    4. 安装并重启服务
#>

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\RDP Wrapper"
# 使用 sebaxakerhtc 的源，更新频率高，支持新版 Win10
$IniUrl = "https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/master/rdpwrap.ini"
$InstallerUrl = "https://github.com/stascorp/rdpwrap/releases/download/v1.6.2/RDPWInst.exe"

Write-Host "=== RDP Wrapper Auto-Installer ===" -ForegroundColor Cyan

# 1. 创建目录并添加 Defender 白名单 (关键!)
Write-Host "[1/5] Configuring Defender Exclusions..."
if (!(Test-Path $InstallDir)) { New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null }
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Write-Host "  Success: Folder added to Defender exclusion" -ForegroundColor Green
} catch {
    Write-Host "  Warning: Failed to add exclusion (Run as Admin?)" -ForegroundColor Yellow
}

# 2. 下载文件
Set-Location $InstallDir
Write-Host "[2/5] Downloading binaries..."
try {
    # 强制使用 TLS 1.2 (GitHub 需要)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    Write-Host "  Downloading RDPWInst.exe..."
    Invoke-WebRequest -Uri $InstallerUrl -OutFile "RDPWInst.exe" -UseBasicParsing
    
    Write-Host "  Downloading latest rdpwrap.ini..."
    Invoke-WebRequest -Uri $IniUrl -OutFile "rdpwrap.ini" -UseBasicParsing
    
    Write-Host "  Success: Files downloaded" -ForegroundColor Green
} catch {
    Write-Host "  Error: Download failed. Check network." -ForegroundColor Red
    Write-Host "  Details: $_"
    exit 1
}

# 3. 安装服务
Write-Host "[3/5] Installing RDP Wrapper..."
try {
    # -i: install, -o: online mode (try download ini, but we already have one)
    $proc = Start-Process -FilePath ".\RDPWInst.exe" -ArgumentList "-i" -PassThru -Wait
    if ($proc.ExitCode -eq 0) {
        Write-Host "  Success: Installation command executed" -ForegroundColor Green
    } else {
        Write-Host "  Warning: Installer exit code $($proc.ExitCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  Error: Installation failed: $_" -ForegroundColor Red
    exit 1
}

# 4. 覆盖配置 (因为安装程序可能会覆盖我们的 ini)
Write-Host "[4/5] Applying latest configuration..."
# 停止服务以解锁文件
Stop-Service termservice -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
# 再次下载/覆盖 ini 确保是新的
Invoke-WebRequest -Uri $IniUrl -OutFile "rdpwrap.ini" -UseBasicParsing
# 启动服务
Start-Service termservice -ErrorAction SilentlyContinue
Write-Host "  Success: Configuration applied" -ForegroundColor Green

# 5. 验证检查
Write-Host "[5/5] Verifying status..."
Start-Sleep -Seconds 3
Get-Service termservice | Select-Object Status, Name, DisplayName

Write-Host "`n=== Installation Complete ===" -ForegroundColor Cyan
Write-Host "Try checking with 'RDPConf.exe' if available, or just connect via RDP!"
