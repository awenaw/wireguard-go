<#
.SYNOPSIS
    RDP Wrapper 离线安装脚本 (Offline Installer)
    
.DESCRIPTION
    1. 配置 Windows Defender 排除项
    2. 使用当前目录下的文件进行安装
    3. 安装并重启服务
#>

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\RDP Wrapper"
$SourceDir = $PSScriptRoot  # 假设安装文件在脚本同级目录

Write-Host "=== RDP Wrapper Offline Installer ===" -ForegroundColor Cyan

# 1. 创建目录并添加 Defender 白名单
Write-Host "[1/4] Configuring Defender Exclusions..."
if (!(Test-Path $InstallDir)) { New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null }
try {
    Add-MpPreference -ExclusionPath $InstallDir -ErrorAction SilentlyContinue
    Write-Host "  Success: Folder added to Defender exclusion" -ForegroundColor Green
} catch {
    Write-Host "  Warning: Failed to add exclusion (Run as Admin?)" -ForegroundColor Yellow
}

# 2. 复制文件
Write-Host "[2/4] Copying files..."
try {
    Copy-Item -Path "$SourceDir\RDPWInst.exe" -Destination "$InstallDir\RDPWInst.exe" -Force
    Copy-Item -Path "$SourceDir\rdpwrap.ini" -Destination "$InstallDir\rdpwrap.ini" -Force
    Write-Host "  Success: Files copied to Program Files" -ForegroundColor Green
} catch {
    Write-Host "  Error: Failed to copy files. missing RDPWInst.exe or rdpwrap.ini in script dir?" -ForegroundColor Red
    exit 1
}

Set-Location $InstallDir

# 3. 安装服务
Write-Host "[3/4] Installing RDP Wrapper..."
try {
    # -i: install
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

# 4. 覆盖配置与重启
Write-Host "[4/4] Applying configuration..."
Stop-Service termservice -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
# 再次覆盖 ini 确保正确
Copy-Item -Path "$SourceDir\rdpwrap.ini" -Destination "$InstallDir\rdpwrap.ini" -Force
Start-Service termservice -ErrorAction SilentlyContinue
Write-Host "  Success: Service restarted" -ForegroundColor Green

Write-Host "`n=== Installation Complete ===" -ForegroundColor Cyan
Get-Service termservice | Select-Object Status, Name
