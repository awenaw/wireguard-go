<#
.SYNOPSIS
    Windows RDP Concurrent Session Setup (English Version)
    
.DESCRIPTION
    Prepares Windows IoT for concurrent RDP sessions.
    - Enables RDP
    - Configures Registry for Multi-Session
    - Checks termsrv.dll version
#>

$ErrorActionPreference = "Stop"

Write-Host "=== Windows RDP Setup ===" -ForegroundColor Cyan

# 1. Enable RDP
Write-Host "[1/4] Enabling Remote Desktop..."
try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
    Write-Host "  Success: RDP Enabled" -ForegroundColor Green
} catch {
    Write-Host "  Error: Run as Admin required!" -ForegroundColor Red
    exit 1
}

# 2. Registry Config
Write-Host "[2/4] Configuring Registry..."
$TSPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$PolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"

try {
    # fSingleSessionPerUser = 0
    New-ItemProperty -Path $TSPath -Name "fSingleSessionPerUser" -Value 0 -PropertyType DWORD -Force | Out-Null
    
    # MaxInstanceCount = 999999
    if (!(Test-Path $PolicyPath)) { New-Item -Path $PolicyPath -Force | Out-Null }
    New-ItemProperty -Path $PolicyPath -Name "MaxInstanceCount" -Value 999999 -PropertyType DWORD -Force | Out-Null
    
    Write-Host "  Success: Registry Updated" -ForegroundColor Green
} catch {
    Write-Host "  Error: Registry Update Failed: $_" -ForegroundColor Red
}

# 3. Firewall
Write-Host "[3/4] Configuring Firewall..."
try {
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -LocalPort 3389 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-Host "  Success: Firewall Rules Added" -ForegroundColor Green
} catch {
    Write-Host "  Warning: Firewall config skipped" -ForegroundColor Yellow
}

# 4. Check DLL Version
Write-Host "[4/4] Checking termsrv.dll..."
$DllPath = "$env:SystemRoot\System32\termsrv.dll"
if (Test-Path $DllPath) {
    $Version = (Get-Item $DllPath).VersionInfo.FileVersion
    Write-Host "  Current termsrv.dll Version: $Version" -ForegroundColor Yellow
    Write-Host "  ACTION: Please download RDP Wrapper and match this version."
} else {
    Write-Host "  Error: termsrv.dll not found!" -ForegroundColor Red
}

Write-Host "Done."
