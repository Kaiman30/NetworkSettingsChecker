$isAdmin = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n╔══════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║           ADMINISTRATOR PRIVILEGES REQUIRED      ║" -ForegroundColor Red
    Write-Host "║     Please run this script as Administrator!     ║" -ForegroundColor Red
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Red
    exit
}

Write-Host " -> Network Settings Checker by Kaiman4ik :3" -ForegroundColor DarkMagenta
Write-Host ""

# ═══════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════
$totalSteps = 14
$currentStep = 0
$results = @{
    Passed = @()
    Failed = @()
    BanRisks = @()
    Warnings = @()
}

function Update-Progress {
    param($stepName)
    $script:currentStep++
    $percent = [math]::Round(($script:currentStep / $totalSteps) * 100)
    Write-Progress -Activity "Scanning Network Settings" -Status $stepName -PercentComplete $percent
}

# ═══════════════════════════════════════════════════════════════════
# 1. DRIVER KEYS CHECK
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking Driver Keys..."
$adapterClassPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
$adapterKeys = Get-ChildItem -Path $adapterClassPath -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^.*\\\\[0-9]{4}$' }

$adapterChecks = @(
    @{ Name = "*NdisDeviceType"; Expected = 1 },
    @{ Name = "*JumboPacket"; Expected = 1514 }
)

foreach ($check in $adapterChecks) {
    $found = $false
    foreach ($adapter in $adapterKeys) {
        $val = Get-ItemProperty -Path $adapter.PSPath -Name $check.Name -ErrorAction SilentlyContinue
        if ($val -and $val.$($check.Name) -eq $check.Expected) { $found = $true; break }
    }
    if ($found) { $results.Passed += $check.Name } else { $results.Failed += $check.Name }
}

# ═══════════════════════════════════════════════════════════════════
# 2. TCP/IP GLOBAL PARAMETERS
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking TCP/IP Parameters..."
$tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"

$tcpChecks = @(
    @{ Name = "SackOpts"; Expected = 0 },
    @{ Name = "DisableTaskOffload"; Expected = 1 },
    @{ Name = "EnableWsd"; Expected = 0 },
    @{ Name = "Tcp1323Opts"; Expected = @(0,1) },
    @{ Name = "DefaultTTL"; Expected = 64 },
    @{ Name = "EnablePMTUDiscovery"; Expected = 0; BanRisk = $true },
    @{ Name = "EnablePMTUBHDetect"; Expected = 0; BanRisk = $true },
    @{ Name = "GlobalMaxTcpWindowSize"; Expected = "*"; BanRisk = $true },
    @{ Name = "TcpMaxDataRetransmissions"; Expected = "*"; BanRisk = $true }
)

foreach ($check in $tcpChecks) {
    $val = Get-ItemProperty -Path $tcpipPath -Name $check.Name -ErrorAction SilentlyContinue
    $result = $false
    
    if ($check.Expected -eq "*") {
        $result = $val -and $val.$($check.Name) -and $val.$($check.Name) -notin @(3,4,5,65535,64240)
    } elseif ($check.Expected -is [array]) {
        $result = $val -and $val.$($check.Name) -in $check.Expected
    } else {
        $result = $val -and $val.$($check.Name) -eq $check.Expected
    }
    
    if ($result) { 
        if ($check.BanRisk) { $results.BanRisks += $check.Name } else { $results.Passed += $check.Name }
    } else { 
        $results.Failed += $check.Name 
    }
}

# ═══════════════════════════════════════════════════════════════════
# 3. AFD PARAMETERS (UDP)
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking UDP Acceleration..."
$afdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"
$udpValue = Get-ItemProperty -Path $afdPath -Name "FastSendDatagramThreshold" -ErrorAction SilentlyContinue
if ($udpValue -and $udpValue.FastSendDatagramThreshold -in @(1500, 4096)) { 
    $results.BanRisks += "FastSendDatagramThreshold" 
} else { 
    $results.Failed += "FastSendDatagramThreshold" 
}

# ═══════════════════════════════════════════════════════════════════
# 4. SYSTEM PROFILE (Throttling)
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking System Throttling..."
$sysProfilePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"

$throttleValue = Get-ItemProperty -Path $sysProfilePath -Name "NetworkThrottlingIndex" -ErrorAction SilentlyContinue
if ($throttleValue -and $throttleValue.NetworkThrottlingIndex -eq 0xFFFFFFFF) { 
    $results.Passed += "NetworkThrottlingIndex" 
} else { 
    $results.Failed += "NetworkThrottlingIndex" 
}

$respValue = Get-ItemProperty -Path $sysProfilePath -Name "SystemResponsiveness" -ErrorAction SilentlyContinue
if ($respValue -and $respValue.SystemResponsiveness -eq 0) { 
    $results.Passed += "SystemResponsiveness" 
} elseif ($respValue -and $respValue.SystemResponsiveness -eq 100) {
    $results.Warnings += "SystemResponsiveness (100 - SABOTAGED!)"
} else { 
    $results.Failed += "SystemResponsiveness" 
}

# ═══════════════════════════════════════════════════════════════════
# 5. INTERFACE SETTINGS (Nagle/ACK)
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking Interface Settings..."
$interfacesPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
$interfaceKeys = Get-ChildItem -Path $interfacesPath -ErrorAction SilentlyContinue

$nagleChecks = @(
    @{ Name = "TCPNoDelay"; Expected = 1; BanRisk = $true },
    @{ Name = "TcpAckFrequency"; Expected = 1; BanRisk = $true },
    @{ Name = "TcpDelAckTicks"; Expected = 0; BanRisk = $true }
)

foreach ($check in $nagleChecks) {
    $found = $false
    foreach ($iface in $interfaceKeys) {
        $dhcpIP = (Get-ItemProperty -Path $iface.PSPath -Name "DhcpIPAddress" -ErrorAction SilentlyContinue).DhcpIPAddress
        $staticIP = (Get-ItemProperty -Path $iface.PSPath -Name "IPAddress" -ErrorAction SilentlyContinue).IPAddress
        if (-not $dhcpIP -and (-not $staticIP -or $staticIP[0] -eq "0.0.0.0")) { continue }
        
        $val = Get-ItemProperty -Path $iface.PSPath -Name $check.Name -ErrorAction SilentlyContinue
        if ($val -and $val.$($check.Name) -eq $check.Expected) { $found = $true; break }
    }
    if ($found) { 
        if ($check.BanRisk) { $results.BanRisks += $check.Name } else { $results.Passed += $check.Name }
    } else { 
        $results.Failed += $check.Name 
    }
}

# ═══════════════════════════════════════════════════════════════════
# 6. NETSH TCP GLOBAL
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking Netsh TCP Global..."
try {
    $netshOutput = netsh int tcp show global 2>$null | Out-String
    
    $netshChecks = @(
        @{ Pattern = "Состояние масштабирования на стороне приема.*enabled|Receive Window Auto-Tuning Level.*enabled"; Name = "Receive Scaling" },
        @{ Pattern = "Состояние объединения сегментов приема.*enabled|Receive Segment Coalescing State.*enabled"; Name = "RSC" },
        @{ Pattern = "Мощность ECN.*disabled|ECN Capability.*disabled"; Name = "ECN" }
    )
    
    foreach ($check in $netshChecks) {
        if ($netshOutput -match $check.Pattern) { 
            $results.Passed += $check.Name 
        } else { 
            $results.Failed += $check.Name 
        }
    }
} catch {
    $results.Warnings += "Netsh command failed"
}

# ═══════════════════════════════════════════════════════════════════
# 7. MSI-X MODE
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking MSI-X Mode..."
$pciPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\PCI"
$msiFound = $false

try {
    $pciDevices = Get-ChildItem -Path $pciPath -ErrorAction SilentlyContinue
    foreach ($device in $pciDevices) {
        $msiPath = "$($device.PSPath)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
        if (Test-Path $msiPath) {
            $msiValue = Get-ItemProperty -Path $msiPath -Name "MSISupported" -ErrorAction SilentlyContinue
            if ($msiValue -and $msiValue.MSISupported -eq 1) { $msiFound = $true; break }
        }
    }
} catch {}

if ($msiFound) { $results.Passed += "MSI-X Mode" } else { $results.Failed += "MSI-X Mode" }

# ═══════════════════════════════════════════════════════════════════
# 8. QOS BANDWIDTH
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Checking QoS Bandwidth..."
$qosPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
$qosValue = Get-ItemProperty -Path $qosPath -Name "NonBestEffortLimit" -ErrorAction SilentlyContinue

if ($qosValue -and $qosValue.NonBestEffortLimit -in @(80,90)) { 
    $results.Passed += "NonBestEffortLimit" 
} else { 
    $results.Failed += "NonBestEffortLimit" 
}

# ═══════════════════════════════════════════════════════════════════
# FINALIZE PROGRESS
# ═══════════════════════════════════════════════════════════════════
Update-Progress "Завершение..."
Start-Sleep -Milliseconds 300
Write-Progress -Activity "Сканирование настроек сети" -Completed

# ═══════════════════════════════════════════════════════════════════
# SUMMARY OUTPUT
# ═══════════════════════════════════════════════════════════════════
Clear-Host

Write-Host "`n╔═════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║              SUMMARY            ║" -ForegroundColor Cyan
Write-Host "╚═════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n  OPTIMIZED SETTINGS:" -ForegroundColor Green
if ($results.Passed.Count -gt 0) {
    foreach ($item in $results.Passed | Sort-Object) {
        Write-Host "    ✓ $item" -ForegroundColor Green
    }
} else {
    Write-Host "    None" -ForegroundColor DarkGray
}

Write-Host "`n  FAILED / DEFAULT SETTINGS:" -ForegroundColor Red
if ($results.Failed.Count -gt 0) {
    foreach ($item in $results.Failed | Sort-Object) {
        Write-Host "    ✗ $item" -ForegroundColor Red
    }
} else {
    Write-Host "    None" -ForegroundColor DarkGray
}

Write-Host "`n  ⚡ WARNINGS:" -ForegroundColor Yellow
if ($results.Warnings.Count -gt 0) {
    foreach ($item in $results.Warnings | Sort-Object) {
        Write-Host "    ! $item" -ForegroundColor Yellow
    }
} else {
    Write-Host "    None" -ForegroundColor DarkGray
}

$totalChecks = $results.Passed.Count + $results.Failed.Count
$passedCount = $results.Passed.Count
$failedCount = $results.Failed.Count

Write-Host "`n╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                        Отчет                               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`n  Провалено: " -NoNewline -ForegroundColor White
Write-Host "$passedCount" -ForegroundColor Red
Write-Host "  Пройдено: " -NoNewline -ForegroundColor White
Write-Host "$failedCount" -ForegroundColor Green

$scorePercent = if ($totalChecks -gt 0) { [math]::Round(($passedCount / $totalChecks) * 100) } else { 0 }
Write-Host "  Score: " -NoNewline -ForegroundColor White
Write-Host "$scorePercent%" -ForegroundColor $(if($scorePercent -ge 80){"Green"}elseif($scorePercent -ge 50){"Yellow"}else{"Red"})

Write-Host "`nПроверка выполнена" -ForegroundColor Cyan
