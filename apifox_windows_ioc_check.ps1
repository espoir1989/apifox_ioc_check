param(
    [int]$LogLookbackDays = 30,
    [int]$DnsLogMaxEvents = 4000,
    [ValidateSet("Auto", "UTF8", "GB2312", "GBK", "OEM", "Default")]
    [string]$OutputEncodingName = "Auto"
)

$ErrorActionPreference = "SilentlyContinue"

function Register-CodePageProvider {
    try {
        [System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
    } catch {
    }
}

function Resolve-TextEncoding {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $null
    }

    switch ($Name.ToUpperInvariant()) {
        "UTF8" {
            return New-Object System.Text.UTF8Encoding($false)
        }
        "GB2312" {
            try {
                return [System.Text.Encoding]::GetEncoding("GB2312")
            } catch {
            }
            try {
                return [System.Text.Encoding]::GetEncoding(936)
            } catch {
            }
            return $null
        }
        "GBK" {
            try {
                return [System.Text.Encoding]::GetEncoding(936)
            } catch {
            }
            return $null
        }
        "OEM" {
            try {
                return [System.Text.Encoding]::GetEncoding([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
            } catch {
            }
            return $null
        }
        "DEFAULT" {
            try {
                return [System.Text.Encoding]::Default
            } catch {
            }
            return $null
        }
        default {
            try {
                return [System.Text.Encoding]::GetEncoding($Name)
            } catch {
            }
            return $null
        }
    }
}

function Initialize-ConsoleEncoding {
    param([string]$PreferredName)

    Register-CodePageProvider

    $encoding = $null

    if ($PreferredName -and $PreferredName -ne "Auto") {
        $encoding = Resolve-TextEncoding -Name $PreferredName
    }

    if ($null -eq $encoding) {
        try {
            $ansiCodePage = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
            if ($ansiCodePage -eq 936) {
                $encoding = Resolve-TextEncoding -Name "GB2312"
            }
        } catch {
        }
    }

    if ($null -eq $encoding) {
        try {
            if ($null -ne [Console]::OutputEncoding) {
                $encoding = [Console]::OutputEncoding
            }
        } catch {
        }
    }

    if ($null -eq $encoding) {
        $encoding = New-Object System.Text.UTF8Encoding($false)
    }

    try {
        [Console]::InputEncoding = $encoding
    } catch {
    }

    try {
        [Console]::OutputEncoding = $encoding
    } catch {
    }

    try {
        Set-Variable -Name OutputEncoding -Scope Global -Value $encoding
    } catch {
    }

    return $encoding
}

$SelectedOutputEncoding = Initialize-ConsoleEncoding -PreferredName $OutputEncodingName
$ScriptVersion = "1.0"
$CompromiseStart = "2026-03-04"
$CompromiseEnd = "2026-03-22"
$Global:FindingCount = 0
$Global:RiskScore = 0

$IocRegex = 'apifox\.it\.com|/public/apifox-event\.js|/event/[02]/log|af_uuid|af_os|af_user|af_name|af_apifox_user|af_apifox_name|_rl_headers|_rl_mc|MIIEvQIBADANBgkqh|collectPreInformations|collectAddInformations'

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("== {0} ==" -f $Title)
}

function Write-Info {
    param([string]$Message)
    Write-Host ("[INFO] {0}" -f $Message)
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("[WARN] {0}" -f $Message)
}

function Add-Hit {
    param(
        [int]$Score,
        [string]$Message
    )
    $Global:FindingCount++
    $Global:RiskScore += $Score
    Write-Host ("[HIT] {0}" -f $Message)
}

function Write-IndentedLines {
    param([object[]]$Lines)
    foreach ($line in $Lines) {
        if ($null -ne $line -and "$line".Length -gt 0) {
            Write-Host ("    {0}" -f $line)
        }
    }
}

function Get-ExistingPaths {
    param([string[]]$Paths)
    $result = @()
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path)) {
            continue
        }
        if (Test-Path -LiteralPath $path) {
            $result += (Resolve-Path -LiteralPath $path).Path
        }
    }
    $result | Sort-Object -Unique
}

function Search-IocInPath {
    param(
        [string]$Path,
        [string]$Label
    )

    $matches = @()

    if (Test-Path -LiteralPath $Path -PathType Container) {
        $files = Get-ChildItem -LiteralPath $Path -File -Recurse -Force |
            Where-Object { $_.Length -lt 10MB } |
            Select-Object -First 400

        if ($files) {
            $matches = Select-String -Path $files.FullName -Pattern $IocRegex | Select-Object -First 20
        }
    } elseif (Test-Path -LiteralPath $Path -PathType Leaf) {
        $matches = Select-String -LiteralPath $Path -Pattern $IocRegex | Select-Object -First 20
    }

    if ($matches -and $matches.Count -gt 0) {
        Add-Hit -Score 3 -Message ("{0} 命中已知 IOC" -f $Label)
        $output = foreach ($m in $matches) {
            "{0}:{1}: {2}" -f $m.Path, $m.LineNumber, ($m.Line.Trim())
        }
        Write-IndentedLines -Lines $output
    }
}

function Search-IocInFile {
    param(
        [string]$Path,
        [string]$Label,
        [int]$Score
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return
    }

    $matches = Select-String -LiteralPath $Path -Pattern $IocRegex | Select-Object -First 10
    if ($matches -and $matches.Count -gt 0) {
        Add-Hit -Score $Score -Message $Label
        $output = foreach ($m in $matches) {
            "{0}:{1}: {2}" -f $m.Path, $m.LineNumber, ($m.Line.Trim())
        }
        Write-IndentedLines -Lines $output
    }
}

function Show-SystemInfo {
    Write-Section "系统信息"
    Write-Info ("脚本版本: {0}" -f $ScriptVersion)
    Write-Info ("当前时间: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"))
    Write-Info ("主机名: {0}" -f $env:COMPUTERNAME)
    Write-Info ("用户: {0}" -f $env:USERNAME)
    Write-Info ("系统: {0}" -f [System.Environment]::OSVersion.VersionString)
    if ($null -ne $SelectedOutputEncoding) {
        Write-Info ("控制台编码: {0} (CodePage={1})" -f $SelectedOutputEncoding.WebName, $SelectedOutputEncoding.CodePage)
    }
    Write-Info ("重点时间窗: {0} 至 {1}" -f $CompromiseStart, $CompromiseEnd)
}

function Check-ApifoxProcess {
    Write-Section "Apifox 进程"
    $procs = Get-Process | Where-Object { $_.ProcessName -match "(?i)apifox" }
    if ($procs) {
        Write-Warn "检测到 Apifox 相关进程仍在运行，建议先退出再继续处置"
        $lines = $procs | ForEach-Object {
            "{0} (PID={1})" -f $_.ProcessName, $_.Id
        }
        Write-IndentedLines -Lines $lines
    } else {
        Write-Info "当前未发现运行中的 Apifox 进程"
    }
}

function Get-ApifoxCandidatePaths {
    $paths = @(
        (Join-Path $env:APPDATA "Apifox"),
        (Join-Path $env:APPDATA "apifox"),
        (Join-Path $env:LOCALAPPDATA "Apifox"),
        (Join-Path $env:LOCALAPPDATA "apifox"),
        (Join-Path $env:LOCALAPPDATA "Programs\Apifox"),
        (Join-Path $env:APPDATA "Apifox\Local Storage"),
        (Join-Path $env:APPDATA "Apifox\Local Storage\leveldb"),
        (Join-Path $env:APPDATA "Apifox\User Data"),
        (Join-Path $env:APPDATA "Apifox\User Data\Default\Local Storage"),
        (Join-Path $env:APPDATA "Apifox\User Data\Default\Local Storage\leveldb"),
        (Join-Path $env:LOCALAPPDATA "Apifox\Local Storage"),
        (Join-Path $env:LOCALAPPDATA "Apifox\Local Storage\leveldb"),
        (Join-Path $env:LOCALAPPDATA "Apifox\User Data"),
        (Join-Path $env:LOCALAPPDATA "Apifox\User Data\Default\Local Storage"),
        (Join-Path $env:LOCALAPPDATA "Apifox\User Data\Default\Local Storage\leveldb")
    )

    Get-ExistingPaths -Paths $paths
}

function Check-ApifoxArtifacts {
    Write-Section "Apifox 本地痕迹"
    $paths = Get-ApifoxCandidatePaths

    if (-not $paths -or $paths.Count -eq 0) {
        Write-Warn "未发现明显的 Apifox 本地路径"
        return
    }

    Write-Info "发现以下 Apifox 相关路径:"
    Write-IndentedLines -Lines $paths

    foreach ($path in $paths) {
        Search-IocInPath -Path $path -Label $path
    }
}

function Check-PowerShellHistory {
    Write-Section "PowerShell 历史"
    $historyPath = Join-Path $env:APPDATA "Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path -LiteralPath $historyPath) {
        Search-IocInFile -Path $historyPath -Label "PowerShell 历史中出现 IOC 字符串" -Score 1
    } else {
        Write-Info "未发现 PowerShell 历史文件"
    }
}

function Check-DnsCache {
    Write-Section "DNS 痕迹"
    $dnsCache = Get-DnsClientCache | Where-Object { $_.Entry -match "apifox\.it\.com" }
    if ($dnsCache) {
        Add-Hit -Score 2 -Message "当前 DNS 缓存中存在 apifox.it.com"
        $lines = $dnsCache | Select-Object -First 10 | ForEach-Object {
            "{0} -> {1}" -f $_.Entry, $_.Data
        }
        Write-IndentedLines -Lines $lines
    } else {
        Write-Info "当前 DNS 缓存中未发现 apifox.it.com"
    }
}

function Check-DnsClientLogs {
    Write-Section "DNS 客户端日志"
    $startTime = (Get-Date).AddDays(-1 * $LogLookbackDays)
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Microsoft-Windows-DNS-Client/Operational"
        StartTime = $startTime
    } -MaxEvents $DnsLogMaxEvents | Where-Object {
        $_.Message -match "apifox\.it\.com"
    } | Select-Object -First 20

    if ($events) {
        Add-Hit -Score 2 -Message ("最近 {0} 天的 DNS 客户端日志命中 apifox.it.com" -f $LogLookbackDays)
        $lines = $events | ForEach-Object {
            "{0}: {1}" -f $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"), (($_.Message -replace "`r?`n", " ") -replace "\s+", " ").Trim()
        }
        Write-IndentedLines -Lines $lines
    } else {
        Write-Info ("最近 {0} 天的 DNS 客户端日志中未发现命中" -f $LogLookbackDays)
    }
}

function Check-RunKeysAndStartup {
    Write-Section "启动项与 Run 键"

    $runKeyPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    $runHits = @()
    foreach ($keyPath in $runKeyPaths) {
        if (-not (Test-Path -LiteralPath $keyPath)) {
            continue
        }

        $item = Get-ItemProperty -LiteralPath $keyPath
        foreach ($prop in $item.PSObject.Properties) {
            if ($prop.Name -in @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                continue
            }
            $value = [string]$prop.Value
            if ($value -match $IocRegex) {
                $runHits += ("{0} -> {1} = {2}" -f $keyPath, $prop.Name, $value)
            }
        }
    }

    $startupPaths = Get-ExistingPaths -Paths @(
        (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"),
        (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup")
    )

    $startupHits = @()
    foreach ($startupPath in $startupPaths) {
        $files = Get-ChildItem -LiteralPath $startupPath -File -Recurse -Force | Select-Object -First 50
        foreach ($file in $files) {
            if ($file.Name -match "(?i)apifox|event|log" -or (Select-String -LiteralPath $file.FullName -Pattern $IocRegex | Select-Object -First 1)) {
                $startupHits += $file.FullName
            }
        }
    }

    if ($runHits.Count -gt 0 -or $startupHits.Count -gt 0) {
        Add-Hit -Score 3 -Message "启动项或 Run 键中出现可疑 IOC，需优先人工核查"
        Write-IndentedLines -Lines ($runHits + $startupHits | Select-Object -First 20)
    } else {
        Write-Info "未在启动项或 Run 键中发现 IOC 字符串"
    }
}

function Check-HighValueCredentialFootprint {
    Write-Section "高价值凭证痕迹"
    $targets = @(
        (Join-Path $env:USERPROFILE ".ssh"),
        (Join-Path $env:USERPROFILE ".git-credentials"),
        (Join-Path $env:USERPROFILE ".kube\config"),
        (Join-Path $env:USERPROFILE ".npmrc"),
        (Join-Path $env:USERPROFILE ".aws\credentials"),
        (Join-Path $env:USERPROFILE ".config\gh\hosts.yml")
    )

    $existing = Get-ExistingPaths -Paths $targets
    if ($existing.Count -gt 0) {
        Write-Warn "主机上存在高价值凭证或访问配置，若处于风险时间窗内建议直接轮换"
        Write-IndentedLines -Lines $existing
    } else {
        Write-Info "未发现常见的高价值凭证文件路径"
    }
}

function Show-Summary {
    Write-Section "结果汇总"
    Write-Info ("命中项数量: {0}" -f $Global:FindingCount)
    Write-Info ("风险分值: {0}" -f $Global:RiskScore)

    if ($Global:RiskScore -ge 6) {
        Write-Warn "结论: 高风险，建议视为已受影响主机进行处置"
    } elseif ($Global:RiskScore -ge 3) {
        Write-Warn "结论: 中风险，建议立即人工复核并按受影响主机处理凭证"
    } elseif ($Global:RiskScore -ge 1) {
        Write-Warn "结论: 低风险，但存在可疑痕迹，需要结合使用记录判断"
    } else {
        Write-Info "结论: 未发现直接 IOC"
    }

    Write-Host ""
    Write-Host "处置建议:"
    Write-Host "  1. 如果你在 2026-03-04 至 2026-03-22 期间启动过 Apifox 桌面端，即使脚本未命中，也建议轮换 SSH、Git、Kubernetes、npm、云平台等凭证。"
    Write-Host "  2. 如果命中 _rl_headers/_rl_mc、apifox.it.com 或 /event/0/log 等 IOC，优先停用该主机上的相关密钥并审计服务器登录日志。"
    Write-Host "  3. 本脚本主要覆盖本地痕迹、DNS 痕迹和基础持久化痕迹；若攻击者已投放独立后门，仍需配合 EDR、网络日志和启动项审计。"
}

if (-not $IsWindows -and -not ($env:OS -eq "Windows_NT")) {
    Write-Host "该脚本仅支持 Windows。"
    exit 1
}

Show-SystemInfo
Check-ApifoxProcess
Check-ApifoxArtifacts
Check-PowerShellHistory
Check-DnsCache
Check-DnsClientLogs
Check-RunKeysAndStartup
Check-HighValueCredentialFootprint
Show-Summary
