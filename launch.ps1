# launch.ps1
# PoC: Netflix Audio Stream Exfiltration via CDP Network Interception
# Automates Chrome CDP setup, operator authentication, and narr invocation.
# Requires: Google Chrome, narr.exe, Windows 10/11, PowerShell 5.1+

$ErrorActionPreference = "SilentlyContinue"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$narrExe   = Join-Path $scriptDir "narr.exe"
$dlDir     = Join-Path $scriptDir "downloads"
$chromeExe = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$cdpPort   = 9222
$chromeProfile = "C:\narr-chrome-profile"
$batPath   = "$env:TEMP\cdp-chrome-launch.bat"

function Assert-ChromeCDP {
    # Check whether the CDP endpoint is alive on the configured port.
    # If unreachable, terminate any existing Chrome instances, relaunch via
    # the Windows Task Scheduler interactive session flag (/it) to ensure
    # the window appears on the interactive desktop, then poll until ready.
    try {
        Invoke-WebRequest -Uri "http://127.0.0.1:$cdpPort/json/version" -UseBasicParsing -TimeoutSec 2 | Out-Null
        return
    } catch {}

    Write-Host "[*] CDP endpoint down. Relaunching Chrome..." -ForegroundColor Yellow
    Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    # The intermediate .bat is required because schtasks /tr does not support
    # passing arguments with embedded quotes directly on some Windows builds.
    Set-Content -Path $batPath -Encoding ascii -Value (
        "@echo off`r`nstart `"`" `"$chromeExe`" " +
        "--remote-debugging-port=$cdpPort " +
        "--user-data-dir=`"$chromeProfile`" " +
        "--start-maximized"
    )

    schtasks /delete /tn "CDP_ChromeLaunch" /f 2>$null | Out-Null
    schtasks /create /tn "CDP_ChromeLaunch" /tr "`"$batPath`"" /sc once /st 00:00 /f /it 2>$null | Out-Null
    schtasks /run    /tn "CDP_ChromeLaunch" | Out-Null

    for ($i = 1; $i -le 25; $i++) {
        Start-Sleep -Seconds 1
        try {
            Invoke-WebRequest -Uri "http://127.0.0.1:$cdpPort/json/version" -UseBasicParsing -TimeoutSec 2 | Out-Null
            Write-Host "[+] Chrome CDP ready on port $cdpPort." -ForegroundColor Green
            return
        } catch {
            Write-Host "    Waiting for CDP... ($i/25)" -ForegroundColor DarkGray
        }
    }
    Write-Host "[!] Chrome CDP did not respond within timeout. Check manually." -ForegroundColor Red
}

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  Netflix Audio Stream Exfiltration PoC" -ForegroundColor White
    Write-Host "  Chrome DevTools Protocol Network Interception" -ForegroundColor DarkGray
    Write-Host "  2026 -- Independent Security Research" -ForegroundColor DarkGray
    Write-Host ""
}

# Validate prerequisites
Write-Banner

if (-not (Test-Path $narrExe)) {
    Write-Host "[!] narr.exe not found at: $scriptDir" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
if (-not (Test-Path $chromeExe)) {
    Write-Host "[!] Google Chrome not found at: $chromeExe" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

New-Item -ItemType Directory -Force -Path $dlDir | Out-Null

# Terminate any existing Chrome to ensure clean CDP attachment
$existing = Get-Process chrome -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[*] Terminating existing Chrome processes..." -ForegroundColor Yellow
    Stop-Process -Name chrome -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

# Launch Chrome in the operator's interactive desktop session
Write-Host "[*] Launching Chrome with CDP on port $cdpPort..." -ForegroundColor Cyan

Set-Content -Path $batPath -Encoding ascii -Value (
    "@echo off`r`nstart `"`" `"$chromeExe`" " +
    "--remote-debugging-port=$cdpPort " +
    "--user-data-dir=`"$chromeProfile`" " +
    "--start-maximized https://www.netflix.com/login"
)

schtasks /delete /tn "CDP_ChromeLaunch" /f 2>$null | Out-Null
schtasks /create /tn "CDP_ChromeLaunch" /tr "`"$batPath`"" /sc once /st 00:00 /f /it 2>$null | Out-Null
schtasks /run    /tn "CDP_ChromeLaunch" | Out-Null

# Poll CDP endpoint
for ($i = 1; $i -le 30; $i++) {
    Start-Sleep -Seconds 1
    try {
        $versionInfo = Invoke-WebRequest -Uri "http://127.0.0.1:$cdpPort/json/version" -UseBasicParsing -TimeoutSec 2
        $browser = ($versionInfo.Content | ConvertFrom-Json).Browser
        Write-Host "[+] CDP active: $browser" -ForegroundColor Green
        break
    } catch {
        Write-Host "    Waiting for CDP endpoint... ($i/30)" -ForegroundColor DarkGray
        if ($i -eq 30) {
            Write-Host "[!] CDP did not become available. Aborting." -ForegroundColor Red
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

Write-Host ""
Write-Host "[*] Authenticate to Netflix in the Chrome window that opened."
Write-Host "    The PoC does not handle or store credentials."
Write-Host "    Return here and press Enter once the session is active."
Write-Host ""
Read-Host "[press Enter when authenticated]"

# Target acquisition loop
Write-Host ""
Write-Host "[*] Ready. Paste a Netflix watch URL to begin interception."
Write-Host "    Type 'exit' to terminate." -ForegroundColor DarkGray
Write-Host ""

while ($true) {
    Write-Host "[target] " -ForegroundColor Cyan -NoNewline
    $target = (Read-Host).Trim()

    if ($target -eq "") { continue }
    if ($target -in "exit","quit","q") { break }
    if ($target -notlike "*netflix.com*") {
        Write-Host "[!] Input does not appear to be a Netflix URL. Retry." -ForegroundColor Yellow
        continue
    }

    Write-Host ""
    Write-Host "[*] Initiating CDP interception for target: $target" -ForegroundColor Cyan
    Write-Host "    Output directory: $dlDir" -ForegroundColor DarkGray
    Write-Host ""

    # Verify CDP is still alive before each invocation
    Assert-ChromeCDP

    # Invoke narr: attaches to CDP, navigates to target, intercepts audio segments
    & $narrExe $target $dlDir

    Write-Host ""
    Write-Host "[+] Captured files:" -ForegroundColor Green
    Get-ChildItem $dlDir -Filter "*.mp4a" | Sort-Object LastWriteTime -Descending | Select-Object -First 5 | ForEach-Object {
        $mb = [math]::Round($_.Length / 1MB, 2)
        Write-Host "    $($_.Name)  [$mb MB]" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "    Rename .mp4a to .m4a for standard media player compatibility." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  ----------------------------------------------------------------" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "[*] Session terminated. Output in: $dlDir" -ForegroundColor Green
Write-Host ""
schtasks /delete /tn "CDP_ChromeLaunch" /f 2>$null | Out-Null
Read-Host "Press Enter to close"
