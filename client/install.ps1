<#
.SYNOPSIS
    Pulse Client Installation Script for Windows

.DESCRIPTION
    Downloads and installs the Pulse monitoring client on Windows.
    Can run as a background service using NSSM or as a scheduled task.

.PARAMETER AgentId
    The agent ID (must match server config)

.PARAMETER AgentName
    The agent display name (optional, defaults to AgentId)

.PARAMETER ServerBase
    The server base URL (e.g., http://your-server:8080)

.PARAMETER ClientPort
    The client port (default: 9090)

.PARAMETER Secret
    Secret for authentication (optional, if server requires it)

.EXAMPLE
    .\install.ps1 -AgentId "my-server-1" -ServerBase "http://monitor.example.com:8080"

.EXAMPLE
    # One-liner installation (run in PowerShell as Administrator):
    irm https://raw.githubusercontent.com/xhhcn/Pulse/main/client/install.ps1 | iex
#>

# Read from environment variables (for piped execution via irm | iex)
$script:AgentId = $env:AgentId
$script:AgentName = $env:AgentName
$script:ServerBase = $env:ServerBase
$script:ClientPort = if ($env:ClientPort) { $env:ClientPort } else { "9090" }
$script:Secret = $env:Secret

# Enable TLS 1.2 globally (required for GitHub on older Windows)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Configuration
$InstallDir = "$env:ProgramFiles\Pulse"
$ServiceName = "PulseClient"
$GitHubRepo = "https://raw.githubusercontent.com/xhhcn/Pulse/main/client"
$BinaryName = "probe-client.exe"

# Colors
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

function Write-Info($msg) { Write-Host "[INFO] " -ForegroundColor Cyan -NoNewline; Write-Host $msg }
function Write-Success($msg) { Write-Host "[SUCCESS] " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Write-Warn($msg) { Write-Host "[WARNING] " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Write-Err($msg) { Write-Host "[ERROR] " -ForegroundColor Red -NoNewline; Write-Host $msg }

# Print banner
function Show-Banner {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Blue
    Write-Host "║                  Pulse Client Installer                   ║" -ForegroundColor Blue
    Write-Host "║           Lightweight Server Monitoring Agent             ║" -ForegroundColor Blue
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Blue
    Write-Host ""
}

# Check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Prompt for required values
function Get-RequiredValues {
    if ([string]::IsNullOrEmpty($script:AgentId)) {
        $script:AgentId = Read-Host "Enter Agent ID (must match server config)"
        if ([string]::IsNullOrEmpty($script:AgentId)) {
            Write-Err "Agent ID is required"
            exit 1
        }
    }
    
    if ([string]::IsNullOrEmpty($script:ServerBase)) {
        $script:ServerBase = Read-Host "Enter Server URL (e.g., http://your-server:8080)"
        if ([string]::IsNullOrEmpty($script:ServerBase)) {
            Write-Err "Server URL is required"
            exit 1
        }
    }
    
    if ([string]::IsNullOrEmpty($script:AgentName)) {
        $script:AgentName = $script:AgentId
    }
}

# Download binary
function Get-Binary {
    Write-Info "Creating installation directory: $InstallDir"
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    
    $downloadUrl = "$GitHubRepo/$BinaryName"
    $outputPath = "$InstallDir\probe-client.exe"
    
    Write-Info "Downloading Pulse client from $downloadUrl..."
    
    try {
        # Use TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Use Invoke-WebRequest which handles redirects better than WebClient
        $ProgressPreference = 'SilentlyContinue'  # Speed up download by hiding progress bar
        Invoke-WebRequest -Uri $downloadUrl -OutFile $outputPath -UseBasicParsing
        
        if (Test-Path $outputPath) {
            $fileSize = (Get-Item $outputPath).Length
            if ($fileSize -gt 1000000) {  # Should be > 1MB
                Write-Success "Downloaded probe-client.exe ($([math]::Round($fileSize/1MB, 2)) MB)"
            } else {
                Write-Err "Downloaded file is too small, may be corrupted"
                exit 1
            }
        } else {
            Write-Err "Download failed - file not found"
            exit 1
        }
    }
    catch {
        Write-Err "Failed to download binary: $_"
        Write-Host ""
        Write-Host "Please try downloading manually from:" -ForegroundColor Yellow
        Write-Host "  $downloadUrl" -ForegroundColor Cyan
        Write-Host "And save to: $outputPath" -ForegroundColor Cyan
        exit 1
    }
}

# Add Windows Firewall rules to allow the client through
function Add-FirewallRule {
    Write-Info "Configuring Windows Firewall..."
    
    $exePath = "$InstallDir\probe-client.exe"
    $ruleName = "Pulse Monitoring Client"
    
    try {
        # Remove existing rules if any
        $existingRules = Get-NetFirewallRule -DisplayName "$ruleName*" -ErrorAction SilentlyContinue
        if ($existingRules) {
            $existingRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
            Write-Info "Removed existing firewall rules"
        }
        
        # Add inbound rule (allow connections to the client's metrics endpoint)
        New-NetFirewallRule -DisplayName "$ruleName (Inbound)" `
            -Direction Inbound `
            -Action Allow `
            -Program $exePath `
            -Profile Any `
            -Description "Allow inbound connections for Pulse monitoring client" `
            -ErrorAction Stop | Out-Null
        
        # Add outbound rule (allow client to connect to the server)
        New-NetFirewallRule -DisplayName "$ruleName (Outbound)" `
            -Direction Outbound `
            -Action Allow `
            -Program $exePath `
            -Profile Any `
            -Description "Allow outbound connections for Pulse monitoring client" `
            -ErrorAction Stop | Out-Null
        
        Write-Success "Firewall rules configured successfully"
    }
    catch {
        Write-Warn "Could not configure firewall automatically: $_"
        Write-Host "  You may need to manually allow probe-client.exe through the firewall" -ForegroundColor Yellow
    }
}

# Create log rotation script
function New-LogRotationScript {
    Write-Info "Creating log rotation script..."
    
    # Create logs directory
    $logsDir = "$InstallDir\logs"
    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    }
    
    # PowerShell log rotation script
    $rotationScript = @"
# Pulse Client Log Rotation Script
# This script manages log files to prevent disk space issues
`$LogDir = "$logsDir"
`$MaxLogSizeMB = 50
`$MaxLogFiles = 7
`$LogFile = Join-Path `$LogDir "pulse-client.log"

# Ensure log directory exists
if (-not (Test-Path `$LogDir)) {
    New-Item -ItemType Directory -Path `$LogDir -Force | Out-Null
}

# Rotate logs if current log is too large
if (Test-Path `$LogFile) {
    `$LogSize = (Get-Item `$LogFile).Length / 1MB
    if (`$LogSize -gt `$MaxLogSizeMB) {
        # Rotate existing logs
        for (`$i = `$MaxLogFiles - 1; `$i -gt 0; `$i--) {
            `$oldLog = Join-Path `$LogDir "pulse-client.log.`$i"
            `$newLog = Join-Path `$LogDir "pulse-client.log.`$(`$i + 1)"
            if (Test-Path `$oldLog) {
                if (`$i -eq (`$MaxLogFiles - 1)) {
                    Remove-Item `$oldLog -Force -ErrorAction SilentlyContinue
                } else {
                    Move-Item `$oldLog `$newLog -Force -ErrorAction SilentlyContinue
                }
            }
        }
        # Move current log to .1
        Move-Item `$LogFile (Join-Path `$LogDir "pulse-client.log.1") -Force -ErrorAction SilentlyContinue
    }
}

# Clean up old logs (keep only MaxLogFiles)
Get-ChildItem `$LogDir -Filter "pulse-client.log.*" -ErrorAction SilentlyContinue | 
    Sort-Object Name -Descending | 
    Select-Object -Skip `$MaxLogFiles | 
    Remove-Item -Force -ErrorAction SilentlyContinue
"@
    
    $rotationScriptPath = "$InstallDir\rotate-logs.ps1"
    Set-Content -Path $rotationScriptPath -Value $rotationScript -Encoding UTF8
    Write-Success "Created log rotation script: $rotationScriptPath"
}

# Create startup script with logging
function New-StartupScript {
    $scriptContent = @"
@echo off
cd /d "$InstallDir"
set AGENT_ID=$($script:AgentId)
set AGENT_NAME=$($script:AgentName)
set SERVER_BASE=$($script:ServerBase)
set CLIENT_PORT=$($script:ClientPort)
"@
    
    if (-not [string]::IsNullOrEmpty($script:Secret)) {
        $scriptContent += "`nset SECRET=$($script:Secret)"
    }
    
    # Add log rotation call and output redirection
    $scriptContent += @"

REM Rotate logs before starting
powershell -ExecutionPolicy Bypass -File "$InstallDir\rotate-logs.ps1"

REM Start client with logging (append mode)
probe-client.exe >> "$InstallDir\logs\pulse-client.log" 2>&1
"@
    
    $scriptPath = "$InstallDir\start-pulse.bat"
    Set-Content -Path $scriptPath -Value $scriptContent -Encoding ASCII
    Write-Success "Created startup script with logging: $scriptPath"
}

# Create scheduled task to run at startup
function New-ScheduledTaskService {
    Write-Info "Creating scheduled task for auto-start..."
    
    # Remove existing task if exists
    $existingTask = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    if ($existingTask) {
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false
        Write-Info "Removed existing scheduled task"
    }
    
    # Create the action
    $action = New-ScheduledTaskAction -Execute "$InstallDir\start-pulse.bat" -WorkingDirectory $InstallDir
    
    # Create trigger to run at startup
    $trigger = New-ScheduledTaskTrigger -AtStartup
    
    # Create principal to run as SYSTEM
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Create settings
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    
    # Register the task
    Register-ScheduledTask -TaskName $ServiceName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Pulse Monitoring Client" | Out-Null
    
    Write-Success "Created scheduled task: $ServiceName"
    
    # Start the task now
    Write-Info "Starting Pulse client..."
    Start-ScheduledTask -TaskName $ServiceName
    
    Write-Success "Pulse client started"
}

# Alternative: Start as background process
function Start-BackgroundProcess {
    Write-Info "Starting Pulse client as background process..."
    
    $env:AGENT_ID = $script:AgentId
    $env:AGENT_NAME = $script:AgentName
    $env:SERVER_BASE = $script:ServerBase
    $env:CLIENT_PORT = $script:ClientPort
    if (-not [string]::IsNullOrEmpty($script:Secret)) {
        $env:SECRET = $script:Secret
    }
    
    Start-Process -FilePath "$InstallDir\probe-client.exe" -WorkingDirectory $InstallDir -WindowStyle Hidden
    
    Write-Success "Pulse client started in background"
}

# Show status
function Show-Status {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "            Pulse Client Installed Successfully!           " -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "Configuration:"
    Write-Host "  Agent ID:    $($script:AgentId)"
    Write-Host "  Server:      $($script:ServerBase)"
    Write-Host "  Client Port:   $($script:ClientPort)"
    if (-not [string]::IsNullOrEmpty($script:Secret)) {
        $secretDisplay = if ($script:Secret.Length -ge 4) { 
            $script:Secret.Substring(0, 4) + "****" 
        } else { 
            "****" 
        }
        Write-Host "  Secret:      $secretDisplay (hidden)"
    }
    Write-Host "  Install Dir: $InstallDir"
    Write-Host ""
    Write-Host "Management Commands (run in PowerShell as Administrator):"
    Write-Host "  Check status:   Get-ScheduledTask -TaskName '$ServiceName'"
    Write-Host "  Start:          Start-ScheduledTask -TaskName '$ServiceName'"
    Write-Host "  Stop:           Stop-ScheduledTask -TaskName '$ServiceName'"
    Write-Host "  Restart:        Stop-ScheduledTask -TaskName '$ServiceName'; Start-ScheduledTask -TaskName '$ServiceName'"
    Write-Host "  View logs:      Get-Content '$InstallDir\logs\pulse-client.log' -Tail 50 -Wait"
    Write-Host ""
    Write-Host "Log Management:"
    Write-Host "  Logs are limited to 50MB per file, 7 files retention (~350MB total)"
    Write-Host "  Location:       $InstallDir\logs\"
    Write-Host "  Rotation:       Automatic on startup"
    Write-Host "  Manual rotate:  powershell -File '$InstallDir\rotate-logs.ps1'"
    Write-Host ""
    Write-Host "Uninstall:"
    Write-Host "  Stop-ScheduledTask -TaskName '$ServiceName' -ErrorAction SilentlyContinue"
    Write-Host "  Unregister-ScheduledTask -TaskName '$ServiceName' -Confirm:`$false -ErrorAction SilentlyContinue"
    Write-Host "  Remove-NetFirewallRule -DisplayName 'Pulse Monitoring Client*' -ErrorAction SilentlyContinue"
    Write-Host "  Remove-Item -Recurse -Force '$InstallDir' -ErrorAction SilentlyContinue"
    Write-Host ""
}

# Main
function Main {
    Show-Banner
    
    if (-not (Test-Administrator)) {
        Write-Err "Please run as Administrator"
        Write-Host "Right-click PowerShell and select 'Run as Administrator'"
        exit 1
    }
    
    Get-RequiredValues
    Get-Binary
    Add-FirewallRule
    New-LogRotationScript
    New-StartupScript
    New-ScheduledTaskService
    Show-Status
}

# Run main function
Main

