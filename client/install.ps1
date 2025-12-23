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

# Create startup script
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
    
    $scriptContent += "`nprobe-client.exe`n"
    
    $scriptPath = "$InstallDir\start-pulse.bat"
    Set-Content -Path $scriptPath -Value $scriptContent -Encoding ASCII
    Write-Success "Created startup script: $scriptPath"
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
    Write-Host ""
    Write-Host "Uninstall:"
    Write-Host "  Unregister-ScheduledTask -TaskName '$ServiceName' -Confirm:`$false"
    Write-Host "  Remove-Item -Recurse -Force '$InstallDir'"
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
    New-StartupScript
    New-ScheduledTaskService
    Show-Status
}

# Run main function
Main

