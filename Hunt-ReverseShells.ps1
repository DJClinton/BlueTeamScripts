<#
.SYNOPSIS
    Advanced Blue Team Threat Hunt - Behavioral Anomalies
.DESCRIPTION
    Scans for suspicious Parent-Child process relationships, Living off the Land
    binaries (LOLBins) making network connections, and malicious command-line arguments.
#>

$OverseerSubnet = "10.10.10."

# Expanded lists based on behavior, not just names
$LOLBins = @("rundll32.exe", "mshta.exe", "regsvr32.exe", "certutil.exe", "wscript.exe", "cscript.exe", "msbuild.exe")
$SuspiciousParents = @("w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe", "spoolsv.exe", "services.exe")
$Shells = @("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe")
$SusArgs = @("-enc", "bypass", "-w hidden", "DownloadString", "Invoke-", "IEX")

Function Write-Log($Message, $Color="White") {
    $Stamp = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$Stamp] $Message" -ForegroundColor $Color
}

Write-Log "=== Initiating Advanced Behavioral Sweep ===" "Cyan"
$ThreatsFound = 0

# Get all running processes with their command lines and parent IDs
$AllProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$ActiveConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

foreach ($Proc in $AllProcs) {
    $IsSuspicious = $false
    $FlagReason = @()

    $ProcName = $Proc.Name.ToLower()
    $CommandLine = $Proc.CommandLine
    
    # 1. PARENT-CHILD RELATIONSHIP CHECK
    # Find the parent process name
    $ParentProc = $AllProcs | Where-Object { $_.ProcessId -eq $Proc.ParentProcessId }
    if ($ParentProc) {
        $ParentName = $ParentProc.Name.ToLower()
        
        # If a web server or service account suddenly spawns a shell, that's a massive red flag (Web Shell)
        if ($ParentName -in $SuspiciousParents -and $ProcName -in $Shells) {
            $IsSuspicious = $true
            $FlagReason += "[Anomalous Parent-Child] $ParentName spawned $ProcName"
        }
    }

    # 2. MALICIOUS COMMAND LINE CHECK
    # Look for hidden windows, encoded strings, or memory execution
    if ($CommandLine) {
        foreach ($Arg in $SusArgs) {
            if ($CommandLine -match $Arg) {
                $IsSuspicious = $true
                $FlagReason += "[Suspicious Argument] Matched '$Arg'"
                break
            }
        }
    }

    # 3. LOLBIN NETWORK CONNECTION CHECK
    # Legitimate Windows binaries shouldn't usually be making random outbound connections
    if ($ProcName -in $LOLBins) {
        $AssociatedConns = $ActiveConnections | Where-Object { $_.OwningProcess -eq $Proc.ProcessId }
        foreach ($Conn in $AssociatedConns) {
            if ($Conn.RemoteAddress -notlike "$OverseerSubnet*" -and $Conn.RemoteAddress -ne "127.0.0.1") {
                $IsSuspicious = $true
                $FlagReason += "[LOLBin Network Activity] $ProcName connected to $($Conn.RemoteAddress)"
            }
        }
    }

    # 4. SVCHOST ANOMALY CHECK
    # svchost.exe should ALWAYS run with a "-k" flag. If it doesn't, it's likely an injected fake.
    if ($ProcName -eq "svchost.exe" -and $CommandLine -notmatch "-k") {
        $IsSuspicious = $true
        $FlagReason += "[Fake Svchost] Missing standard -k argument"
    }

    # REPORTING
    if ($IsSuspicious) {
        $ThreatsFound++
        Write-Log "----------------------------------------" "Red"
        Write-Log "WARNING: BEHAVIORAL ANOMALY DETECTED" "Red"
        Write-Log "Process Name : $ProcName (PID: $($Proc.ProcessId))" "White"
        Write-Log "Parent Name  : $($ParentName) (PID: $($Proc.ParentProcessId))" "White"
        Write-Log "Command Line : $CommandLine" "DarkGray"
        
        foreach ($Reason in $FlagReason) {
            Write-Log "Trigger      : $Reason" "Yellow"
        }

        # Show associated network traffic if any
        $NetTraffic = $ActiveConnections | Where-Object { $_.OwningProcess -eq $Proc.ProcessId }
        foreach ($Net in $NetTraffic) {
            Write-Log "Network      : $($Net.LocalAddress):$($Net.LocalPort) -> $($Net.RemoteAddress):$($Net.RemotePort)" "Magenta"
        }
    }
}

if ($ThreatsFound -eq 0) {
    Write-Log "Sweep complete. No behavioral anomalies detected." "Green"
} else {
    Write-Log "Sweep complete. Found $ThreatsFound potential threat(s)." "Red"
    Write-Log "Investigate the command lines and Parent PIDs immediately." "Yellow"
}
Write-Log "=======================================" "Cyan"<#
.SYNOPSIS
    Advanced Blue Team Threat Hunt - Behavioral Anomalies
.DESCRIPTION
    Scans for suspicious Parent-Child process relationships, Living off the Land
    binaries (LOLBins) making network connections, and malicious command-line arguments.
#>

$OverseerSubnet = "10.10.10."

# Expanded lists based on behavior, not just names
$LOLBins = @("rundll32.exe", "mshta.exe", "regsvr32.exe", "certutil.exe", "wscript.exe", "cscript.exe", "msbuild.exe")
$SuspiciousParents = @("w3wp.exe", "httpd.exe", "nginx.exe", "sqlservr.exe", "spoolsv.exe", "services.exe")
$Shells = @("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe")
$SusArgs = @("-enc", "bypass", "-w hidden", "DownloadString", "Invoke-", "IEX")

Function Write-Log($Message, $Color="White") {
    $Stamp = (Get-Date).ToString("HH:mm:ss")
    Write-Host "[$Stamp] $Message" -ForegroundColor $Color
}

Write-Log "=== Initiating Advanced Behavioral Sweep ===" "Cyan"
$ThreatsFound = 0

# Get all running processes with their command lines and parent IDs
$AllProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$ActiveConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

foreach ($Proc in $AllProcs) {
    $IsSuspicious = $false
    $FlagReason = @()

    $ProcName = $Proc.Name.ToLower()
    $CommandLine = $Proc.CommandLine
    
    # 1. PARENT-CHILD RELATIONSHIP CHECK
    # Find the parent process name
    $ParentProc = $AllProcs | Where-Object { $_.ProcessId -eq $Proc.ParentProcessId }
    if ($ParentProc) {
        $ParentName = $ParentProc.Name.ToLower()
        
        # If a web server or service account suddenly spawns a shell, that's a massive red flag (Web Shell)
        if ($ParentName -in $SuspiciousParents -and $ProcName -in $Shells) {
            $IsSuspicious = $true
            $FlagReason += "[Anomalous Parent-Child] $ParentName spawned $ProcName"
        }
    }

    # 2. MALICIOUS COMMAND LINE CHECK
    # Look for hidden windows, encoded strings, or memory execution
    if ($CommandLine) {
        foreach ($Arg in $SusArgs) {
            if ($CommandLine -match $Arg) {
                $IsSuspicious = $true
                $FlagReason += "[Suspicious Argument] Matched '$Arg'"
                break
            }
        }
    }

    # 3. LOLBIN NETWORK CONNECTION CHECK
    # Legitimate Windows binaries shouldn't usually be making random outbound connections
    if ($ProcName -in $LOLBins) {
        $AssociatedConns = $ActiveConnections | Where-Object { $_.OwningProcess -eq $Proc.ProcessId }
        foreach ($Conn in $AssociatedConns) {
            if ($Conn.RemoteAddress -notlike "$OverseerSubnet*" -and $Conn.RemoteAddress -ne "127.0.0.1") {
                $IsSuspicious = $true
                $FlagReason += "[LOLBin Network Activity] $ProcName connected to $($Conn.RemoteAddress)"
            }
        }
    }

    # 4. SVCHOST ANOMALY CHECK
    # svchost.exe should ALWAYS run with a "-k" flag. If it doesn't, it's likely an injected fake.
    if ($ProcName -eq "svchost.exe" -and $CommandLine -notmatch "-k") {
        $IsSuspicious = $true
        $FlagReason += "[Fake Svchost] Missing standard -k argument"
    }

    # REPORTING
    if ($IsSuspicious) {
        $ThreatsFound++
        Write-Log "----------------------------------------" "Red"
        Write-Log "WARNING: BEHAVIORAL ANOMALY DETECTED" "Red"
        Write-Log "Process Name : $ProcName (PID: $($Proc.ProcessId))" "White"
        Write-Log "Parent Name  : $($ParentName) (PID: $($Proc.ParentProcessId))" "White"
        Write-Log "Command Line : $CommandLine" "DarkGray"
        
        foreach ($Reason in $FlagReason) {
            Write-Log "Trigger      : $Reason" "Yellow"
        }

        # Show associated network traffic if any
        $NetTraffic = $ActiveConnections | Where-Object { $_.OwningProcess -eq $Proc.ProcessId }
        foreach ($Net in $NetTraffic) {
            Write-Log "Network      : $($Net.LocalAddress):$($Net.LocalPort) -> $($Net.RemoteAddress):$($Net.RemotePort)" "Magenta"
        }
    }
}

if ($ThreatsFound -eq 0) {
    Write-Log "Sweep complete. No behavioral anomalies detected." "Green"
} else {
    Write-Log "Sweep complete. Found $ThreatsFound potential threat(s)." "Red"
    Write-Log "Investigate the command lines and Parent PIDs immediately." "Yellow"
}
Write-Log "=======================================" "Cyan"
