#Requires -RunAsAdministrator
# === CONFIG ===
$SysmonExe       = .\"sysmon64.exe"          # Your file name
$SysmonConfig    = .\"sysmon-config.xml"

# === FUNCTIONS ===
function Clean-Splunk-Registry {
    Write-Host "Cleaning Splunk registry..." -ForegroundColor Gray
    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products",
        "HKLM:\SOFTWARE\Classes\Installer\Products",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKCU:\SOFTWARE\Microsoft\Installer\Products"
    )
    foreach ($key in $keys) {
        Get-ChildItem $key -ErrorAction SilentlyContinue | Where-Object {
            $_.PSChildName -match "splunk" -or ($_.GetValue("DisplayName") -like "*Splunk*")
        } | ForEach-Object { Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Stop-Splunk {
    $exe = "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe"
    if (Test-Path $exe) { & $exe stop --accept-license --answer-yes --no-prompt 2>$null; Start-Sleep 5 }
    Stop-Service "SplunkForwarder" -Force -ErrorAction SilentlyContinue
    Get-Process splunk* -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}

function Start-Splunk {
    $exe = "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe"
    if (Test-Path $exe) {
        & $exe start --accept-license --answer-yes --no-prompt
        $i = 0
        do { Start-Sleep 1; $i++; $svc = Get-Service "SplunkForwarder" -ErrorAction SilentlyContinue }
        until ($svc.Status -eq "Running" -or $i -ge 30)
        if ($svc.Status -eq "Running") { Write-Host "SplunkForwarder service started." -ForegroundColor Green }
        else { Write-Host "Service failed to start." -ForegroundColor Yellow }
    }
}

function Get-CurrentUF {
    $exe = "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe"
    if (Test-Path $exe) { return (Get-Item $exe).VersionInfo.FileVersion }
    return $null
}

function Uninstall-Splunk {
    Stop-Splunk
    $p = Start-Process "msiexec.exe" -ArgumentList "/x `"$SplunkMSI`" /quiet /norestart REMOVE_FROM_GROUPS=1 /l*v `"$log`"" -Wait -PassThru
    if ($p.ExitCode -in 0,1605) { Write-Host "Uninstalled." -ForegroundColor Green }
    else { Write-Host "Uninstall failed (code $($p.ExitCode))." -ForegroundColor Red }
    Clean-Splunk-Registry
    Remove-Item "$env:ProgramFiles\SplunkUniversalForwarder" -Recurse -Force -ErrorAction SilentlyContinue
}

function Restart-Splunk {
    # Stop everything first
    Stop-Splunk

    # Small delay to make sure everything is really dead
    Start-Sleep -Seconds 3

    # Start it again
    $exe = "$env:ProgramFiles\SplunkUniversalForwarder\bin\splunk.exe"
    if (Test-Path $exe) {
        Write-Host "Starting Splunk service..." -ForegroundColor Gray
        & $exe start --accept-license --answer-yes --no-prompt

        # Wait until service is running
        $timeout = 30
        $i = 0
        do {
            Start-Sleep 1
            $i++
            $svc = Get-Service "SplunkForwarder" -ErrorAction SilentlyContinue
        } until ($svc.Status -eq "Running" -or $i -ge $timeout)

        if ($svc.Status -eq "Running") {
            Write-Host "SPLUNK RESTARTED SUCCESSFULLY!" -ForegroundColor Green
        } else {
            Write-Host "Service failed to start within $timeout seconds." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Splunk not installed or binary not found!" -ForegroundColor Red
    }

}

function Upgrade-Splunk {
    $current = Get-CurrentUF
    if (-not $current) { Install-Splunk }
    Stop-Splunk
    $p = Start-Process "msiexec.exe" -ArgumentList "/i `"$SplunkMSI`" /quiet /norestart AGREETOLICENSE=Yes /l*v `"$log`"" -Wait -PassThru
    if ($p.ExitCode -eq 1603) {  
        Start-Splunk
        break
    }
    if ($p.ExitCode -eq 0) { 
        Start-Splunk
    }
}

function Install-Splunk {
    # Installation
    msiexec.exe -ArgumentList $msiArgs -PassThru -Wait
    Start-Service SplunkForwarder
    Install-Sysmon
 }

function Install-Sysmon {
    # === UNINSTALL ===
    $possibleNames = @("sysmon64.exe", "Sysmon64.exe", "sysmon.exe", "Sysmon.exe", "svcrm.exe")
    $found = $false
    foreach ($name in $possibleNames) {
        $path = "$env:SystemRoot\$name"
        if (Test-Path $path) {
            $found = $true
            try {
                $proc = Start-Process -FilePath $path -ArgumentList "-u", "force" -Wait -PassThru -WindowStyle Hidden
                if ($proc.ExitCode -eq 0) { Write-Host "Driver uninstalled." -ForegroundColor Green }
                else { Write-Host "Uninstall code: $($proc.ExitCode)" -ForegroundColor Yellow }
            } catch { Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red }
            Start-Sleep 2
            Remove-Item $path -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $found) { Write-Host "No previous Sysmon found." -ForegroundColor Gray }

    # === INSTALL NEW SYSMON64.EXE ===
    $target = "$env:SystemRoot\sysmon64.exe"
    Copy-Item $SysmonExe $target -Force

    $p = Start-Process -FilePath $target -ArgumentList "-accepteula -i `"$SysmonConfig`"" -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -eq 0) {
        Sleep 3
	Restart-Splunk
    } else {
        Write-Host "Install failed (code $($p.ExitCode))" -ForegroundColor Red
    }
    Pause-Msg
}

    # === SET AUDIT POLICIES ===
   function Enable-FullAuditPolicies {
        Start-Sleep 2

    $auditpolCommands = @(
        '/set /category:"Account Logon" /success:enable /failure:enable',
        '/set /subcategory:"User Account Management" /success:enable /failure:enable',
        '/set /subcategory:"Computer Account Management" /success:enable /failure:enable',
        '/set /subcategory:"Security Group Management" /success:enable /failure:enable',
        '/set /subcategory:"Process Creation" /success:enable',
        '/set /subcategory:"Plug and Play Events" /success:enable /failure:enable',
        '/set /subcategory:"Directory Service Access" /success:enable /failure:disable',
        '/set /subcategory:"Account Lockout" /success:enable /failure:enable',
        '/set /subcategory:"User / Device Claims" /success:enable /failure:enable',
        '/set /subcategory:"Logon" /success:enable /failure:enable',
        '/set /subcategory:"Logoff" /success:enable /failure:enable',
        '/set /subcategory:"Special Logon" /success:enable /failure:enable',
        '/set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable',
        '/set /subcategory:"File Share" /success:enable /failure:enable',
        '/set /subcategory:"Other Object Access Events" /success:enable /failure:disable',
        '/set /subcategory:"SAM" /success:enable',
        '/set /subcategory:"Security State Change" /success:enable /failure:enable',
        '/set /subcategory:"Security System Extension" /success:enable /failure:enable',
        '/set /subcategory:"Other Object Access Events" /success:enable /failure:enable',
        '/set /subcategory:"Audit Policy Change" /success:enable /failure:Disable',
        '/set /subcategory:"Authentication Policy Change" /success:enable /failure:Disable',
        '/set /subcategory:"Authorization Policy Change" /success:enable /failure:Disable',
        '/set /subcategory:"Detailed File Share" /success:enable /failure:enable',
        '/set /subcategory:"Security Group Management" /success:enable /failure:enable',
        '/set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable',
        '/set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable',
        '/set /subcategory:"Computer Account Management" /success:enable /failure:enable',
        '/set /subcategory:"Group Membership" /success:enable /failure:enable',
        '/set /subcategory:"Directory Service Access" /success:enable',
        '/set /subcategory:"Handle Manipulation" /success:enable',
        '/set /subcategory:"Credential Validation" /failure:enable',
        '/set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable',
        '/set /subcategory:"MPSSVC rule-level policy change" /success:enable',
        '/set /subcategory:"Filtering Platform policy change" /success:enable',
        '/set /subcategory:"Removable Storage" /success:enable'
    )

    foreach ($cmd in $auditpolCommands) {
        auditpol $cmd.Split(" ") | Out-Null
    }

    # Enable extra event logs
    wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true
    wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true

    # PowerShell Script Block Logging + Module Logging + CmdLine in ProcCreation
    REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
    REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockInvocationLogging /t REG_DWORD /d 1 /f
    REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
    REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f
    REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
}

function Get-CurrentSysmon {
    $paths = "$env:SystemRoot\sysmon64.exe", "$env:SystemRoot\Sysmon64.exe", "$env:SystemRoot\sysmon.exe", "$env:SystemRoot\svcrm.exe"
    foreach ($p in $paths) { if (Test-Path $p) { return (Get-Item $p).VersionInfo.FileVersion } }
    return $null
}

function Check-Sysmon {
    $ver = Get-CurrentSysmon
    $svc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service "Sysmon" -ErrorAction SilentlyContinue }
    if ($ver) {
        Write-Host "SYSMON: v$ver" -ForegroundColor Green
        if ($svc) { Write-Host " Service: $($svc.Status)" -ForegroundColor $(if($svc.Status -eq "Running"){"Green"}else{"Yellow"}) }
        else { Write-Host " Service: NOT FOUND" -ForegroundColor Red }
    } else { Write-Host "SYSMON: NOT INSTALLED" -ForegroundColor Red }
}

function Check-Splunk {
    $ver = Get-CurrentUF
    $svc = Get-Service "SplunkForwarder" -ErrorAction SilentlyContinue
    if ($ver) {
        Write-Host "SPLUNK UF: v$ver" -ForegroundColor Green
        if ($svc) { Write-Host " Service: $($svc.Status)" -ForegroundColor $(if($svc.Status -eq "Running"){"Green"}else{"Yellow"}) }
        else { Write-Host " Service: NOT FOUND" -ForegroundColor Red }
    } else { Write-Host "SPLUNK UF: NOT INSTALLED" -ForegroundColor Red }
}