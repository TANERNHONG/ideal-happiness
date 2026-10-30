<#
Start the console when you sign in to Windows, without a window, and restart it if it stops.

    cd triage-console
    powershell -ExecutionPolicy Bypass -File autostart.ps1            # register (or update) the task
    powershell -ExecutionPolicy Bypass -File autostart.ps1 -Remove    # remove it

A Scheduled Task for your own account only ("Project DAD Console"), started at sign-in, no administrator rights.
It runs ..\.venv\Scripts\pythonw.exe -m service here; the service's output goes to var\service.log. It listens on
127.0.0.1:8765 as before. Stop a copy started by hand first: two copies cannot share the port.
#>
param([switch]$Remove)

$name = "Project DAD Console"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonw = Join-Path (Split-Path -Parent $here) ".venv\Scripts\pythonw.exe"

if ($Remove) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    "Removed: $name"
    return
}
if (-not (Test-Path $pythonw)) { throw "Not found: $pythonw (create the virtual environment first)" }

$action = New-ScheduledTaskAction -Execute $pythonw -Argument "-m service" -WorkingDirectory $here
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
"Registered: $name (starts at sign-in; output in var\service.log). Start it now with: Start-ScheduledTask -TaskName '$name'"
