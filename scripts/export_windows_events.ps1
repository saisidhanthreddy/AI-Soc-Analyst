# Export Windows logon events (4624 success, 4625 failure) to JSON for the SOC agent.
# Run from an ADMIN PowerShell (reading the Security log needs admin rights):
#   powershell -ExecutionPolicy Bypass -File scripts\export_windows_events.ps1 -Hours 24
param(
    [int]$Hours = 24,
    [int]$MaxEvents = 5000,
    [string]$Out = "data\windows_security_live.json"
)

$filter = @{ LogName = 'Security'; Id = 4624, 4625; StartTime = (Get-Date).AddHours(-$Hours) }

try {
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
} catch {
    Write-Host "No events found or access denied. Run PowerShell as Administrator." -ForegroundColor Yellow
    exit 1
}

$rows = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $d = @{}
    foreach ($item in $xml.Event.EventData.Data) { $d[$item.Name] = $item.'#text' }
    [pscustomobject]@{
        EventID         = $e.Id
        TimeCreated     = $e.TimeCreated.ToUniversalTime().ToString('o')
        TargetUserName  = $d['TargetUserName']
        IpAddress       = $d['IpAddress']
        LogonType       = $d['LogonType']
        WorkstationName = $d['WorkstationName']
        Computer        = $e.MachineName
    }
}

New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
@($rows) | ConvertTo-Json -Depth 3 | Out-File -Encoding utf8 $Out
Write-Host "Wrote $(@($rows).Count) events to $Out"
