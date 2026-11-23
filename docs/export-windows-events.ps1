<#
.SYNOPSIS
  Export Windows Security / System / PowerShell events to JSON for LogSentinel.

.DESCRIPTION
  Flattens each event's XML <EventData> into top-level fields
  (TargetUserName, IpAddress, LogonType, CommandLine, ScriptBlockText ...)
  so LogSentinel rules can match on them.

  Run from an elevated PowerShell prompt (reading the Security log needs admin):

    .\export-windows-events.ps1 -Hours 24 -OutFile C:\Temp\windows_security.json

  Then:  python -m logsentinel C:\Temp\windows_security.json --html report.html

  Tip: to get 4688 command lines and 4104 script blocks, enable
  "Include command line in process creation events" and
  "Turn on PowerShell Script Block Logging" in Group Policy.
#>
param(
    [int]$Hours = 24,
    [string]$OutFile = ".\windows_security.json"
)

$since = (Get-Date).AddHours(-$Hours)
$queries = @(
    @{ LogName = 'Security'; Id = 4624,4625,4648,4672,4688,4697,4720,4726,4728,4732,4740,4756,1102; StartTime = $since },
    @{ LogName = 'System'; Id = 7045; StartTime = $since },
    @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since }
)

$events = foreach ($q in $queries) {
    try {
        Get-WinEvent -FilterHashtable $q -ErrorAction Stop | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $row = [ordered]@{
                TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
                EventID     = $_.Id
                Computer    = $_.MachineName
            }
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $row[$d.Name] = $d.'#text' }
            }
            [pscustomobject]$row
        }
    } catch {
        Write-Warning "Skipping $($q.LogName): $($_.Exception.Message)"
    }
}

$events | ConvertTo-Json -Depth 4 | Out-File -Encoding utf8 $OutFile
Write-Host "Exported $(@($events).Count) events to $OutFile"
