<#
.SYNOPSIS
    Exports Windows Security events into the CSV schema LogSentry expects.
.DESCRIPTION
    Reads the Security log with Get-WinEvent and writes the fields LogSentry
    parses. Run this on a host you administer, then feed the CSV to LogSentry
    with --windows-csv. Read-only. It only reads the event log.
.PARAMETER Hours
    How many hours back to collect. Default 24.
.PARAMETER OutputPath
    Where to write the CSV. Default .\security-events.csv.
.EXAMPLE
    .\Export-SecurityEvents.ps1 -Hours 24 -OutputPath C:\Temp\sec.csv
#>
[CmdletBinding()]
param(
    [int]$Hours = 24,
    [string]$OutputPath = '.\security-events.csv'
)

$ids = 4625, 4624, 4740, 4672, 4728, 4732, 4756, 1102
$start = (Get-Date).AddHours(-1 * $Hours)

Write-Host "Collecting Security events from the last $Hours hours."
$events = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $start } -ErrorAction SilentlyContinue

$rows = foreach ($e in $events) {
    $x = [xml]$e.ToXml()
    $data = @{}
    foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    [pscustomobject]@{
        TimeCreated    = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        EventId        = $e.Id
        Computer       = $e.MachineName
        TargetAccount  = $data['TargetUserName']
        SubjectAccount = $data['SubjectUserName']
        IpAddress      = $data['IpAddress']
        LogonType      = $data['LogonType']
        GroupName      = $data['TargetGroupName']
        Message        = ($e.Message -split "`r?`n")[0]
    }
}

$rows | Sort-Object TimeCreated | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "Wrote $($rows.Count) events to $OutputPath"
