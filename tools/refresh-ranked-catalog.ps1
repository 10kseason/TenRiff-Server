[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ChartRoot,

    [string]$OutputPath = (Join-Path $PSScriptRoot '..\catalog\generated-bms-catalog.txt'),

    [string]$ExcludedChartFile = (Join-Path $PSScriptRoot '..\catalog\excluded-charts.txt')
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $ChartRoot).Path.TrimEnd('\', '/')
$output = [System.IO.Path]::GetFullPath($OutputPath)
$extensions = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
foreach ($extension in '.bms', '.bme', '.bml', '.pms') {
    [void]$extensions.Add($extension)
}

$excluded = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
if (Test-Path -LiteralPath $ExcludedChartFile) {
    $lineNumber = 0
    foreach ($rawLine in [System.IO.File]::ReadLines(
            [System.IO.Path]::GetFullPath($ExcludedChartFile))) {
        $lineNumber++
        $line = ($rawLine -split '#', 2)[0].Trim()
        if (-not $line) { continue }
        if ($line -notmatch '^[0-9a-fA-F]{64}$') {
            throw "Invalid SHA-256 in exclusion file at line $lineNumber."
        }
        [void]$excluded.Add($line)
    }
}

$files = Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction Stop |
    Where-Object { $extensions.Contains($_.Extension) }

$entries = $files | ForEach-Object -Parallel {
    $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    $relative = [System.IO.Path]::GetRelativePath($using:root, $_.FullName).Replace('\', '/')
    [pscustomobject]@{
        Hash = $hash
        Path = "/charts/$relative"
    }
} -ThrottleLimit 4

$seen = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$lines = foreach ($entry in ($entries | Sort-Object Path)) {
    if ($excluded.Contains($entry.Hash) -or -not $seen.Add($entry.Hash)) { continue }
    "$($entry.Hash)=$($entry.Path)"
}

[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($output)) | Out-Null
[System.IO.File]::WriteAllLines(
    $output, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))

Write-Output "Wrote $($lines.Count) ranked BMS entries to $output ($($excluded.Count) exclusions loaded)."
