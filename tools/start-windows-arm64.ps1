[CmdletBinding()]
param(
    [string]$ChartRoot,
    [string]$BindAddress = "0.0.0.0",
    [ValidateRange(1, 65535)]
    [int]$Port = 27301,
    [string]$ApiBindAddress = "127.0.0.1",
    [ValidateRange(1, 65535)]
    [int]$ApiPort = 27302,
    [string]$ServerName = "TenRiff Ranked Server"
)

$ErrorActionPreference = "Stop"
$packageRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$server = Join-Path $packageRoot "tenriff-server.exe"
$verifier = Join-Path $packageRoot "tenriff-replay-verifier.exe"
$ncnn = Join-Path $packageRoot "ncnn.dll"
$model = Join-Path $packageRoot "models\ncnn\NK3-P64-hybrid.ncnn.param"
foreach ($required in @($server, $verifier, $ncnn, $model)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required ARM64 runtime file is missing: $required"
    }
}

if (-not $ChartRoot) {
    $ChartRoot = Join-Path $packageRoot "charts"
}
$ChartRoot = [System.IO.Path]::GetFullPath($ChartRoot)
$dataRoot = Join-Path $packageRoot "data"
$stagingRoot = Join-Path $dataRoot "replay-staging"
$secretRoot = Join-Path $packageRoot "secrets"
$secretFile = Join-Path $secretRoot "receipt-secret"
$excludeFile = Join-Path $packageRoot "catalog\excluded-charts.txt"
New-Item -ItemType Directory -Path $ChartRoot, $dataRoot, $stagingRoot, $secretRoot -Force |
    Out-Null

if (-not (Test-Path -LiteralPath $secretFile -PathType Leaf)) {
    $secret = New-Object byte[] 32
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($secret)
        [System.IO.File]::WriteAllBytes($secretFile, $secret)
    } finally {
        $generator.Dispose()
    }
}

$env:TENRIFF_NK3_BACKEND = "VULKAN"
$arguments = @(
    "--bind", $BindAddress,
    "--port", $Port,
    "--api-bind", $ApiBindAddress,
    "--api-port", $ApiPort,
    "--database", (Join-Path $dataRoot "tenriff.sqlite3"),
    "--receipt-secret-file", $secretFile,
    "--verifier", $verifier,
    "--replay-staging", $stagingRoot,
    "--chart-root", $ChartRoot,
    "--exclude-chart-file", $excludeFile,
    "--name", $ServerName
)

Write-Host "Starting native ARM64 TenRiff Server with forced ncnn Vulkan verification."
Write-Host "Charts: $ChartRoot"
& $server @arguments
exit $LASTEXITCODE
