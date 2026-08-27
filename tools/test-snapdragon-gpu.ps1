param()

$ErrorActionPreference = "Stop"
$packageRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$smoke = Join-Path $packageRoot "nk3_onnx_smoke.exe"
$verifier = Join-Path $packageRoot "tenriff-replay-verifier.exe"
$ncnn = Join-Path $packageRoot "ncnn.dll"

foreach ($path in @($smoke, $verifier, $ncnn)) {
    & (Join-Path $PSScriptRoot "verify-pe-machine.ps1") `
        -Path $path -ExpectedMachine ARM64
}

$env:TENRIFF_NK3_BACKEND = "VULKAN"
Write-Host "Running NK3 with VULKAN forced. CPU fallback is disabled for this check."
& $smoke
if ($LASTEXITCODE -ne 0) {
    throw "Snapdragon Vulkan smoke failed with exit code $LASTEXITCODE. Update the Qualcomm graphics driver and retry."
}
Write-Host "Snapdragon ARM64 ncnn Vulkan smoke passed."
