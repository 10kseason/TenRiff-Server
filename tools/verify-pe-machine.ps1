param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [ValidateSet("X64", "ARM64")]
    [string]$ExpectedMachine = "ARM64"
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path -LiteralPath $Path).Path
$bytes = [System.IO.File]::ReadAllBytes($resolved)
if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw "Not a PE executable: $resolved"
}

$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length -or
    $bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45 -or
    $bytes[$peOffset + 2] -ne 0 -or $bytes[$peOffset + 3] -ne 0) {
    throw "Invalid PE header: $resolved"
}

$expected = if ($ExpectedMachine -eq "ARM64") { 0xaa64 } else { 0x8664 }
$actual = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
if ($actual -ne $expected) {
    throw ("Unexpected PE machine 0x{0:x4}; expected {1} in {2}" -f
        $actual, $ExpectedMachine, $resolved)
}

Write-Host ("Verified {0}: {1} (0x{2:x4})" -f $ExpectedMachine, $resolved, $actual)
