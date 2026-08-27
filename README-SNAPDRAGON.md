# TenRiff Server on Snapdragon Windows

`TenRiff-Server-windows-arm64.zip` is a native Windows ARM64 package. It includes
the server, the matching TenRiff 1.5.1 Hotfix 4 replay verifier, ARM64 ncnn, and
the converted NK3 models.

The package uses the Snapdragon Adreno GPU through ncnn Vulkan. ncnn does not use
the Hexagon NPU. The server launcher forces `TENRIFF_NK3_BACKEND=VULKAN`, so a
missing or broken Vulkan driver does not silently turn a GPU check into CPU
success.

## Verify the GPU

Use an up-to-date Qualcomm graphics driver, then run this once after extracting
the archive:

```powershell
pwsh -File .\tools\test-snapdragon-gpu.ps1
```

The script verifies that the executables and ncnn DLL are ARM64, then runs the
bundled NK3 model with Vulkan forced. A pass is runtime evidence that this
machine can execute TenRiff's verifier model on its Vulkan GPU.

GitHub Actions verifies the native ARM64 build, server tests, and PE machine
types, but its ARM runner has no Snapdragon Adreno Vulkan device. Therefore the
package is not GPU-verified until this script passes on the target server.

## Start the server

Put BMS files under `charts/`, or pass a different folder, then run:

```powershell
pwsh -File .\tools\start-windows-arm64.ps1
pwsh -File .\tools\start-windows-arm64.ps1 -ChartRoot "D:\BMS"
```

The launcher creates `data/`, `secrets/receipt-secret`, and `charts/` when they
are missing. It listens for game traffic on TCP 27301 and keeps the account and
leaderboard API on `127.0.0.1:27302` by default. Put HTTPS in front of the API
before exposing it outside the machine.

GPU inference is used by the replay verifier while it reconstructs NK3 chart
conversion. Networking, SQLite, hashing, and other server work remain on CPU.
