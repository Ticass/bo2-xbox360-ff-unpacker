$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Tools = Join-Path $Root "tools"
$OutDir = Join-Path $Root "_tools"
$OutExe = Join-Path $OutDir "xmem_lzx_decompress.exe"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if ($Cl) {
    Push-Location $Root
    try {
        & cl.exe /nologo /O2 /I"$Tools" /Fe"$OutExe" `
            "$Tools\xmem_lzx_decompress.c" "$Tools\lzx.c"
    }
    finally {
        Pop-Location
    }
    if (-not (Test-Path $OutExe)) {
        throw "cl.exe completed but did not produce $OutExe"
    }
    Write-Host "Built $OutExe"
    exit 0
}

$Gcc = Get-Command gcc.exe -ErrorAction SilentlyContinue
if ($Gcc) {
    & gcc.exe -O2 -I "$Tools" `
        "$Tools\xmem_lzx_decompress.c" "$Tools\lzx.c" `
        -o "$OutExe"
    if (-not (Test-Path $OutExe)) {
        throw "gcc.exe completed but did not produce $OutExe"
    }
    Write-Host "Built $OutExe"
    exit 0
}

throw "No C compiler found. Install Visual Studio Build Tools or MinGW-w64 gcc, then rerun this script."
