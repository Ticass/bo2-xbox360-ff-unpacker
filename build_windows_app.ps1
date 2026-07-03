param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Spec = Join-Path $Root "ff_app.spec"
$Dist = Join-Path $Root "dist"
$Build = Join-Path $Root "build"

if ($Clean) {
    if (Test-Path $Dist) { Remove-Item -LiteralPath $Dist -Recurse -Force }
    if (Test-Path $Build) { Remove-Item -LiteralPath $Build -Recurse -Force }
}

$Helper = Join-Path $Root "_tools\xmem_lzx_decompress.exe"
if (-not (Test-Path $Helper)) {
    Write-Host "Missing _tools\xmem_lzx_decompress.exe. Building helper..."
    powershell -ExecutionPolicy Bypass -File (Join-Path $Root "build_lzx_helper.ps1")
}

if (-not (Test-Path $Helper)) {
    throw "Missing _tools\xmem_lzx_decompress.exe after helper build."
}

$XMemHelper = Join-Path $Root "_tools\xmem_compress.exe"
$XMemSource = Join-Path $Root "tools\xmem_compress.cs"
$NeedsXMemBuild = -not (Test-Path $XMemHelper)
if (-not $NeedsXMemBuild -and (Test-Path $XMemSource)) {
    $NeedsXMemBuild = (Get-Item $XMemSource).LastWriteTimeUtc -gt (Get-Item $XMemHelper).LastWriteTimeUtc
}
if ($NeedsXMemBuild) {
    Write-Host "Building XMem compressor helper..."
    $Csc = Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe"
    if (-not (Test-Path $Csc)) {
        throw "Missing .NET Framework C# compiler: $Csc"
    }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $XMemHelper) | Out-Null
    & $Csc /nologo /platform:x86 /optimize+ /out:$XMemHelper $XMemSource
}

if (-not (Test-Path $XMemHelper)) {
    throw "Missing _tools\xmem_compress.exe after helper build."
}

python -m PyInstaller --version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "PyInstaller is not installed. Installing it for this Python environment..."
    python -m pip install pyinstaller
}

python -m PyInstaller $Spec --noconfirm --distpath $Dist --workpath $Build

$Exe = Join-Path $Dist "BO2FastFileUnpacker.exe"
if (-not (Test-Path $Exe)) {
    throw "Build finished but executable was not found: $Exe"
}

Write-Host ""
Write-Host "Built:"
Write-Host $Exe
Write-Host ""
Write-Host "Users can run this executable directly or drag .ff files onto it."
