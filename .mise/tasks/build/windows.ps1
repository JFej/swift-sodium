#!/usr/bin/env pwsh
#MISE description="Build all Windows libsodium variants"

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ProjectRoot = if ($env:MISE_PROJECT_ROOT) { $env:MISE_PROJECT_ROOT } else { Resolve-Path "$PSScriptRoot/../../.." }
$Version = $env:LIBSODIUM_VERSION
$Release = $env:LIBSODIUM_RELEASE
$ExpectedHash = $env:LIBSODIUM_SHA256
if (-not $Version -or -not $Release -or -not $ExpectedHash) {
    throw "Run this task through mise so the pinned build environment is available."
}

$VSWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $VSWhere)) {
    throw "vswhere.exe was not found. Install Visual Studio with the MSBuild component."
}
$MSBuild = & $VSWhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
if (-not $MSBuild) {
    throw "MSBuild was not found in the installed Visual Studio instance."
}

$BuildRoot = if ($env:SODIUM_BUILD_ROOT) { $env:SODIUM_BUILD_ROOT } else { "$ProjectRoot/Build" }
$VariantsRoot = if ($env:SODIUM_VARIANTS_ROOT) { $env:SODIUM_VARIANTS_ROOT } else { "$BuildRoot/variants" }
$Archive = "$BuildRoot/cache/libsodium-$Version.tar.gz"
$SourceParent = "$BuildRoot/work/windows"

New-Item -ItemType Directory -Force -Path (Split-Path $Archive), $SourceParent, $VariantsRoot | Out-Null
if (-not (Test-Path $Archive)) {
    Invoke-WebRequest -Uri "https://github.com/jedisct1/libsodium/releases/download/$Release/libsodium-$Version.tar.gz" -OutFile $Archive
}

$ActualHash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
if ($ActualHash -ne $ExpectedHash) {
    throw "libsodium checksum mismatch: expected $ExpectedHash, got $ActualHash"
}

tar -xzf $Archive -C $SourceParent
$Source = "$SourceParent/libsodium-$Version"
$Solution = "$Source/builds/msvc/vs2026/libsodium.sln"

function Write-Variant([string] $Identifier, [string] $Platform, [string] $Triple) {
    & $MSBuild $Solution /m /p:Configuration=StaticRelease /p:Platform=$Platform
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed for $Platform with exit code $LASTEXITCODE." }
    $Library = Get-ChildItem "$Source/bin/$Platform" -Recurse -Filter libsodium.lib | Select-Object -First 1
    if (-not $Library) { throw "No libsodium.lib produced for $Platform" }

    $Output = "$VariantsRoot/$Identifier"
    New-Item -ItemType Directory -Force -Path "$Output/library", "$Output/include" | Out-Null
    Copy-Item $Library.FullName "$Output/library/libsodium.lib" -Force
    Copy-Item "$Source/src/libsodium/include/*" "$Output/include" -Recurse -Force
    Copy-Item "$Source/LICENSE" "$Output/LICENSE.libsodium" -Force
    @{
        identifier = $Identifier
        library = "library/libsodium.lib"
        supportedTriples = @($Triple)
    } | ConvertTo-Json | Set-Content "$Output/metadata.json"
}

Write-Variant "windows-x86_64" "x64" "x86_64-unknown-windows-msvc"
Write-Variant "windows-aarch64" "ARM64" "aarch64-unknown-windows-msvc"
