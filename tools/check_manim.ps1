<#
.SYNOPSIS
    check_manim.ps1 -- prove that the Manim back-end really renders.

.DESCRIPTION
    The Manim path is the one part of ProtoVerify that cannot be exercised from
    the unit tests on a machine without Manim and ffmpeg, so this script checks
    the three things that actually matter and prints exactly which one is
    missing:

      1. python -c "import manim" succeeds
      2. ffmpeg -version succeeds
      3. manim render -ql protoverify.viz.manim_scenes.SequenceScene produces a
         non-empty MP4 from examples\golden\ns_R2.trace.json

    It writes the trace it needs (the golden Lowe attack for ns/R1) if it is not
    already present, then renders it to out\ns_manim.mp4.

.PARAMETER Python
    The Python interpreter to use. Defaults to "python".

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\check_manim.ps1
#>

[CmdletBinding()]
param([string]$Python = "python")

$ErrorActionPreference = "Continue"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$OutDir = "out"
$Trace = "examples\golden\ns_R2.trace.json"
$Video = Join-Path $OutDir "ns_manim.mp4"
$Scene = "protoverify.viz.manim_scenes.SequenceScene"
$Status = 0

function Say($Text) { Write-Host $Text }
function Ok($Text) { Write-Host "  [ ok ] $Text" }
function Bad($Text) { Write-Host "  [FAIL] $Text"; $script:Status = 1 }

Say "protoverify: checking the Manim back-end"
Say ""

# -- 1. the python package --------------------------------------------------
Say "1/3  python -c 'import manim'"
& $Python -c "import manim; print('manim', manim.__version__)"
if ($LASTEXITCODE -eq 0) {
    Ok "manim is importable"
} else {
    Bad "manim is not importable"
    Say "       install:  pip install 'protoverify[manim]'"
    Say "       system packages: Cairo, Pango and ffmpeg (see README.md)"
}

# -- 2. ffmpeg --------------------------------------------------------------
Say ""
Say "2/3  ffmpeg -version"
$ffmpeg = Get-Command ffmpeg -ErrorAction SilentlyContinue
if ($ffmpeg) {
    & ffmpeg -version 2>&1 | Select-Object -First 1
    Ok "ffmpeg is on PATH ($($ffmpeg.Source))"
} else {
    Bad "ffmpeg is not on PATH"
    Say "       install:  winget install Gyan.FFmpeg"
    Say "                 (or choco install ffmpeg)"
}

# -- 3. the golden trace ---------------------------------------------------
Say ""
Say "3/3  render SequenceScene at -ql"
if (-not (Test-Path $Trace)) {
    Say "  $Trace is missing; generating it"
    & $Python -m protoverify.cli --no-color --quiet verify examples\ns.spdl `
        --claim R2 --trace-dir examples\golden | Out-Null
    if (Test-Path "examples\golden\ns_R2.json") {
        Move-Item "examples\golden\ns_R2.json" $Trace -Force
    }
}
if (-not (Test-Path $Trace)) {
    Bad "could not produce $Trace (is protoverify installed?)"
} else {
    Ok "using $Trace"
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $env:PROTOVERIFY_TRACE = (Resolve-Path $Trace).Path
    $env:PYTHONPATH = (Resolve-Path "src").Path
    & manim render -ql --format=mp4 --media_dir "$OutDir\_manim_check" `
        --output_file ns_manim --disable_caching $Scene 2>&1 |
        Select-Object -Last 20
    $Produced = Get-ChildItem "$OutDir\_manim_check" -Filter 'ns_manim*.mp4' `
        -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    Remove-Item "$OutDir\_manim_check" -Recurse -Force -ErrorAction SilentlyContinue
    if ($Produced -and $Produced.Length -gt 0) {
        Copy-Item $Produced.FullName $Video -Force
        Ok ("rendered $Video ({0} bytes)" -f (Get-Item $Video).Length)
    } else {
        Bad "manim produced no MP4 under $OutDir"
        Say "       run the command above by hand to see manim's own error"
    }
}

Say ""
if ($Status -eq 0) {
    Say "RESULT: the Manim back-end renders correctly."
} else {
    Say "RESULT: the Manim back-end could not be exercised here."
    Say "        The matplotlib back-end is unaffected and remains the default:"
    Say "          protoverify run-example ns --animate --engine mpl"
}
exit $Status