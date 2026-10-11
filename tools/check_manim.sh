#!/usr/bin/env bash
#
# check_manim.sh -- prove that the Manim back-end really renders.
#
# The Manim path is the one part of ProtoVerify that cannot be exercised from the
# unit tests on a machine without Manim and ffmpeg, so this script checks the
# three things that actually matter and prints exactly which one is missing:
#
#   1. `python -c "import manim"` succeeds
#   2. `ffmpeg -version` succeeds
#   3. `manim render -ql protoverify.viz.manim_scenes.SequenceScene` produces a
#      non-empty MP4 from examples/golden/ns_R2.trace.json
#
# It writes the trace it needs (the golden Lowe attack for ns/R1) if it is not
# already present, then renders it to out/ns_manim.mp4.
#
# Usage:   bash tools/check_manim.sh
# Install: see the "Rendering with Manim" section of README.md -- Manim needs
#          Cairo, Pango and ffmpeg as *system* packages, not just pip wheels.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

OUT_DIR="out"
TRACE="examples/golden/ns_R2.trace.json"
VIDEO="$OUT_DIR/ns_manim.mp4"
SCENE="protoverify.viz.manim_scenes.SequenceScene"
STATUS=0

say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ ok ] %s\n' "$*"; }
bad()  { printf '  [FAIL] %s\n' "$*"; STATUS=1; }

say "protoverify: checking the Manim back-end"
say ""

# -- 1. the python package --------------------------------------------------
say "1/3  python -c 'import manim'"
if python -c "import manim; print('manim', manim.__version__)" 2>&1; then
    ok "manim is importable"
else
    bad "manim is not importable"
    say "       install:  pip install 'protoverify[manim]'"
    say "       system packages: cairo, pango, ffmpeg (see README.md)"
fi

# -- 2. ffmpeg --------------------------------------------------------------
say ""
say "2/3  ffmpeg -version"
if command -v ffmpeg >/dev/null 2>&1; then
    ffmpeg -version 2>&1 | head -n 1
    ok "ffmpeg is on PATH"
else
    bad "ffmpeg is not on PATH"
    say "       install:  Linux  sudo apt install ffmpeg"
    say "                 macOS  brew install ffmpeg"
    say "                 Windows  winget install Gyan.FFmpeg"
fi

# -- 3. the golden trace ---------------------------------------------------
say ""
say "3/3  render SequenceScene at -ql"
if [ ! -f "$TRACE" ]; then
    say "  $TRACE is missing; generating it"
    python -m protoverify.cli --no-color --quiet verify examples/ns.spdl \
        --claim R2 --trace-dir examples/golden >/dev/null 2>&1
    if [ -f "examples/golden/ns_R2.json" ]; then
        mv "examples/golden/ns_R2.json" "$TRACE"
    fi
fi
if [ ! -f "$TRACE" ]; then
    bad "could not produce $TRACE (is protoverify installed?)"
else
    ok "using $TRACE"
    mkdir -p "$OUT_DIR"
    PROTOVERIFY_TRACE="$TRACE" manim render -ql --format=mp4 \
        --media_dir "$OUT_DIR/_manim_check" \
        --output_file ns_manim \
        --disable_caching \
        "$SCENE" 2>&1 | tail -n 20
    PRODUCED="$(find "$OUT_DIR/_manim_check" -name 'ns_manim*.mp4' -type f 2>/dev/null | head -n 1)"
    rm -rf "$OUT_DIR/_manim_check"
    if [ -n "$PRODUCED" ] && [ -s "$PRODUCED" ]; then
        cp "$PRODUCED" "$VIDEO"
        SIZE="$(wc -c < "$VIDEO" | tr -d ' ')"
        ok "rendered $VIDEO ($SIZE bytes)"
    else
        bad "manim produced no MP4 at $OUT_DIR"
        say "       run the command above by hand to see manim's own error"
    fi
fi

say ""
if [ "$STATUS" -eq 0 ]; then
    say "RESULT: the Manim back-end renders correctly."
else
    say "RESULT: the Manim back-end could not be exercised here."
    say "        The matplotlib back-end is unaffected and remains the default:"
    say "          protoverify run-example ns --animate --engine mpl"
fi
exit "$STATUS"