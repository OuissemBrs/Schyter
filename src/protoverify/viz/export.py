"""Rendering entry point shared by the CLI and the tests.

``render_trace`` is the only function the rest of the package needs.  It picks a
back-end, transparently falls back to the matplotlib GIF renderer when Manim or
ffmpeg are unavailable, and writes GIF/MP4/PNG.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from ..core.trace import Trace
from .common import RenderOptions, ffmpeg_available, manim_available, run_command

__all__ = ["available_engines", "render_trace", "render_with_manim", "render_with_matplotlib"]


def render_trace(
    trace: Trace,
    *,
    out: str,
    engine: str = "mpl",
    style: str = "seq",
    fps: int = 20,
    speed: float = 1.0,
    quality: str = "l",
    show: bool = False,
) -> str:
    """Render ``trace`` to ``out`` and return the path actually written."""
    options = RenderOptions(out=out, engine=engine, style=style, fps=fps,
                            speed=speed, quality=quality, show=show)
    Path(options.out).parent.mkdir(parents=True, exist_ok=True)
    if engine == "manim":
        if not manim_available():
            print(*_manim_missing(), sep="\n")
            return render_with_matplotlib(trace, _with_fallback_extension(options))
        if not ffmpeg_available():
            print(*_ffmpeg_missing(), sep="\n")
            return render_with_matplotlib(trace, _with_fallback_extension(options))
        return render_with_manim(trace, options)
    return render_with_matplotlib(trace, options)


def _manim_missing() -> tuple[str, ...]:
    """Say exactly which tool is absent and how to get it."""
    return (
        "protoverify: the 'manim' back-end was requested but manim is not installed.",
        "            install the Python package with:  pip install 'protoverify[manim]'",
        "            manim also needs the system libraries Cairo and Pango; see the",
        "            README section 'Rendering with Manim' for Linux, macOS and Windows.",
        "            falling back to the matplotlib back-end (GIF/PNG only).",
    )


def _ffmpeg_missing() -> tuple[str, ...]:
    """Say exactly which tool is absent and how to get it."""
    return (
        "protoverify: manim is installed but ffmpeg is not on PATH, so no video",
        "            can be produced.  Install it with:",
        "              Linux    sudo apt install ffmpeg",
        "              macOS    brew install ffmpeg",
        "              Windows  winget install Gyan.FFmpeg",
        "            falling back to the matplotlib back-end (GIF/PNG only).",
    )


def _with_fallback_extension(options: RenderOptions) -> RenderOptions:
    """Never hand a ``.mp4`` to the matplotlib path: Pillow cannot write one."""
    if options.out.rsplit(".", 1)[-1].lower() != "mp4":
        return options
    return RenderOptions(out=options.out[:-4] + ".gif", engine="mpl", style=options.style,
                         fps=options.fps, speed=options.speed, quality=options.quality,
                         show=options.show)


def available_engines() -> dict[str, bool]:
    """Report which optional rendering dependencies are installed."""
    return {"manim": manim_available(), "ffmpeg": ffmpeg_available()}


def render_with_matplotlib(trace: Trace, options: RenderOptions) -> str:
    """Render with the matplotlib back-end (sequence or event-graph style)."""
    if options.style == "graph":
        from .mpl_graph import render_graph

        return render_graph(trace, options)
    from .mpl_sequence import render_sequence

    return render_sequence(trace, options)


def render_with_manim(trace: Trace, options: RenderOptions) -> str:
    """Render with the Manim Community Edition back-end via ``manim render``."""
    from . import manim_scenes  # noqa: F401  (registers the scenes with manim)

    flags = {"l": "-ql", "m": "-qm", "h": "-qh"}[options.quality]
    scene = {"seq": "SequenceScene", "graph": "GraphScene"}[options.style]
    out_dir = Path(options.out).parent
    suffix = Path(options.out).suffix.lower().lstrip(".") or "mp4"
    environment = dict(os.environ)
    temporary = _trace_path(trace)
    environment["PROTOVERIFY_TRACE"] = str(temporary)
    args = [
        "manim", "render", flags,
        f"--format={suffix}",
        "--media_dir", str(out_dir / "_manim"),
        "--output_file", Path(options.out).stem,
        "--disable_caching",
        f"protoverify.viz.manim_scenes.{scene}",
    ]
    try:
        result = run_command(args)
        produced = _latest_render(out_dir / "_manim", suffix)
        if result.returncode != 0 or produced is None:
            detail = (result.stderr or result.stdout or "no output").strip()
            raise RuntimeError(f"manim render failed ({result.returncode}):\n{detail}")
        if Path(options.out).resolve() != produced.resolve():
            produced.replace(options.out)
    finally:
        temporary.unlink(missing_ok=True)
        _cleanup(out_dir / "_manim")
    return options.out


def _trace_path(trace: Trace) -> Path:
    """Write the trace to a temporary JSON file Manim can read."""
    import tempfile

    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115
        "w", suffix=".json", prefix="protoverify_", delete=False, encoding="utf-8"
    )
    with handle:
        json.dump(trace.to_json(), handle, indent=2)
    return Path(handle.name)


def _latest_render(media_dir: Path, suffix: str) -> Path | None:
    """Return the newest rendered file of ``suffix`` under ``media_dir``."""
    if not media_dir.exists():
        return None
    candidates = sorted(media_dir.rglob(f"*.{suffix}"), key=lambda p: p.stat().st_mtime)
    return candidates[-1] if candidates else None


def _cleanup(media_dir: Path) -> None:
    """Remove the temporary Manim media directory."""
    if media_dir.exists():
        shutil.rmtree(media_dir, ignore_errors=True)
