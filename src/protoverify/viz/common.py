"""Shared helpers for the animation back-ends.

Nothing in this module (or anywhere else under ``viz/``) imports the engine:
renderers only ever see a :class:`~protoverify.core.trace.Trace`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..core.trace import AgentInfo, Step, Trace, TraceError

__all__ = [
    "COLOURS",
    "RenderOptions",
    "Renderer",
    "abbreviate",
    "agent_colour",
    "ffmpeg_available",
    "knowledge_history",
    "load_trace",
    "manim_available",
    "step_label",
    "subframe_count",
    "total_frames",
]


class Renderer(Protocol):
    """The drawing contract every matplotlib back-end implements."""

    def draw(self, ax: object, panel: object, frame: int) -> None:
        """Render one frame of the animation onto ``ax`` and the side ``panel``."""
        ...

#: The palette shared by both back-ends.
COLOURS = {
    "background": "#fbfbfd",
    "lifeline": "#94a3b8",
    "lifeline_attacker": "#d62728",
    "box": "#e2e8f0",
    "box_attacker": "#fecaca",
    "text": "#0f172a",
    "muted": "#64748b",
    "honest": "#1f77b4",
    "honest_alt": "#2ca02c",
    "attacker": "#d62728",
    "forged": "#d62728",
    "learned": "#f5c518",
    "learned_edge": "#b8860b",
    "violation": "#b91c1c",
}

#: Quality presets shared by the matplotlib and Manim back-ends.
_QUALITY_PRESETS = {
    "l": {"dpi": 90, "subframes": 6},
    "m": {"dpi": 120, "subframes": 8},
    "h": {"dpi": 160, "subframes": 12},
}


@dataclass(frozen=True, slots=True)
class RenderOptions:
    """Everything a renderer needs besides the trace itself."""

    out: str
    engine: str = "mpl"
    style: str = "seq"
    fps: int = 20
    speed: float = 1.0
    quality: str = "l"
    show: bool = False

    @property
    def dpi(self) -> int:
        """The pixel density implied by the quality preset."""
        return int(_QUALITY_PRESETS[self.quality]["dpi"])

    @property
    def subframes(self) -> int:
        """How many frames each trace step is interpolated over."""
        return int(_QUALITY_PRESETS[self.quality]["subframes"])


def load_trace(path: str | Path) -> Trace:
    """Read and validate a trace JSON file."""
    try:
        return Trace.from_file(path)
    except FileNotFoundError as exc:
        raise TraceError(f"no such trace file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise TraceError(f"{path} is not valid JSON: {exc}") from exc


def agent_colour(agents: tuple[AgentInfo, ...], agent: str) -> str:
    """Return the stable colour of ``agent``: blue/green when honest, red for the attacker."""
    for info in agents:
        if info.id == agent:
            if info.kind == "attacker":
                return COLOURS["attacker"]
            break
    honest = [a.id for a in agents if a.kind != "attacker"]
    index = honest.index(agent) if agent in honest else 0
    return COLOURS["honest"] if index % 2 == 0 else COLOURS["honest_alt"]


def abbreviate(message: str, limit: int = 46) -> str:
    """Shorten a long message term, keeping both ends readable."""
    if len(message) <= limit:
        return message
    keep = (limit - 3) // 2
    return f"{message[:keep]}...{message[-keep:]}"


def step_label(step: Step, limit: int = 46) -> str:
    """Return the text drawn above an arrow for ``step``."""
    return f"{step.label}: {abbreviate(step.msg, limit)}"


def knowledge_history(trace: Trace) -> list[tuple[str, ...]]:
    """Return the attacker's knowledge after every step, for the side panel."""
    history: list[tuple[str, ...]] = []
    current: list[str] = []
    for step in trace.steps:
        for term in step.attacker_new:
            if term not in current:
                current.append(term)
        history.append(tuple(current))
    return history


def subframe_count(trace: Trace, subframes: int) -> int:
    """Number of frames produced for one step of ``trace``."""
    return max(1, subframes)


def total_frames(trace: Trace, subframes: int) -> int:
    """Total frame count of a rendering: ``len(steps) * subframes``."""
    return len(trace.steps) * subframe_count(trace, subframes)


def manim_available() -> bool:
    """True when the optional Manim Community Edition package is importable."""
    try:
        import manim  # noqa: F401
    except Exception:
        return False
    return True


def ffmpeg_available() -> bool:
    """True when an ``ffmpeg`` binary is on ``PATH``."""
    return shutil.which("ffmpeg") is not None


def run_command(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run a helper process and capture its output as text."""
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="replace",
    )
