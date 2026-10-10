"""Animated sequence-diagram rendering of an attack trace (matplotlib back-end).

One lifeline per agent, arrows that grow from the sender's lifeline to the
receiver's across ``subframes`` interpolated frames, and a right-hand panel that
grows the attacker's knowledge step by step.  Attacker steps are drawn as red
dashed arrows, and every term the attacker learns is flashed in yellow.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..core.trace import Step, Trace
from .common import (
    COLOURS,
    Renderer,
    RenderOptions,
    abbreviate,
    agent_colour,
    knowledge_history,
    step_label,
)

__all__ = ["SequenceRenderer", "render_sequence"]


@dataclass(slots=True)
class _Arrow:
    """The interpolated state of the arrow currently being drawn."""

    step: Step
    progress: float
    y: float


class SequenceRenderer:
    """Draws every frame of the sequence animation onto a single figure."""

    def __init__(self, trace: Trace, options: RenderOptions) -> None:
        self.trace = trace
        self.options = options
        self.agents = tuple(a.id for a in trace.agents)
        self.columns = {name: index + 1 for index, name in enumerate(self.agents)}
        self.knowledge = knowledge_history(trace)
        self.last = len(trace.steps) - 1

    # -- geometry --------------------------------------------------------
    @property
    def _panel_left(self) -> float:
        return len(self.agents) + 1.6

    def _row(self, index: int) -> float:
        return float(len(self.trace.steps) - index)

    def _step_of_frame(self, frame: int) -> tuple[int, float]:
        """Map a frame number to ``(step index, progress)``."""
        per = max(1, self.options.subframes)
        index = min(frame // per, self.last)
        progress = (frame % per + 1) / per
        return index, min(1.0, progress)

    # -- drawing ---------------------------------------------------------
    def draw(self, ax: object, panel: object, frame: int) -> None:
        """Render frame ``frame`` (0-based) of the animation."""
        ax.clear()  # type: ignore[attr-defined]
        panel.clear()  # type: ignore[attr-defined]
        self._draw_background(ax)
        self._draw_lifelines(ax)
        index, progress = self._step_of_frame(frame)
        self._draw_steps(ax, index, progress)
        self._draw_panel(panel, index)
        self._draw_caption(ax, index, progress)

    def _draw_background(self, ax: object) -> None:
        ax.set_facecolor(COLOURS["background"])  # type: ignore[attr-defined]
        ax.set_xlim(0, len(self.agents) + 1)  # type: ignore[attr-defined]
        ax.set_ylim(0.1, len(self.trace.steps) + 2.6)  # type: ignore[attr-defined]
        ax.set_xticks([])  # type: ignore[attr-defined]
        ax.set_yticks([])  # type: ignore[attr-defined]
        for spine in ax.spines.values():  # type: ignore[attr-defined]
            spine.set_visible(False)

    def _draw_lifelines(self, ax: object) -> None:
        top = len(self.trace.steps) + 1.2
        for name in self.agents:
            x = self.columns[name]
            colour = agent_colour(self.trace.agents, name)
            style = "--" if self._is_attacker(name) else "-"
            ax.plot([x, x], [0.5, top],  # type: ignore[attr-defined]
                    color=colour, linestyle=style, linewidth=1.4, alpha=0.85, zorder=1)
            ax.add_patch(self._box(x, top + 0.35, colour))  # type: ignore[attr-defined]
            ax.text(x, top + 0.35, name, ha="center", va="center",  # type: ignore[attr-defined]
                    fontsize=9.5, fontweight="bold",
                    color=COLOURS["attacker"] if self._is_attacker(name) else COLOURS["text"],
                    zorder=5)

    def _box(self, x: float, y: float, colour: str) -> object:
        from matplotlib.patches import FancyBboxPatch

        return FancyBboxPatch(
            (x - 0.45, y - 0.25), 0.9, 0.5,
            boxstyle="round,pad=0.08",
            linewidth=1.6, edgecolor=colour,
            facecolor=COLOURS["box_attacker"] if colour == COLOURS["attacker"] else COLOURS["box"],
            zorder=4,
        )

    def _draw_steps(self, ax: object, index: int, progress: float) -> None:
        for position, step in enumerate(self.trace.steps):
            self._draw_step(ax, step, position, 1.0 if position < index else
                            (progress if position == index else 0.0))

    def _draw_step(self, ax: object, step: Step, position: int, progress: float) -> None:
        if progress <= 0.0:
            return
        y = self._row(position)
        x_from = self.columns.get(step.frm, 0)
        x_to = self.columns.get(step.to, 0)
        head = x_from + (x_to - x_from) * progress
        colour = COLOURS["forged"] if step.is_attacker else agent_colour(
            self.trace.agents, step.frm)
        style = "--" if step.is_attacker else "-"
        ax.annotate(  # type: ignore[attr-defined]
            "", xy=(head, y), xytext=(x_from, y),
            arrowprops={"arrowstyle": "->", "color": colour, "linestyle": style,
                        "linewidth": 2.0, "mutation_scale": 16},
            zorder=3,
        )
        if progress > 0.45:
            ax.text(  # type: ignore[attr-defined]
                (x_from + head) / 2, y + 0.22, step_label(step),
                ha="center", va="bottom", fontsize=8, color=COLOURS["text"], zorder=5,
            )
        if step.is_attacker:
            ax.text(  # type: ignore[attr-defined]
                (x_from + head) / 2, y - 0.22, "(attacker)",
                ha="center", va="top", fontsize=7, color=COLOURS["attacker"],
                style="italic", zorder=5,
            )

    def _draw_panel(self, panel: object, index: int) -> None:
        panel.set_facecolor("#ffffff")  # type: ignore[attr-defined]
        panel.set_xlim(0, 1)  # type: ignore[attr-defined]
        panel.set_ylim(0, 1)  # type: ignore[attr-defined]
        panel.set_xticks([])  # type: ignore[attr-defined]
        panel.set_yticks([])  # type: ignore[attr-defined]
        for spine in panel.spines.values():  # type: ignore[attr-defined]
            spine.set_edgecolor(COLOURS["box"])
            spine.set_linewidth(1.4)
        panel.text(0.05, 0.965, "attacker knowledge", fontsize=9,  # type: ignore[attr-defined]
                   fontweight="bold", color=COLOURS["text"], va="top")
        current = self.knowledge[index] if index >= 0 else ()
        newest = set(self.trace.steps[index].attacker_new) if index >= 0 else set()
        for row, term in enumerate(current[:22]):
            fresh = term in newest
            panel.text(  # type: ignore[attr-defined]
                0.05, 0.915 - row * 0.038, term,
                fontsize=8, va="top", color=COLOURS["text"],
                bbox={"facecolor": COLOURS["learned"], "edgecolor": "none", "pad": 1.6}
                if fresh else None,
            )
        if not current:
            panel.text(0.05, 0.915, "(nothing yet)", fontsize=8,  # type: ignore[attr-defined]
                       va="top", color=COLOURS["muted"], style="italic")

    def _draw_caption(self, ax: object, index: int, progress: float) -> None:
        title = f"{self.trace.protocol} - claim {self.trace.claim} ({self.trace.status})"
        ax.text(0.2, len(self.trace.steps) + 2.25, title,  # type: ignore[attr-defined]
                fontsize=12, fontweight="bold", color=COLOURS["text"])
        step = self.trace.steps[index] if index >= 0 else None
        if step is not None:
            ax.text(  # type: ignore[attr-defined]
                0.2, 0.9, f"step {step.i}/{len(self.trace.steps)}: "
                f"{abbreviate(step.note, 90)}",
                fontsize=8.5, color=COLOURS["text"], ha="left", va="center",
            )
        if step is not None and index == self.last and progress >= 0.99:
            ax.text(  # type: ignore[attr-defined]
                0.2, 0.35, self.trace.violation, fontsize=8.5, style="italic",
                color=COLOURS["violation"], ha="left", va="center", wrap=True,
            )

    def _is_attacker(self, agent: str) -> bool:
        return any(a.id == agent and a.kind == "attacker" for a in self.trace.agents)


def render_sequence(trace: Trace, options: RenderOptions) -> str:
    """Render the sequence animation and return the path of the written file."""
    import matplotlib

    if options.show:
        try:
            matplotlib.use("TkAgg")
        except ImportError as exc:  # pragma: no cover - depends on the Tk bindings
            raise RuntimeError(
                f"interactive mode needs Tkinter (pip install tk): {exc}"
            ) from exc
    else:
        matplotlib.use("Agg", force=True)
    import matplotlib.pyplot as plt
    from matplotlib.animation import FuncAnimation

    renderer = SequenceRenderer(trace, options)
    figure, (ax, panel) = plt.subplots(
        1, 2, figsize=(13, 7), dpi=options.dpi,
        gridspec_kw={"width_ratios": [3.2, 1.0]},
    )
    total = len(trace.steps) * max(1, options.subframes)
    if options.out.rsplit(".", 1)[-1].lower() == "png":
        renderer.draw(ax, panel, max(0, total - 1))
        figure.savefig(options.out, dpi=options.dpi)
        plt.close(figure)
        return options.out
    animation = FuncAnimation(
        figure, _frame(renderer, ax, panel),  # type: ignore[arg-type]
        frames=total, interval=max(1, int(1000 / max(1, options.fps * options.speed))),
        blit=False, repeat=False,
    )
    written = _write(animation, options)
    if options.show:  # pragma: no cover - interactive only
        from .controls import attach_controls

        attach_controls(figure, animation, renderer, ax, panel, total, options)
        plt.show()
    plt.close(figure)
    return written


def _frame(renderer: Renderer, ax: object, panel: object) -> Callable[[int], list[object]]:
    """Return the ``FuncAnimation`` draw callback for one figure."""

    def draw(frame: int) -> list[object]:
        renderer.draw(ax, panel, frame)
        return []

    return draw


def _write(animation: Any, options: RenderOptions) -> str:
    """Save the animation as GIF or MP4."""
    from matplotlib.animation import FFMpegWriter, PillowWriter

    suffix = options.out.rsplit(".", 1)[-1].lower()
    fps = max(1, round(options.fps * max(0.1, options.speed)))
    if suffix == "mp4":
        animation.save(options.out, writer=FFMpegWriter(fps=fps))
    else:
        animation.save(options.out, writer=PillowWriter(fps=fps))
    return options.out
