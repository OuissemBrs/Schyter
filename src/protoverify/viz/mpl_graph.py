"""Animated event-graph rendering of an attack trace (matplotlib + networkx).

Nodes are the trace's events, grouped into one labelled box per role run; edges
are the message flows recorded in the trace.  The layout is *layered by step
index* -- not force directed -- and the axes limits are fixed, so consecutive
frames are stable and the animation never jitters.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..core.trace import Trace
from .common import (
    COLOURS,
    Renderer,
    RenderOptions,
    abbreviate,
    agent_colour,
    knowledge_history,
    step_label,
)

__all__ = ["GraphRenderer", "render_graph"]

_X_GAP = 3.0
_Y_GAP = 1.9
_LABEL_OFFSET = 0.85


class GraphRenderer:
    """Draws every frame of the event-graph animation onto one figure."""

    def __init__(self, trace: Trace, options: RenderOptions) -> None:
        self.trace = trace
        self.options = options
        self.graph = self._build_graph()
        self.positions = self._layout()
        self.knowledge = knowledge_history(trace)
        self.xlim = self._x_limits()
        self.ylim = self._y_limits()

    # -- graph -----------------------------------------------------------
    def _build_graph(self) -> Any:
        """Build the networkx event graph (runs, steps, message edges)."""
        import networkx as nx

        graph = nx.DiGraph()
        for run in self.trace.runs:
            graph.add_node(f"run{run.id}", kind="run", run=run)
        for step in self.trace.steps:
            graph.add_node(f"step{step.i}", kind="step", step=step)
        for edge in self.trace.edges:
            graph.add_edge(f"step{edge.src}", f"step{edge.dst}", kind=edge.kind)
        for run in self.trace.runs:
            for step in self.trace.steps:
                if step.run == run.id:
                    graph.add_edge(f"run{run.id}", f"step{step.i}", kind="owns")
        return graph

    def _row_of_run(self) -> dict[int, int]:
        """Map each run id to its horizontal lane (0 = top)."""
        rows = {run.id: index for index, run in enumerate(self.trace.runs)}
        rows[-1] = len(self.trace.runs)  # the attacker's own lane
        return rows

    def _layout(self) -> dict[str, tuple[float, float]]:
        """Deterministic layered layout: x grows with the step index."""
        rows = self._row_of_run()
        top = len(self.trace.runs)
        positions: dict[str, tuple[float, float]] = {}
        for step in self.trace.steps:
            lane = rows.get(step.run if step.run is not None else -1, top)
            positions[f"step{step.i}"] = ((step.i - 1) * _X_GAP, (top - lane) * _Y_GAP)
        for run in self.trace.runs:
            xs = [positions[f"step{s.i}"][0] for s in self.trace.steps if s.run == run.id]
            centre = sum(xs) / len(xs) if xs else 0.0
            positions[f"run{run.id}"] = (centre, (top - rows[run.id]) * _Y_GAP + _LABEL_OFFSET)
        return positions

    def _x_limits(self) -> tuple[float, float]:
        last = len(self.trace.steps)
        return (-_X_GAP, max(1, last - 1) * _X_GAP + _X_GAP)

    def _y_limits(self) -> tuple[float, float]:
        """Leave room above the top lane for the title and below for the labels."""
        top = len(self.trace.runs) * _Y_GAP + _LABEL_OFFSET + 1.4
        return (-_Y_GAP * 0.85, top)

    # -- drawing ---------------------------------------------------------
    def draw(self, ax: object, panel: object, frame: int) -> None:
        """Render frame ``frame`` of the graph animation."""
        ax.clear()  # type: ignore[attr-defined]
        panel.clear()  # type: ignore[attr-defined]
        index = self._step_index(frame)
        self._draw_frame(ax, frame, index)
        self._draw_panel(panel, index)
        ax.set_title(  # type: ignore[attr-defined]
            f"{self.trace.protocol} - claim {self.trace.claim} ({self.trace.status})",
            fontsize=11, fontweight="bold", color=COLOURS["text"],
        )

    def _step_index(self, frame: int) -> int:
        per = max(1, self.options.subframes)
        if not self.trace.steps:
            return -1
        return min(frame // per, len(self.trace.steps) - 1)

    def _draw_frame(self, ax: object, frame: int, index: int) -> None:
        self._draw_lane_labels(ax)
        self._draw_edges(ax, frame, index)
        self._draw_nodes(ax, frame, index)
        self._draw_legend(ax)
        ax.set_facecolor(COLOURS["background"])  # type: ignore[attr-defined]
        ax.set_xlim(*self.xlim)  # type: ignore[attr-defined]
        ax.set_ylim(*self.ylim)  # type: ignore[attr-defined]
        ax.set_xticks([])  # type: ignore[attr-defined]
        ax.set_yticks([])  # type: ignore[attr-defined]
        for spine in ax.spines.values():  # type: ignore[attr-defined]
            spine.set_visible(False)

    def _draw_lane_labels(self, ax: object) -> None:
        from matplotlib.patches import FancyBboxPatch

        for run in self.trace.runs:
            centre = self.positions[f"run{run.id}"]
            colour = agent_colour(self.trace.agents, run.agent)
            ax.add_patch(  # type: ignore[attr-defined]
                FancyBboxPatch(
                    (centre[0] - 2.2, centre[1] - 0.3), 4.4, 0.6,
                    boxstyle="round,pad=0.1", linewidth=1.4, edgecolor=colour,
                    facecolor=COLOURS["box"], zorder=0,
                )
            )
            ax.text(centre[0], centre[1], f"role {run.role}: {run.agent} -> {run.peer}",  # type: ignore[attr-defined]
                    ha="center", va="center", fontsize=8, color=COLOURS["text"], zorder=1)

    def _draw_edges(self, ax: object, frame: int, index: int) -> None:
        per = max(1, self.options.subframes)
        for edge in self.trace.edges:
            if edge.dst > index + 1:
                continue
            src, dst = self.positions[f"step{edge.src}"], self.positions[f"step{edge.dst}"]
            step = self.trace.steps[edge.dst - 1]
            colour = COLOURS["forged"] if step.is_attacker else COLOURS["muted"]
            style = "--" if step.is_attacker else "-"
            alpha = 0.35 if edge.dst == frame // per + 1 else 0.85
            ax.annotate(  # type: ignore[attr-defined]
                "", xy=dst, xytext=src,
                arrowprops={"arrowstyle": "->", "color": colour, "linestyle": style,
                            "linewidth": 1.5, "alpha": alpha, "mutation_scale": 13},
                zorder=2,
            )

    def _draw_nodes(self, ax: object, frame: int, index: int) -> None:
        per = max(1, self.options.subframes)
        current = frame // per + 1
        for step in self.trace.steps:
            x, y = self.positions[f"step{step.i}"]
            colour = COLOURS["forged"] if step.is_attacker else agent_colour(
                self.trace.agents, step.frm)
            marker = "X" if step.is_attacker else ("o" if step.type == "send" else "s")
            size = 240 if step.i == current else 140
            ax.scatter([x], [y], s=size, marker=marker,  # type: ignore[attr-defined]
                       color=colour, zorder=4,
                       edgecolors=COLOURS["learned"] if step.i == current else "white",
                       linewidths=2.4)
            ax.text(x, y - 0.32, f"{step.i}. {abbreviate(step_label(step), 20)}",  # type: ignore[attr-defined]
                    ha="center", va="top", fontsize=7, color=COLOURS["text"], zorder=4)

    def _draw_legend(self, ax: object) -> None:
        from matplotlib.lines import Line2D

        handles = [
            Line2D([], [], color=COLOURS["honest"], marker="o", ls="", label="honest send"),
            Line2D([], [], color=COLOURS["honest_alt"], marker="s", ls="", label="honest receive"),
            Line2D([], [], color=COLOURS["attacker"], marker="X", ls="", label="attacker"),
            Line2D([], [], color=COLOURS["learned"], marker="o", ls="", label="current step"),
        ]
        ax.legend(handles=handles, loc="upper left", fontsize=7, frameon=False)  # type: ignore[attr-defined]

    def _draw_panel(self, panel: object, index: int) -> None:
        panel.set_facecolor("#ffffff")  # type: ignore[attr-defined]
        panel.set_xticks([])  # type: ignore[attr-defined]
        panel.set_yticks([])  # type: ignore[attr-defined]
        panel.text(0.05, 0.97, "attacker knowledge", fontsize=9,  # type: ignore[attr-defined]
                   fontweight="bold", color=COLOURS["text"], va="top")
        current = self.knowledge[index] if index >= 0 else ()
        newest = set(self.trace.steps[index].attacker_new) if index >= 0 else set()
        for row, term in enumerate(current[:24]):
            panel.text(0.05, 0.92 - row * 0.036, term, fontsize=8, va="top",  # type: ignore[attr-defined]
                       color=COLOURS["text"],
                       bbox={"facecolor": COLOURS["learned"], "edgecolor": "none", "pad": 1.6}
                       if term in newest else None)
        if 0 <= index < len(self.trace.steps):
            step = self.trace.steps[index]
            panel.text(0.05, 0.1, abbreviate(step.note, 120), fontsize=7.5,  # type: ignore[attr-defined]
                       va="bottom", color=COLOURS["muted"], wrap=True)
        if index == len(self.trace.steps) - 1 and self.trace.violation:
            panel.text(0.05, 0.015, self.trace.violation, fontsize=7.5, style="italic",  # type: ignore[attr-defined]
                       va="bottom", color=COLOURS["violation"], wrap=True)


def _frame(renderer: Renderer, ax: object, panel: object) -> Callable[[int], list[object]]:
    """Return the ``FuncAnimation`` draw callback for one figure."""

    def draw(frame: int) -> list[object]:
        renderer.draw(ax, panel, frame)
        return []

    return draw


def render_graph(trace: Trace, options: RenderOptions) -> str:
    """Render the event-graph animation and return the path of the written file."""
    import matplotlib

    matplotlib.use("Agg", force=True)
    import matplotlib.pyplot as plt
    from matplotlib.animation import FFMpegWriter, FuncAnimation, PillowWriter

    renderer = GraphRenderer(trace, options)
    figure, (ax, panel) = plt.subplots(
        1, 2, figsize=(14, 6), dpi=options.dpi, gridspec_kw={"width_ratios": [4.0, 1.0]}
    )
    total = len(trace.steps) * max(1, options.subframes)
    if options.out.rsplit(".", 1)[-1].lower() == "png":
        renderer.draw(ax, panel, max(0, total - 1))
        figure.savefig(options.out, dpi=options.dpi)
        plt.close(figure)
        return options.out
    animation = FuncAnimation(
        figure, _frame(renderer, ax, panel),  # type: ignore[arg-type]
        frames=total,
        interval=max(1, int(1000 / max(1, options.fps * options.speed))),
        blit=False, repeat=False,
    )
    suffix = options.out.rsplit(".", 1)[-1].lower()
    fps = max(1, round(options.fps * max(0.1, options.speed)))
    if suffix == "mp4":
        animation.save(options.out, writer=FFMpegWriter(fps=fps))
    else:
        animation.save(options.out, writer=PillowWriter(fps=fps))
    if options.show:  # pragma: no cover - interactive only
        from .controls import attach_controls

        attach_controls(figure, animation, renderer, ax, panel, total, options)
        plt.show()
    plt.close(figure)
    return options.out
