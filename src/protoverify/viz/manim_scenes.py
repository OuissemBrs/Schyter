"""Manim Community Edition scenes for ProtoVerify attack traces.

The scenes are deterministic (no randomness) and use ``Text`` only -- never
``Tex`` or ``MathTex`` -- so no LaTeX installation is required.  They read the
trace path from the ``PROTOVERIFY_TRACE`` environment variable, which lets
``manim render`` run them without any command line arguments::

    PROTOVERIFY_TRACE=trace.json manim render -ql protoverify.viz.manim_scenes.SequenceScene

Set ``PROTOVERIFY_FONT`` to pick a monospace font; the default uses whatever font
Manim was configured with.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any

from manim import (
    DOWN,
    UP,
    Arrow,
    Create,
    Dot,
    FadeIn,
    FadeOut,
    GrowArrow,
    Indicate,
    Scene,
    ShowPassingFlash,
    SurroundingRectangle,
    Text,
    Transform,
    VGroup,
    config,
    np,
)

try:  # Manim CE moved ``ManimColor`` into the top-level namespace in 0.19
    from manim import ManimColor
except ImportError:  # pragma: no cover - depends on the installed manim version
    from manim.utils.color import ManimColor

from ..core.trace import Step, Trace
from .common import COLOURS, abbreviate, agent_colour, knowledge_history, step_label

__all__ = ["GraphScene", "KnowledgeScene", "SequenceScene", "load_scene_trace"]

FONT = os.environ.get("PROTOVERIFY_FONT") or None
MAX_PANEL_ROWS = 9
FRAME_WIDTH = 13.6
ROW_HEIGHT = 0.72


def load_scene_trace(path: str | None = None) -> Trace:
    """Load the trace a scene should render, honouring ``PROTOVERIFY_TRACE``."""
    target = path or os.environ.get("PROTOVERIFY_TRACE", "")
    if not target:
        raise RuntimeError(
            "set PROTOVERIFY_TRACE to the trace JSON file this scene should render"
        )
    return Trace.from_json(json.loads(pathlib.Path(target).read_text(encoding="utf-8")))


def _col(name: str) -> ManimColor:
    """Return one of the shared palette colours."""
    return ManimColor(COLOURS[name])


def _text(content: str, size: int, colour: str, **kwargs: Any) -> Text:
    """Create a ``Text`` object, applying the optional monospace font."""
    if FONT:
        return Text(content, font=FONT, font_size=size, color=_col(colour), **kwargs)
    return Text(content, font_size=size, color=_col(colour), **kwargs)


class _TraceScene(Scene):
    """Shared set-up: background colour, title card and trace loading."""

    trace: Trace

    def setup_trace(self, path: str | None = None) -> None:
        """Load the trace and paint the title card."""
        self.trace = load_scene_trace(path)
        self.camera.background_color = _col("background")
        self.title = _text(
            f"{self.trace.protocol}  -  claim {self.trace.claim}  -  {self.trace.status}",
            30, "text",
        ).to_edge(UP)
        self.add(self.title)
        self.caption: Any = None

    def say(self, step: Step) -> None:
        """Fade the caption of ``step`` in, replacing the previous one."""
        new = _text(abbreviate(step.note, 120), 15, "text").to_edge(DOWN, buff=0.35)
        if self.caption is None:
            self.play(FadeIn(new), run_time=0.25)
        else:
            self.play(Transform(self.caption, new), run_time=0.25)
        self.caption = new

    def show_violation(self) -> None:
        """Flash the violated claim and fade in the explanation."""
        flash = _text(f"claim {self.trace.claim} ({self.trace.claim_kind}) FALSIFIED",
                      26, "violation").move_to(config.frame_center)
        self.play(Indicate(flash, color=_col("learned"), scale_factor=1.15))
        sentence = _text(abbreviate(self.trace.violation, 150), 17,
                         "violation").to_edge(DOWN, buff=1.1)
        self.play(FadeIn(sentence, shift=UP * 0.3))
        self.wait(2.5)


class SequenceScene(_TraceScene):
    """Lifeline diagram with growing arrows and a live knowledge panel."""

    def construct(self) -> None:
        """Build and play the whole trace."""
        self.setup_trace()
        self.column_x = self._columns()
        self.lines, self.boxes = self._draw_lifelines()
        self.panel_lines = self._draw_panel()
        self.play(Create(self.lines), FadeIn(self.boxes), run_time=1.0)
        for index, step in enumerate(self.trace.steps):
            self._play_step(step, index)
        self.show_violation()

    def _columns(self) -> dict[str, float]:
        names = [a.id for a in self.trace.agents]
        spread = min(2.4, 9.0 / max(1, len(names) - 1)) if len(names) > 1 else 0.0
        left = -3.0 - spread * (len(names) - 1) / 2
        return {name: left + index * spread for index, name in enumerate(names)}

    def _draw_lifelines(self) -> tuple[VGroup, VGroup]:
        lines = VGroup()
        boxes = VGroup()
        for name, x in self.column_x.items():
            colour = agent_colour(self.trace.agents, name)
            is_attacker = colour == COLOURS["attacker"]
            line = Dot(radius=0.03, color=colour).move_to([x, 0.2, 0])
            shaft = Arrow(
                start=[x, -3.4, 0], end=[x, 3.3, 0], buff=0, color=colour,
                stroke_width=4 if is_attacker else 2,
                max_tip_length_to_length_ratio=0.0,
            )
            label = _text(name, 20, "attacker" if is_attacker else "text", color=colour)
            box = SurroundingRectangle(
                label, buff=0.16, corner_radius=0.12, color=colour,
                fill_color=_col("box_attacker" if is_attacker else "box"),
                fill_opacity=0.9, stroke_width=2,
            )
            box.move_to([x, 3.7, 0])
            lines.add(VGroup(line, shaft))
            boxes.add(VGroup(box, label))
        return lines, boxes

    def _draw_panel(self) -> list[Text]:
        x = 5.2
        header = _text("attacker knowledge", 17, "text").move_to([x, 3.3, 0])
        self.add(header)
        lines = [header]
        for row in range(MAX_PANEL_ROWS):
            placeholder = _text(" ", 13, "muted").move_to([x, 2.8 - row * 0.42, 0])
            self.add(placeholder)
            lines.append(placeholder)
        return lines

    def _play_step(self, step: Step, index: int) -> None:
        y = 2.5 - index * ROW_HEIGHT
        if y < -3.2:  # pragma: no cover - only for very long traces
            return
        colour = _col("forged") if step.is_attacker else _col("honest")
        start = np.array([self.column_x[step.frm], y, 0.0])
        end = np.array([self.column_x[step.to], y, 0.0])
        arrow = Arrow(start=start, end=end, buff=0.2, color=colour, stroke_width=4,
                      max_tip_length_to_length_ratio=0.08)
        label = _text(step_label(step, 40), 12, "text")
        label.move_to([(start[0] + end[0]) / 2, y + 0.3, 0.0])
        grow = GrowArrow(arrow) if step.is_attacker else Create(arrow)
        self.play(grow, FadeIn(label), run_time=0.6)
        self.say(step)
        self._update_panel(step)
        self.wait(0.35)

    def _update_panel(self, step: Step) -> None:
        index = self.trace.steps.index(step)
        current = knowledge_history(self.trace)[index][:MAX_PANEL_ROWS]
        for row, line in enumerate(self.panel_lines[1:]):
            term = current[row] if row < len(current) else " "
            new = _text(term, 13, "text").move_to(line.get_center())
            if term == " ":
                self.play(FadeOut(line), FadeIn(new), run_time=0.15)
            elif term in step.attacker_new:
                self.play(Indicate(line), Transform(line, new), run_time=0.3)
                self.play(line.animate.set_color(_col("learned")), run_time=0.15)
            else:
                self.play(Transform(line, new), run_time=0.15)


class GraphScene(_TraceScene):
    """Event graph: one node per trace step, attacker path highlighted."""

    def construct(self) -> None:
        """Build and play the whole trace."""
        self.setup_trace()
        nodes, arrows, labels = self._build()
        self.play(FadeIn(nodes), FadeIn(labels), run_time=1.0)
        self.play(Create(arrows), run_time=1.2)
        for index, step in enumerate(self.trace.steps):
            self.play(Indicate(nodes[index], color=_col("learned")), run_time=0.35)
            if step.is_attacker:
                self.play(ShowPassingFlash(nodes[index], run_time=0.45))
            self.say(step)
            self.wait(0.15)
        self.show_violation()

    def _build(self) -> tuple[VGroup, VGroup, VGroup]:
        nodes = VGroup()
        arrows = VGroup()
        labels = VGroup()
        count = max(1, len(self.trace.steps))
        width = min(2.6, FRAME_WIDTH / count)
        for index, step in enumerate(self.trace.steps):
            x = -FRAME_WIDTH / 2 + width / 2 + index * width
            colour = _col("forged") if step.is_attacker else _col("honest")
            dot = Dot(radius=0.13, color=colour).move_to([x, 0.8, 0])
            tag = _text(f"{step.i}: {abbreviate(step.msg, 18)}", 11,
                        "text").next_to(dot, DOWN, buff=0.25)
            nodes.add(dot)
            labels.add(tag)
            if index:
                arrows.add(Arrow(
                    start=nodes[index - 1].get_center(), end=[x, 0.8, 0], buff=0.2,
                    color=_col("muted"), stroke_width=2,
                    max_tip_length_to_length_ratio=0.08,
                ))
        return nodes, arrows, labels


class KnowledgeScene(_TraceScene):
    """Step-by-step ``analyze`` closure: what the attacker decrypts and projects."""

    def construct(self) -> None:
        """Replay the attacker's knowledge growth, one line per learned term."""
        self.setup_trace()
        header = _text("how the attacker derives its knowledge", 20, "text")
        header.move_to([0, 2.0, 0])
        self.play(FadeIn(header))
        y = 1.2
        for step in self.trace.steps:
            line = _text(f"step {step.i}: {step.frm} -> {step.to}", 14,
                         "text").move_to([0, y, 0])
            self.play(FadeIn(line), run_time=0.3)
            y -= 0.45
            for term in step.attacker_new:
                gained = _text(f"+ learns {term}", 14, "learned").move_to([0.3, y, 0])
                self.play(FadeIn(gained, shift=UP * 0.15), run_time=0.25)
                y -= 0.4
            self.say(step)
            if y < -2.4:  # pragma: no cover - only for very long traces
                break
        self.wait(1.0)
