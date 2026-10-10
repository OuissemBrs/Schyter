"""Visualisation tests (headless, Agg).

The Manim test is marked ``manim`` and skipped unless both manim and ffmpeg are
installed; the rest always run because matplotlib, networkx and Pillow are hard
requirements of the ``viz`` extra.
"""

from __future__ import annotations

import shutil

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)

matplotlib = pytest.importorskip("matplotlib")

from protoverify.core.search import Bounds, Verifier
from protoverify.core.trace import Trace
from protoverify.parser import parse_file
from protoverify.viz.common import RenderOptions
from protoverify.viz.export import available_engines, render_trace

pytestmark = pytest.mark.viz


@pytest.fixture(scope="module")
def ns_trace() -> Trace:
    protocol = parse_file(str(example_path("ns")))
    for result in Verifier(protocol, Bounds()).verify():
        if result.trace is not None and result.claim == "R3":
            return result.trace
    raise AssertionError("ns must falsify R3")  # pragma: no cover


def frame_count(path: object) -> int:
    from PIL import Image

    with Image.open(path) as image:  # type: ignore[arg-type]
        return int(getattr(image, "n_frames", 1))


@pytest.fixture(autouse=True)
def headless() -> None:
    matplotlib.use("Agg", force=True)


def test_sequence_gif_is_written(ns_trace: Trace, tmp_path: object) -> None:
    out = tmp_path / "attack.gif"  # type: ignore[operator]
    written = render_trace(ns_trace, out=str(out), engine="mpl", style="seq", fps=12)
    assert written == str(out)
    assert out.exists()
    assert out.stat().st_size > 10_000  # type: ignore[attr-defined]


def test_frame_count_equals_steps_times_subframes(ns_trace: Trace, tmp_path: object) -> None:
    from protoverify.viz.common import total_frames

    out = tmp_path / "attack.gif"  # type: ignore[operator]
    render_trace(ns_trace, out=str(out), engine="mpl", style="seq", quality="l")
    assert frame_count(out) == total_frames(ns_trace, 6)
    assert frame_count(out) == len(ns_trace.steps) * 6


def test_graph_gif_is_written(ns_trace: Trace, tmp_path: object) -> None:
    out = tmp_path / "graph.gif"  # type: ignore[operator]
    render_trace(ns_trace, out=str(out), engine="mpl", style="graph", fps=12)
    assert out.exists() and out.stat().st_size > 10_000  # type: ignore[attr-defined]


def test_png_export(ns_trace: Trace, tmp_path: object) -> None:
    out = tmp_path / "frame.png"  # type: ignore[operator]
    render_trace(ns_trace, out=str(out), engine="mpl", style="seq", fps=5)
    assert out.exists() and out.stat().st_size > 1_000  # type: ignore[attr-defined]


@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg is not installed")
def test_mp4_export(ns_trace: Trace, tmp_path: object) -> None:
    out = tmp_path / "attack.mp4"  # type: ignore[operator]
    render_trace(ns_trace, out=str(out), engine="mpl", style="seq", fps=10)
    assert out.exists() and out.stat().st_size > 1_000  # type: ignore[attr-defined]


def test_manim_falls_back_to_matplotlib(ns_trace: Trace, tmp_path: object) -> None:
    if available_engines()["manim"]:
        pytest.skip("manim is installed: the fallback path is not exercised")
    out = tmp_path / "fallback.mp4"  # type: ignore[operator]
    written = render_trace(ns_trace, out=str(out), engine="manim", style="seq", fps=10)
    assert written.endswith(".gif")
    assert (tmp_path / "fallback.gif").exists()  # type: ignore[operator]


def test_options_expose_the_quality_preset() -> None:
    low = RenderOptions(out="x.gif", quality="l")
    high = RenderOptions(out="x.gif", quality="h")
    assert high.dpi > low.dpi
    assert high.subframes > low.subframes


def test_colours_separate_honest_and_attacker(ns_trace: Trace) -> None:
    from protoverify.viz.common import COLOURS, agent_colour

    attacker = next(a for a in ns_trace.agents if a.kind == "attacker")
    honest = next(a for a in ns_trace.agents if a.kind == "honest")
    assert agent_colour(ns_trace.agents, attacker.id) == COLOURS["attacker"]
    assert agent_colour(ns_trace.agents, honest.id) in (COLOURS["honest"], COLOURS["honest_alt"])


def test_abbreviate_keeps_both_ends() -> None:
    from protoverify.viz.common import abbreviate

    long = "x" * 100
    short = abbreviate(long, 20)
    assert len(short) <= 20 and short.startswith("x") and short.endswith("x")
    assert abbreviate("short", 20) == "short"


def test_knowledge_history_grows(ns_trace: Trace) -> None:
    from protoverify.viz.common import knowledge_history

    history = knowledge_history(ns_trace)
    assert len(history) == len(ns_trace.steps)
    assert history[0] == tuple(ns_trace.steps[0].attacker_new)
    assert len(history[-1]) >= len(history[0])


def test_load_trace_validates(tmp_path: object) -> None:
    from protoverify.core.trace import TraceError
    from protoverify.viz.common import load_trace

    bad = tmp_path / "bad.json"  # type: ignore[operator]
    bad.write_text('{"protocol": ""}', encoding="utf-8")
    with pytest.raises(TraceError):
        load_trace(bad)


def test_interactive_controls_can_be_attached(ns_trace: Trace) -> None:
    """The widget layout works headless; only ``plt.show`` needs a display."""
    import matplotlib.pyplot as plt

    from protoverify.viz.common import RenderOptions
    from protoverify.viz.controls import StepPlayer, attach_controls
    from protoverify.viz.mpl_sequence import SequenceRenderer

    options = RenderOptions(out="interactive.gif", style="seq", fps=10)
    renderer = SequenceRenderer(ns_trace, options)
    figure, (ax, panel) = plt.subplots(1, 2)
    total = len(ns_trace.steps) * options.subframes
    player = attach_controls(figure, object(), renderer, ax, panel, total, options)
    assert isinstance(player, StepPlayer)
    player.seek(4)
    assert player.index == 4
    player.step(-options.subframes)
    assert player.index == 0
    player.step(1000)
    assert player.index == total - 1
    player.restart()
    assert player.index == 0
    plt.close(figure)


@pytest.mark.manim
@pytest.mark.skipif(not available_engines()["manim"], reason="manim is not installed")
@pytest.mark.skipif(shutil.which("ffmpeg") is None, reason="ffmpeg is not installed")
def test_manim_renders_a_scene(ns_trace: Trace, tmp_path: object) -> None:
    out = tmp_path / "scene.mp4"  # type: ignore[operator]
    written = render_trace(ns_trace, out=str(out), engine="manim", style="seq", quality="l")
    assert written.endswith(".mp4")
    assert (tmp_path / "scene.mp4").stat().st_size > 0  # type: ignore[attr-defined]
