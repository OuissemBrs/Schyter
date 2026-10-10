"""Optional GUI tests.

They only check that the module is importable and that the pure helpers work;
the Tk window itself needs a display, so ``run`` is exercised in ``show=False``
mode which renders one frame off-screen.
"""

from __future__ import annotations

import pathlib

import pytest

from conftest import SRC  # noqa: F401  (path bootstrap)

tkinter = pytest.importorskip("tkinter")
matplotlib = pytest.importorskip("matplotlib")
pytest.importorskip("matplotlib.backends.backend_tkagg")

from protoverify import gui


def test_examples_are_listed() -> None:
    assert "ns" in gui.examples()
    assert gui.default_protocol().endswith("ns.spdl")


def test_verify_helper_runs_the_engine() -> None:
    results = gui.verify_file(str(pathlib.Path(gui.default_protocol()).parent / "nsl.spdl"))
    assert results
    assert all(r.verified for r in results)


def test_window_builds_and_renders_one_frame() -> None:
    assert gui.run(gui.default_protocol(), show=False) == 0
