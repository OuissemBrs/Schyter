"""An optional Tkinter GUI: verify a protocol and play its attack trace.

Launch it with ``python -m protoverify.gui``.  The window embeds a matplotlib
canvas; ``run(..., show=False)`` builds and paints the whole interface without a
main loop, which is what the smoke test exercises.
"""

from __future__ import annotations

import pathlib
import queue
import tkinter as tk
from collections.abc import Sequence
from dataclasses import dataclass
from tkinter import filedialog, ttk
from typing import Any, cast

from .core.search import Bounds, ClaimResult, Verifier
from .core.trace import Trace
from .parser import parse_file
from .parser.checks import check_or_raise

__all__ = ["examples", "main", "run"]

from .cli import examples_dir

COLUMNS = (("role", 80), ("claim", 80), ("kind", 100), ("status", 110), ("states", 90))


def examples() -> list[str]:
    """Return the bundled example protocol names."""
    directory = examples_dir()
    if directory is None:
        return []
    return sorted(p.stem for p in directory.glob("*.spdl"))


def default_protocol() -> str:
    """Return the path the window opens with."""
    directory = examples_dir()
    return str((directory or pathlib.Path("examples")) / "ns.spdl")


def verify_file(path: str, claim: str | None = None) -> list[ClaimResult]:
    """Parse, statically check and verify ``path``."""
    protocol = parse_file(path)
    check_or_raise(protocol)
    return Verifier(protocol, Bounds(timeout=30.0)).verify([claim] if claim else None)


@dataclass(slots=True)
class _Widgets:
    """Every widget the callbacks need, in one bundle."""

    root: tk.Tk
    figure: object
    canvas: object
    table: ttk.Treeview
    chosen: tk.StringVar
    claim: tk.StringVar
    status: tk.StringVar
    results: queue.Queue[object]


def run(path: str, show: bool = True) -> int:
    """Open the window; returns the process exit code."""
    widgets = _build(path)
    if show:  # pragma: no cover - interactive only
        widgets.root.mainloop()
    else:
        widgets.root.after(0, _verify_now, widgets)
        widgets.root.update()
        _drain(widgets)
        widgets.root.update()
    return 0


def _build(path: str) -> _Widgets:
    """Create the whole interface without entering the Tk main loop."""
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    from matplotlib.figure import Figure

    root = tk.Tk()
    root.title("ProtoVerify")
    root.geometry("1100x760")
    table = ttk.Treeview(
        root, columns=tuple(name for name, _ in COLUMNS), show="headings", height=8
    )
    for name, width in COLUMNS:
        table.heading(name, text=name)
        table.column(name, width=width)
    table.pack(fill="x", padx=10, pady=6)

    figure = Figure(figsize=(11, 6), dpi=90)
    canvas = FigureCanvasTkAgg(figure, master=root)
    canvas.get_tk_widget().pack(fill="both", expand=True, padx=10, pady=6)

    widgets = _Widgets(
        root=root,
        figure=figure,
        canvas=canvas,
        table=table,
        chosen=tk.StringVar(value=path),
        claim=tk.StringVar(value=""),
        status=tk.StringVar(value="ready"),
        results=queue.Queue(),
    )
    _build_controls(widgets)
    table.bind("<Double-1>", lambda _event: _on_double_click(widgets))  # pragma: no cover
    return widgets


def _build_controls(widgets: _Widgets) -> None:
    """Lay out the button bar under the table."""
    bar = ttk.Frame(widgets.root)
    bar.pack(fill="x", padx=10)
    ttk.Entry(bar, textvariable=widgets.chosen).pack(side="left", fill="x", expand=True, padx=4)
    ttk.Button(bar, text="Browse", command=lambda: _browse(widgets)).pack(side="left")  # pragma: no cover
    ttk.Entry(bar, textvariable=widgets.claim, width=8).pack(side="left", padx=4)
    ttk.Button(bar, text="Verify", command=lambda: _verify_now(widgets)).pack(side="left", padx=4)
    ttk.Label(bar, textvariable=widgets.status).pack(side="left", padx=8)


def _browse(widgets: _Widgets) -> None:  # pragma: no cover - interactive only
    picked = filedialog.askopenfilename(filetypes=[("SPDL", "*.spdl"), ("All", "*")])
    if picked:
        widgets.chosen.set(picked)


def _verify_now(widgets: _Widgets) -> None:
    """Kick off a verification and schedule the result drain."""
    widgets.status.set("verifying ...")
    try:
        widgets.results.put(verify_file(widgets.chosen.get(), widgets.claim.get() or None))
    except Exception as exc:  # pragma: no cover - interactive only
        widgets.status.set(str(exc))


def _drain(widgets: _Widgets) -> None:
    """Render whatever verification results are waiting in the queue."""
    try:
        payload = widgets.results.get_nowait()
    except queue.Empty:
        widgets.root.after(120, _drain, widgets)
        return
    _show_results(widgets, cast(list[ClaimResult], payload))


def _show_results(widgets: _Widgets, results: list[ClaimResult]) -> None:
    """Fill the table and draw the first attack trace found."""
    widgets.table.delete(*widgets.table.get_children())
    first: Trace | None = None
    for result in results:
        widgets.table.insert(
            "", "end",
            values=(result.role, result.claim, result.kind, result.status, result.states),
        )
        if first is None and result.trace is not None:
            first = result.trace
    for row in widgets.table.get_children():
        if widgets.table.set(row, "status") == "FALSIFIED":
            widgets.table.tag_configure(row, background="#fee2e2")
    if first is not None:
        _draw(widgets, first)
        cast(Any, widgets.canvas).draw_idle()
        widgets.status.set("done - double click a FALSIFIED row to animate it")
    else:
        widgets.status.set(f"done - {len(results)} claim(s) checked")


def _on_double_click(widgets: _Widgets) -> None:  # pragma: no cover - interactive only
    selection = widgets.table.selection()
    if not selection:
        return
    label = widgets.table.set(selection[0], "claim")
    for result in verify_file(widgets.chosen.get(), label):
        if result.claim == label and result.trace is not None:
            _draw(widgets, result.trace)
            cast(Any, widgets.canvas).draw_idle()
            widgets.status.set(f"attack trace for {label}")
            return


def _draw(widgets: _Widgets, trace: Trace) -> None:
    """Render the final frame of ``trace`` into the embedded canvas."""
    from .viz.common import RenderOptions
    from .viz.mpl_sequence import SequenceRenderer

    widgets.figure.clear()  # type: ignore[attr-defined]
    ax, panel = widgets.figure.subplots(  # type: ignore[attr-defined]
        1, 2, gridspec_kw={"width_ratios": [3.2, 1.0]}
    )
    renderer = SequenceRenderer(trace, RenderOptions(out="gui", style="seq"))
    renderer.draw(ax, panel, len(trace.steps) * 6 - 1)
    cast(Any, widgets.canvas).draw_idle()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of ``python -m protoverify.gui``."""
    del argv
    return run(default_protocol())


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
