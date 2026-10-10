"""Terminal reporting: coloured tables, plain-ANSI or no colour at all."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence

from .core.search import ClaimResult
from .core.trace import Status, Trace

__all__ = ["Palette", "render_table", "render_trace", "write_trace"]

_COLOURS = {
    Status.VERIFIED.value: "32",
    Status.FALSIFIED.value: "31",
    Status.UNKNOWN.value: "33",
}


class Palette:
    """Plain-ANSI colouring that can be switched off entirely."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    @classmethod
    def detect(cls, stream: object = None, force: bool | None = None) -> Palette:
        """Pick a palette based on ``--color`` and whether the stream is a tty."""
        if force is not None:
            return cls(force)
        target = stream if stream is not None else sys.stdout
        if os.environ.get("NO_COLOR"):
            return cls(False)
        return cls(bool(getattr(target, "isatty", lambda: False)()))

    def status(self, value: str, text: str | None = None) -> str:
        """Colour ``text`` (default ``value``) according to a claim status."""
        return self.colour(_COLOURS.get(value, "0"), text if text is not None else value)

    def colour(self, code: str, text: str) -> str:
        """Wrap ``text`` in an ANSI colour code when colouring is enabled."""
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        """Wrap ``text`` in the ANSI bold attribute."""
        return self.colour("1", text)

    def dim(self, text: str) -> str:
        """Wrap ``text`` in the ANSI dim attribute."""
        return self.colour("2", text)


def render_table(protocol: str, results: Sequence[ClaimResult], palette: Palette) -> str:
    """Render the per-claim result table."""
    headers = ("role", "claim", "kind", "status", "states", "seconds")
    rows = [
        (r.role, r.claim, r.kind, r.status, str(r.states), f"{r.seconds:.2f}")
        for r in results
    ]
    widths = [
        max([len(headers[i]), *(len(row[i]) for row in rows)])
        for i in range(len(headers))
    ]
    out = [palette.bold(f"protocol {protocol}"), ""]
    out.append("  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))))
    out.append("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in rows:
        cells = [row[i].ljust(widths[i]) for i in range(len(headers))]
        cells[3] = palette.status(row[3], row[3].ljust(widths[3]))
        out.append("  ".join(cells))
    summary = _summary(results, palette)
    if summary:
        out.extend(["", summary])
    return "\n".join(out)


def _summary(results: Sequence[ClaimResult], palette: Palette) -> str:
    """Render the one-line count of verified / falsified / unknown claims."""
    counts = {status.value: 0 for status in Status}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    parts = [
        palette.status(status.value, f"{counts[status.value]} {status.value.lower()}")
        for status in Status
        if counts.get(status.value)
    ]
    reason = next((r.reason for r in results if r.reason), "")
    line = f"{len(results)} claim(s): " + ", ".join(parts)
    return f"{line}  ({reason})" if reason else line


def render_trace(trace: Trace, palette: Palette) -> str:
    """Render the human-readable form of a falsifying trace."""
    lines = [palette.bold(f"attack trace for {trace.protocol}/{trace.claim} "
                         f"({trace.status})")]
    lines.append(palette.dim(f"  bounds: {trace.bounds}"))
    for step in trace.steps:
        tag = palette.status(Status.FALSIFIED.value, step.type) if step.is_attacker else step.type
        lines.append(f"  {step.i:>2}. [{tag}] {step.frm} -> {step.to}  {step.msg}")
        lines.append(f"       {palette.dim(step.note)}")
        if step.attacker_new:
            lines.append(
                palette.dim(f"       attacker learned: {', '.join(step.attacker_new)}")
            )
    lines.append("")
    lines.append(palette.colour("31", f"  violation: {trace.violation}"))
    return "\n".join(lines)


def write_trace(trace: Trace, path: str) -> str:
    """Write ``trace`` to ``path`` and return the message to show the user."""
    written = trace.to_file(path)
    return f"wrote trace for {trace.protocol}/{trace.claim} to {written}"
