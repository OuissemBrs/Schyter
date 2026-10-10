"""Shared pytest fixtures and helpers."""

from __future__ import annotations

import pathlib
import sys

SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"


def example_path(name: str) -> pathlib.Path:
    """Return the path of the example file ``name`` (with or without suffix)."""
    candidate = EXAMPLES / name
    if candidate.suffix == ".spdl" and candidate.exists():
        return candidate
    return EXAMPLES / f"{name}.spdl"
