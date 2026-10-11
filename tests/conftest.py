"""Shared pytest fixtures and helpers.

Hypothesis configuration lives in ``pyproject.toml``:

* the default profile is **derandomised** with ``--hypothesis-seed=0`` forced via
  ``addopts``, so CI is reproducible -- a green run today is the same green run
  tomorrow, and a failure replays from the printed seed;
* ``pytest --hypothesis-profile=thorough`` raises ``max_examples`` to 500 for a
  deeper local sweep while staying deterministic.
"""

from __future__ import annotations

import pathlib
import sys

from hypothesis import settings

settings.register_profile("ci", derandomize=True)
settings.register_profile("thorough", derandomize=True, max_examples=500)
settings.load_profile("ci")

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
