"""Every trace the engine emits must survive the *independent* replayer.

``tools/independent_replay.py`` re-derives a trace using only ``core/terms``,
``core/unify`` and ``core/attacker``: no ``replay``, no ``search``, no ``claims``.
Running it over every falsifying trace of every example turns the independent
checker into a standing guard against the engine's own bookkeeping bugs.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file

TOOL = pathlib.Path(__file__).resolve().parents[2] / "tools" / "independent_replay.py"


def _load_tool() -> object:
    spec = importlib.util.spec_from_file_location("independent_replay", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["independent_replay"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def tool() -> object:
    return _load_tool()


@pytest.mark.parametrize("name", ["ns", "replay", "challenge_response_no_id"])
def test_every_falsifying_trace_replays_independently(tool: object, name: str,
                                                       tmp_path: pathlib.Path) -> None:
    protocol = parse_file(str(example_path(name)))
    traces = [r.trace for r in Verifier(protocol, Bounds()).verify() if r.trace is not None]
    assert traces, f"{name} is expected to produce at least one falsifying trace"
    for index, trace in enumerate(traces):
        path = tmp_path / f"{name}_{trace.claim}_{index}.json"
        trace.to_file(path)
        report = tool.check(path, example_path(name))  # type: ignore[attr-defined]
        assert report and all("FAIL" not in line for line in report)


def test_the_tool_detects_a_tampered_trace(tool: object, tmp_path: pathlib.Path) -> None:
    """The independent checker must actually be able to fail."""
    from protoverify.core.trace import Trace

    protocol = parse_file(str(example_path("ns")))
    trace = next(r.trace for r in Verifier(protocol, Bounds()).verify(["R1"])
                 if r.trace is not None)
    tampered = Trace.from_json(
        {**trace.to_json(), "steps": _shift_step(trace.to_json()["steps"])}
    )
    path = tmp_path / "tampered.json"
    tampered.to_file(path)
    with pytest.raises(tool.Failure):  # type: ignore[attr-defined]
        tool.check(path, example_path("ns"))  # type: ignore[attr-defined]


def _shift_step(steps: list[dict]) -> list[dict]:
    """Replace the last message with a different, unbuildable one."""
    out = [dict(s) for s in steps]
    out[-1] = {**out[-1], "msg": "{nr#1}pk(nonexistent-agent)"}
    return out


def test_nsl_responder_never_learns_alice_nonce() -> None:
    """In NSL, Mallory never obtains ``ni`` in any trace that completes Bob."""
    protocol = parse_file(str(example_path("nsl")))
    result = next(r for r in Verifier(protocol, Bounds()).verify(["R1"]))
    assert result.verified
    assert result.trace is None
