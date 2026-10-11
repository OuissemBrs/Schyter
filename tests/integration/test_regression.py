"""Change detector: engine output vs the generated ``regression_snapshot.json``.

This test deliberately can only catch *changes*: the snapshot is produced by
``tools/make_snapshot.py`` from the engine's own output, so it confirms the engine
agrees with its past self and nothing more. The oracle is
``tests/integration/test_reference.py``.
"""

from __future__ import annotations

import json

import pytest

from conftest import EXAMPLES, SRC  # noqa: F401  (path bootstrap)
from protoverify.cli import list_examples
from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file

SNAPSHOT = EXAMPLES / "regression_snapshot.json"
BOUNDS = {"nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}


def snapshot() -> dict[str, dict[str, object]]:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


@pytest.mark.slow
@pytest.mark.parametrize("name", list_examples())
def test_engine_matches_the_snapshot(name: str) -> None:
    recorded = snapshot()[name]["claims"]  # type: ignore[index]
    protocol = parse_file(str(EXAMPLES / f"{name}.spdl"))
    actual = {r.claim: r.status for r in Verifier(protocol, BOUNDS.get(name, Bounds())).verify()}
    differing = sorted(
        claim for claim in set(recorded) | set(actual)  # type: ignore[operator]
        if recorded.get(claim) != actual.get(claim)  # type: ignore[union-attr]
    )
    if differing:
        lines = [
            f"{name}: snapshot != engine for {len(differing)} claim(s)",
            f"{'claim':<6} {'snapshot':<12} engine",
        ]
        lines += [
            f"{c:<6} {recorded.get(c)!s:<12} {actual.get(c)}"  # type: ignore[union-attr]
            for c in differing
        ]
        lines.append(
            "If this change is intended: python tools/make_snapshot.py, "
            "then explain it in DECISIONS.md."
        )
        raise AssertionError("\n".join(lines))
    assert actual


def test_snapshot_is_marked_as_non_authoritative() -> None:
    data = snapshot()
    assert set(data) == set(list_examples())
    for name in data:
        assert "description" in data[name] and "bounds" in data[name]


def test_snapshot_is_not_the_oracle() -> None:
    """The reference file must exist and be a different file."""
    reference = EXAMPLES / "expected_reference.json"
    assert reference.exists()
    assert reference != SNAPSHOT
    assert "source" in json.loads(reference.read_text(encoding="utf-8"))["protocols"]["ns"]
