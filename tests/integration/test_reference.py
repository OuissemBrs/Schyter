"""Reference oracle: engine output vs the hand-written ``expected_reference.json``.

``examples/expected_reference.json`` was written by hand from the specification,
the literature and first-principles reasoning (see DECISIONS.md). It is the only
oracle. This test is what makes a *wrong* engine answer visible, which
``test_regression.py`` (snapshot comparison) structurally cannot do.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from conftest import EXAMPLES, SRC  # noqa: F401  (path bootstrap)
from protoverify.cli import list_examples
from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file

REFERENCE = EXAMPLES / "expected_reference.json"
SNAPSHOT = EXAMPLES / "regression_snapshot.json"

#: Bounds used for the slow examples when regenerating the snapshot.
BOUNDS = {"nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}


@dataclass(frozen=True, slots=True)
class Row:
    """One line of the reference / engine / snapshot table."""

    protocol: str
    claim: str
    reference: str
    engine: str
    snapshot: str

    @property
    def agree(self) -> bool:
        """True when all three columns are identical."""
        return self.reference == self.engine == self.snapshot


def reference() -> dict[str, dict[str, object]]:
    return json.loads(REFERENCE.read_text(encoding="utf-8"))


def snapshot() -> dict[str, dict[str, object]]:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def engine_rows() -> list[Row]:
    """Run the engine on every example and build the comparison table."""
    ref = reference()["protocols"]  # type: ignore[index]
    snap = snapshot()
    rows: list[Row] = []
    for name in list_examples():
        protocol = parse_file(str(EXAMPLES / f"{name}.spdl"))
        results = Verifier(protocol, BOUNDS.get(name, Bounds())).verify()
        expected = ref[name]["claims"]  # type: ignore[index]
        recorded = snap[name]["claims"]  # type: ignore[index]
        for result in results:
            rows.append(
                Row(
                    protocol=name,
                    claim=result.claim,
                    reference=expected[result.claim],  # type: ignore[index]
                    engine=result.status,
                    snapshot=recorded[result.claim],  # type: ignore[index]
                )
            )
    return rows


def table(rows: list[Row]) -> str:
    """Render the comparison table, marking every disagreement."""
    head = f"{'protocol':<24} {'claim':<6} {'reference':<10} {'engine':<10} {'snapshot':<10} ok"
    lines = [head, "-" * len(head)]
    for row in rows:
        mark = " " if row.agree else "  <-- DISAGREEMENT"
        lines.append(
            f"{row.protocol:<24} {row.claim:<6} {row.reference:<10} "
            f"{row.engine:<10} {row.snapshot:<10}{mark}"
        )
    return "\n".join(lines)


def disagreements(rows: list[Row]) -> list[Row]:
    return [r for r in rows if not r.agree]


@pytest.mark.parametrize("name", list_examples())
def test_every_example_is_covered_by_the_reference(name: str) -> None:
    ref = reference()["protocols"]  # type: ignore[index]
    assert name in ref, f"{name} has no entry in expected_reference.json"
    protocol = parse_file(str(EXAMPLES / f"{name}.spdl"))
    labels = [c.label for _, c in protocol.all_claims()]
    assert set(labels) == set(ref[name]["claims"])  # type: ignore[index]


def test_reference_file_is_not_a_snapshot() -> None:
    """The oracle must not be a byte copy of the generated file."""
    ref = reference()
    snap = snapshot()
    assert set(ref["protocols"]) == set(snap)  # type: ignore[index]
    for name, entry in ref["protocols"].items():  # type: ignore[union-attr]
        assert entry["source"], f"{name} has no 'source' field"
        assert entry["reasoning"], f"{name} has no reasoning"


@pytest.mark.slow
def test_engine_matches_the_reference_oracle() -> None:
    rows = engine_rows()
    bad = disagreements(rows)
    report = table(rows)
    if bad:
        raise AssertionError(
            "the engine disagrees with the hand-written reference:\n"
            f"{report}\n\n"
            "Do NOT edit expected_reference.json to match the engine. Decide whether\n"
            "the reference or the engine is wrong, record the evidence in DECISIONS.md,\n"
            "and fix the engine if it is the engine."
        )
    assert report


@pytest.mark.slow
def test_the_comparison_table_is_printable() -> None:
    """The table itself is the deliverable of Issue 2; keep it renderable."""
    text = table(engine_rows())
    assert "reference" in text and "engine" in text and "snapshot" in text
    print(text)
