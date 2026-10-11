"""Integration tests: properties of the bundled examples.

The verdict tables live elsewhere on purpose:

* ``test_reference.py`` compares the engine against the hand-written
  ``examples/expected_reference.json`` -- the only oracle;
* ``test_regression.py`` compares the engine against the generated
  ``examples/regression_snapshot.json`` -- a change detector.

This module covers the properties that are *not* verdict tables, plus the
statement that neither data file can influence a verification result.
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from conftest import EXAMPLES, SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.cli import list_examples
from protoverify.core.search import Bounds, Verifier
from protoverify.core.trace import Status, Trace
from protoverify.parser import check_or_raise, parse_file

#: Bounds used for the slower examples, matching ``tools/make_snapshot.py``.
BOUNDS = {"nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}


def bounds_for(name: str) -> Bounds:
    return BOUNDS.get(name, Bounds())


def verify(name: str) -> list[object]:
    protocol = parse_file(str(example_path(name)))
    return Verifier(protocol, bounds_for(name)).verify()


@pytest.mark.parametrize("name", sorted(list_examples()))
def test_example_parses_and_passes_static_checks(name: str) -> None:
    check_or_raise(parse_file(str(example_path(name))))


@pytest.mark.slow
def test_ns_responder_claims_are_falsified() -> None:
    results = {r.claim: r for r in verify("ns")}
    assert all(results[c].verified for c in ("I1", "I2", "I3", "I4"))
    assert all(results[c].falsified for c in ("R1", "R2", "R3", "R4"))


@pytest.mark.slow
def test_nsl_is_fully_verified() -> None:
    assert all(r.status == Status.VERIFIED.value for r in verify("nsl"))


def test_every_falsified_claim_carries_a_trace() -> None:
    for result in verify("replay"):
        if result.falsified:
            assert result.trace is not None
            assert result.trace.violation
            assert Trace.from_json(result.trace.to_json()) == result.trace


def test_naming_the_missing_fixes_ns() -> None:
    """NSL differs from NS only in message 2, and that is exactly the fix."""
    ns = parse_file(str(example_path("ns")))
    nsl = parse_file(str(example_path("nsl")))
    assert [r.name for r in ns.roles] == [r.name for r in nsl.roles]
    assert [c.label for _, c in ns.all_claims()] == [c.label for _, c in nsl.all_claims()]
    assert ns.role("I").messages[1].msg != nsl.role("I").messages[1].msg


def test_results_do_not_depend_on_the_data_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Neither oracle nor snapshot is read by the engine; removing both changes nothing."""
    files = (EXAMPLES / "expected_reference.json", EXAMPLES / "regression_snapshot.json")
    backup = {p: p.read_text(encoding="utf-8") for p in files}
    try:
        for path in files:
            path.unlink()
        monkeypatch.setattr("protoverify.cli.examples_dir", lambda: None)
        assert list_examples() == []
        results = {r.claim: r.status for r in verify("ns")}
        assert results["R3"] == Status.FALSIFIED.value
    finally:
        monkeypatch.undo()
        for path, text in backup.items():
            path.write_text(text, encoding="utf-8")
    assert list_examples()


def test_traces_validate_against_the_schema() -> None:
    for result in verify("ns") + verify("replay"):
        if result.trace is None:
            continue
        path = pathlib.Path(tempfile.mkdtemp()) / f"{result.claim}.json"
        assert Trace.from_file(result.trace.to_file(path)).steps == result.trace.steps
