"""Integration tests: every example against ``examples/expected.json``.

The expected file is *data*, not configuration: nothing in the engine reads it,
so deleting it cannot change a single verification result.  ``test_results_do_not_
depend_on_expected_json`` asserts exactly that.
"""

from __future__ import annotations

import json

import pytest

from conftest import EXAMPLES, SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.cli import list_examples
from protoverify.core.search import Bounds, Verifier
from protoverify.core.trace import Status, Trace
from protoverify.parser import check_or_raise, parse_file

EXPECTED = EXAMPLES / "expected.json"
SLOW = {"ns", "nsl", "yahalom", "replay"}


def expected() -> dict[str, dict[str, object]]:
    return json.loads(EXPECTED.read_text(encoding="utf-8"))


def bounds_for(name: str) -> Bounds:
    if name == "nsl":
        return Bounds(max_runs=3)
    if name == "yahalom":
        return Bounds(timeout=60.0)
    return Bounds()


def verify(name: str) -> list[object]:
    protocol = parse_file(str(example_path(name)))
    return Verifier(protocol, bounds_for(name)).verify()


@pytest.fixture(scope="module")
def expectations() -> dict[str, dict[str, object]]:
    return expected()


@pytest.mark.parametrize("name", sorted(list_examples()))
def test_example_parses_and_passes_static_checks(name: str) -> None:
    check_or_raise(parse_file(str(example_path(name))))


@pytest.mark.parametrize("name", sorted(list_examples()))
def test_example_matches_expected(name: str, expectations: dict[str, dict[str, object]]) -> None:
    if name in SLOW:
        pytest.mark.slow(f"{name} exercises the full search")
    actual = {r.claim: r.status for r in verify(name)}
    assert actual == expectations[name]["claims"]


@pytest.mark.slow
def test_ns_responder_claims_are_falsified() -> None:
    results = {r.claim: r for r in verify("ns")}
    assert all(results[c].verified for c in ("I1", "I2", "I3", "I4"))
    assert all(results[c].falsified for c in ("R1", "R2", "R3", "R4"))


@pytest.mark.slow
def test_nsl_is_fully_verified() -> None:
    results = verify("nsl")
    assert all(r.status == Status.VERIFIED.value for r in results)


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
    ns_second = ns.role("I").messages[1].msg
    nsl_second = nsl.role("I").messages[1].msg
    assert ns_second != nsl_second


def test_results_do_not_depend_on_expected_json(
    tmp_path: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    backup = EXPECTED.read_text(encoding="utf-8")
    try:
        EXPECTED.unlink()
        monkeypatch.setattr("protoverify.cli.examples_dir", lambda: None)  # type: ignore[arg-type]
        assert list_examples() == []
        results = {r.claim: r.status for r in verify("ns")}
        assert results["R3"] == Status.FALSIFIED.value
    finally:
        monkeypatch.undo()
        EXPECTED.write_text(backup, encoding="utf-8")
    assert EXPECTED.exists()
    assert "ns" in list_examples()


def test_traces_validate_against_the_schema() -> None:
    for result in verify("ns") + verify("replay"):
        if result.trace is None:
            continue
        restored = Trace.from_file(result.trace.to_file(_tmp(result.claim)))
        assert restored.steps == result.trace.steps


def _tmp(name: str) -> object:
    import tempfile
    from pathlib import Path

    return Path(tempfile.mkdtemp()) / f"{name}.json"
