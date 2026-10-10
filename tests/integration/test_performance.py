"""Performance guards: the bundled examples must stay fast enough to be usable."""

from __future__ import annotations

import time

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file


def timed(name: str, bounds: Bounds) -> float:
    protocol = parse_file(str(example_path(name)))
    start = time.monotonic()
    Verifier(protocol, bounds).verify()
    return time.monotonic() - start


@pytest.mark.slow
def test_nsl_with_three_runs_under_five_seconds() -> None:
    assert timed("nsl", Bounds(max_runs=3, timeout=60.0)) < 5.0


@pytest.mark.slow
def test_full_ns_claim_set_under_ten_seconds() -> None:
    assert timed("ns", Bounds(timeout=60.0)) < 10.0


@pytest.mark.slow
def test_every_example_verifies_quickly() -> None:
    for name in ("challenge_response", "challenge_response_no_id", "replay"):
        assert timed(name, Bounds(timeout=60.0)) < 5.0


def test_a_tiny_state_budget_yields_unknown_not_a_wrong_answer() -> None:
    protocol = parse_file(str(example_path("nsl")))
    results = Verifier(protocol, Bounds(max_states=5, timeout=60.0)).verify()
    assert results
    for result in results:
        assert result.status in ("VERIFIED", "UNKNOWN")
        if result.status == "UNKNOWN":
            assert result.reason
            assert result.trace is None
