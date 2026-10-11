"""Sharing one search between claims of the same ``(role, partner)`` group.

The optimisation exists because a group of claims is answered by *the same*
search: the state space and the goal set do not depend on which claim is being
proved, only on the group.  If that is true, running the search once per claim
must produce byte-identical results -- verdict, trace and all.  This module
checks exactly that for every bundled example, so the optimisation can never
quietly change an answer.
"""

from __future__ import annotations

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file

BOUNDS = {"nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}

EXAMPLES = [
    "ns", "nsl", "challenge_response", "challenge_response_no_id", "replay", "yahalom",
]


def bounds_for(name: str) -> Bounds:
    return BOUNDS.get(name, Bounds())


def summary(results: object) -> dict[str, tuple[str, int]]:
    """``claim -> (status, number of trace steps)``, the comparable part of a result."""
    return {r.claim: (r.status, len(r.trace.steps) if r.trace else -1) for r in results}  # type: ignore[attr-defined]


@pytest.mark.slow
@pytest.mark.parametrize("name", EXAMPLES)
def test_shared_and_per_claim_searches_agree(name: str) -> None:
    protocol = parse_file(str(example_path(name)))
    shared = Verifier(protocol, bounds_for(name)).verify()
    per_claim = Verifier(protocol, bounds_for(name)).verify(share=False)

    assert summary(shared) == summary(per_claim), (
        f"{name}: sharing the search changed a verdict\n"
        f"{'claim':<6} {'shared':<22} per-claim"
    )
    assert [r.claim for r in shared] == [r.claim for r in per_claim]


@pytest.mark.slow
@pytest.mark.parametrize("name", EXAMPLES)
def test_a_single_claim_agrees_with_the_shared_group(name: str) -> None:
    """Each claim on its own must give the same answer as in the shared run."""
    protocol = parse_file(str(example_path(name)))
    shared = {r.claim: r for r in Verifier(protocol, bounds_for(name)).verify()}
    for label in list(shared):
        alone = Verifier(protocol, bounds_for(name)).verify([label])[0]
        reference = shared[label]
        assert alone.status == reference.status, f"{name}/{label}: status differs"
        assert (alone.trace is None) == (reference.trace is None), f"{name}/{label}: trace differs"
        if alone.trace is not None:
            assert alone.trace.steps == reference.trace.steps, f"{name}/{label}: steps differ"


@pytest.mark.slow
def test_sharing_never_turns_verified_into_unknown() -> None:
    """The shared early exit fires only when *every* claim has a counterexample."""
    protocol = parse_file(str(example_path("ns")))
    shared = {r.claim: r for r in Verifier(protocol, Bounds()).verify()}
    assert {c: r.status for c, r in shared.items()} == {
        "I1": "VERIFIED", "I2": "VERIFIED", "I3": "VERIFIED", "I4": "VERIFIED",
        "R1": "FALSIFIED", "R2": "FALSIFIED", "R3": "FALSIFIED", "R4": "FALSIFIED",
    }
    assert all(r.reason == "" for r in shared.values())


@pytest.mark.slow
def test_one_search_really_is_shared() -> None:
    """The shared run must not do the work of four searches.

    With one search per ``(role, partner)`` group the reported state count is the
    *same* for every claim of that group.  If claims were verified one at a time
    the counts would differ per claim.
    """
    protocol = parse_file(str(example_path("ns")))
    results = Verifier(protocol, Bounds()).verify()
    by_role: dict[str, set[int]] = {}
    for result in results:
        by_role.setdefault(result.role, set()).add(result.states)
    for role, counts in by_role.items():
        assert len(counts) == 1, f"role {role} was not searched once: states={sorted(counts)}"
