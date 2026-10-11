"""Claim implication hierarchy: Nisynch => Niagree => Weakagree => Alive.

The four agreement predicates are evaluated on every concrete trace the search
visits for every bundled example.  A satisfied stronger claim must always come
with a satisfied weaker one, on real traces and not only on paper.
"""

from __future__ import annotations

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.cli import list_examples
from protoverify.core import claims as semantics
from protoverify.core.run import Run
from protoverify.core.search import Bounds, Searcher, Verifier
from protoverify.core.terms import Term
from protoverify.parser import parse_file

BOUNDS = {"nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}
MAX_TRACES = 300


def collect_traces(name: str) -> list[tuple[Run, dict[int, Run], dict[str, Term]]]:
    """Return ``(claimant run, all runs, substitution)`` for many terminal traces."""
    protocol = parse_file(str(example_path(name)))
    search: Searcher = Verifier(protocol, BOUNDS.get(name, Bounds())).searcher
    found: list[tuple[Run, dict[int, Run], dict[str, Term]]] = []
    for role_name in dict.fromkeys(r for r, _ in protocol.all_claims()):
        agent = search._default_agent(role_name)
        for peer in search.peer_pool(agent):
            _walk(search, search._initial_state(role_name, agent, peer), found)
            if len(found) >= MAX_TRACES:
                return found
    return found


def _walk(
    search: Searcher, state: object, found: list[tuple[Run, dict[int, Run], dict[str, Term]]]
) -> None:
    ready = search._ready(state)  # type: ignore[arg-type]
    if not ready:
        runs = state.runs  # type: ignore[attr-defined]
        found.extend((run, runs, state.sigma) for run in runs.values())  # type: ignore[attr-defined]
        return
    for event in ready:
        for child in search._advance(state, event):  # type: ignore[attr-defined]
            _walk(search, child, found)


def hierarchy_holds(claimant: Run, runs: dict[int, Run], sigma: dict[str, Term],
                    partner: str | None) -> bool:
    """Check ``Nisynch => Niagree => Weakagree => Alive`` on one trace.

    Both directions matter.  *Satisfied* is the implication the hierarchy states:
    a satisfied stronger claim must come with a satisfied weaker one.  The
    contrapositive is what makes a set of verdicts coherent: because ``Niagree``
    is defined to *include* ``Weakagree``, and ``Weakagree`` to include ``Alive``,
    a falsified ``Alive`` -- the claimant completed with no partner run at all --
    forces ``Weakagree``, ``Niagree`` and ``Nisynch`` to be falsified as well.  An
    engine that reported ``Alive`` FALSIFIED next to ``Nisynch`` VERIFIED would be
    contradicting itself.
    """
    if partner is None:
        return True
    alive = any(r.role.name == partner for r in runs.values())
    weak = semantics.weakagree(claimant, runs, partner, sigma)
    non_injective = semantics.niagree(claimant, runs, partner, sigma)
    injective = semantics.nisynch(claimant, runs, partner, sigma)
    assert not weak or alive, "Weakagree satisfied but Alive is false"
    assert not non_injective or weak, "Niagree satisfied but Weakagree is false"
    assert not injective or non_injective, "Nisynch satisfied but Niagree is false"
    if not alive:
        # The whole partner side is missing, so nothing above Alive can hold.
        assert not weak, "Alive is false but Weakagree is satisfied"
        assert not non_injective, "Alive is false but Niagree is satisfied"
        assert not injective, "Alive is false but Nisynch is satisfied"
    return True


def agreement_sides_are_coherent(verdicts: dict[str, str]) -> None:
    """A falsified ``Alive`` must drag every stronger agreement claim down with it.

    This is checked on whole verdicts rather than on single traces, because it is
    a statement about what the engine is allowed to report for one role.
    """
    alive = verdicts.get("Alive")
    if alive != "FALSIFIED":
        return
    for kind in ("Weakagree", "Niagree", "Nisynch"):
        status = verdicts.get(kind)
        assert status != "VERIFIED", (
            f"Alive is FALSIFIED but {kind} is VERIFIED: the claim hierarchy is "
            f"contradicted -- {kind} is defined to include Alive"
        )


@pytest.mark.parametrize("name", list_examples())
def test_implication_hierarchy_holds_on_real_traces(name: str) -> None:
    protocol = parse_file(str(example_path(name)))
    partners = {
        role: _partner(protocol, role) for role in dict.fromkeys(r for r, _ in protocol.all_claims())
    }
    traces = collect_traces(name)
    assert traces, f"no terminal trace was visited for {name}"
    checked = 0
    for claimant, runs, sigma in traces:
        partner = partners[claimant.role.name]
        hierarchy_holds(claimant, runs, sigma, partner)
        checked += 1
    assert checked == len(traces)


def _partner(protocol: object, role: str) -> str | None:
    from protoverify.parser.checks import resolve_partner

    for owner, claim in protocol.all_claims():  # type: ignore[attr-defined]
        if owner == role:
            return resolve_partner(protocol, claim)  # type: ignore[arg-type]
    return None


def test_the_paper_hierarchy_is_explicit() -> None:
    assert semantics.IMPLICATION_ORDER == ("Alive", "Weakagree", "Niagree", "Nisynch")


@pytest.mark.slow
@pytest.mark.parametrize("name", list_examples())
def test_reported_verdicts_never_contradict_the_hierarchy(name: str) -> None:
    """A falsified ``Alive`` must not sit next to a VERIFIED stronger claim."""
    protocol = parse_file(str(example_path(name)))
    results = Verifier(protocol, BOUNDS.get(name, Bounds())).verify()
    by_role: dict[str, dict[str, str]] = {}
    for result in results:
        by_role.setdefault(result.role, {})[result.kind] = result.status
    for verdicts in by_role.values():
        agreement_sides_are_coherent(verdicts)


def test_the_coherence_check_can_actually_fail() -> None:
    """Guard against the invariant silently becoming a no-op."""
    agreement_sides_are_coherent({"Alive": "FALSIFIED", "Nisynch": "FALSIFIED"})
    agreement_sides_are_coherent({"Alive": "VERIFIED", "Nisynch": "VERIFIED"})
    agreement_sides_are_coherent({"Nisynch": "FALSIFIED"})  # no Alive claim at all
    with pytest.raises(AssertionError, match="contradicted"):
        agreement_sides_are_coherent({"Alive": "FALSIFIED", "Nisynch": "VERIFIED"})
