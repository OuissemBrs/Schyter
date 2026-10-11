"""Regression tests for ``attacker_new``: what the attacker really learns.

The knowledge recorded in a trace must be the *Dolev-Yao* gain of a message, not
its syntactic surface.  A nonce sealed inside a ciphertext addressed to somebody
else is not learned, and reporting it as such was a real defect found by the
independent replay in ``tools/independent_replay.py``.
"""

from __future__ import annotations

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.replay import _newly_learned
from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file

NS = """
const c: Ticket;
protocol leak(A,B) {
  role A {
    fresh na: Nonce;  fresh nb: Nonce;
    send_1(A,B, {na,nb}pk(A));
    recv_2(B,A, na);
    send_3(A,B, {nb}pk(B));
    claim_x(A,Secret,na);
    claim_y(A,Secret,nb);
  }
  role B {
    var na: Nonce;  var nb: Nonce;
    recv_1(A,B, {na,nb}pk(A));
    send_2(B,A, na);
    recv_3(A,B, {nb}pk(B));
    claim_p(B,Niagree);
  }
}
"""


def learned_for(protocol_source: str, path: str) -> dict[int, tuple[str, ...]]:
    """Return ``step number -> attacker_new`` of the first falsifying trace."""
    from protoverify.parser import parse

    protocol = parse(protocol_source)
    for result in Verifier(protocol, Bounds()).verify():
        if result.trace is None:
            continue
        if result.claim == path.split("/")[-1].split(".")[0] or result.claim == path:
            return {s.i: s.attacker_new for s in result.trace.steps}
    for result in Verifier(protocol, Bounds()).verify():
        if result.trace is not None:
            return {s.i: s.attacker_new for s in result.trace.steps}
    raise AssertionError("expected at least one falsified claim")  # pragma: no cover


def test_a_sealed_nonce_is_not_reported_as_learned() -> None:
    """``{na,nb}pk(A)`` reveals nothing when Mallory does not hold ``sk(A)``."""
    learned = learned_for(NS, "x")
    first = learned[1]
    assert "na" not in str(first)
    assert "nb" not in str(first)


def test_newly_learned_is_the_closure_difference() -> None:
    from protoverify.core.attacker import Attacker
    from protoverify.core.terms import AsymEnc, Atom, Pk, Tuple

    adversary = Attacker(agents=["A", "B", "M"], compromised=["M"])
    before = adversary.initial()
    sealed = AsymEnc(Tuple((Atom("na"), Atom("nb"))), Pk(Atom("A")))
    closure, _ = adversary.analyze(before | {sealed})
    assert _newly_learned(closure, set(before)) == ()
    opened = AsymEnc(Tuple((Atom("na"), Atom("nb"))), Pk(Atom("M")))
    closure2, _ = adversary.analyze(before | {opened})
    assert _newly_learned(closure2, set(before)) == ("na", "nb")


def test_lowe_trace_reports_the_real_leaks() -> None:
    """In NS the attacker learns ``ni`` at step 1 and ``nr`` at step 5 only."""
    protocol = parse_file(str(example_path("ns")))
    result = next(
        r for r in Verifier(protocol, Bounds()).verify(["R1"]) if r.trace is not None
    )
    trace = result.trace
    assert trace is not None
    learned = {s.i: s.attacker_new for s in trace.steps}
    assert learned[1] == ("ni#2",)
    assert learned[3] == ()
    assert learned[4] == ()
    assert learned[5] == ("nr#1",)
    assert learned[6] == ()


def test_no_reported_term_was_already_known() -> None:
    """A trace never reports the same term as learned twice."""
    for name in ("ns", "nsl", "replay", "challenge_response", "challenge_response_no_id"):
        protocol = parse_file(str(example_path(name)))
        for result in Verifier(protocol, Bounds()).verify():
            if result.trace is None:
                continue
            seen: set[str] = set()
            for step in result.trace.steps:
                assert not (set(step.attacker_new) & seen), f"{name}/{result.claim}"
                seen |= set(step.attacker_new)


@pytest.mark.parametrize("name", ["ns", "nsl"])
def test_claim_verdicts_are_unaffected(name: str) -> None:
    """The display filter must never influence a claim verdict."""
    protocol = parse_file(str(example_path(name)))
    verdicts = {r.claim: r.status for r in Verifier(protocol, Bounds()).verify()}
    expected = {
        "ns": {"R1": "FALSIFIED", "R2": "FALSIFIED", "R3": "FALSIFIED", "R4": "FALSIFIED"},
        "nsl": {"R1": "VERIFIED", "R2": "VERIFIED", "R3": "VERIFIED", "R4": "VERIFIED"},
    }
    for claim, status in expected[name].items():
        assert verdicts[claim] == status
