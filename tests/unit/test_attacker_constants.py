"""Attacker-generated constants: what they add, and what they must never do.

The adversary may invent values of its own (``nM``, ``kM``, ``dM``).  That is
*sound*, because it created them.  What stays unsound -- and is forbidden -- is
guessing an honest party's fresh value before that value has been sent.
"""

from __future__ import annotations

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.attacker import ATTACKER_CONSTANTS, Attacker
from protoverify.core.search import Bounds, Searcher, Verifier
from protoverify.core.terms import Atom
from protoverify.parser import parse, parse_file

#: Bounds matching ``tools/make_snapshot.py`` so verdicts are comparable.
BOUNDS = {"nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}

#: Every bundled example.
EXAMPLES = [
    "ns", "nsl", "challenge_response", "challenge_response_no_id", "replay", "yahalom",
]

#: A receive of a bare nonce: the attacker can answer it with a value of its own.
BARE_NONCE = """
protocol bare(A,B) {
  role A {
    fresh na: Nonce;
    send_1(A,B, na);
    claim_A1(A,Secret,na);
  }
  role B {
    var na: Nonce;
    recv_1(A,B, na);
    claim_B1(B,Alive);
  }
}
"""


def searcher(source: str) -> Searcher:
    protocol = parse(source)
    adversary = Attacker(agents=["A", "B", "M"], compromised=["M"])
    return Searcher(protocol, adversary, Bounds(), agent_pool=["A", "B", "M"])


# -- the constants exist ------------------------------------------------
def test_the_attacker_knows_its_own_constants() -> None:
    knowledge = Attacker(agents=["A", "B", "M"], compromised=["M"]).initial()
    for value in ATTACKER_CONSTANTS.values():
        assert Atom(value) in knowledge


def test_there_is_one_constant_per_basic_value_type() -> None:
    assert set(ATTACKER_CONSTANTS) == {"Nonce", "Key", "Data"}
    assert len(set(ATTACKER_CONSTANTS.values())) == len(ATTACKER_CONSTANTS)


@pytest.mark.parametrize("name", EXAMPLES)
def test_no_example_redeclares_an_attacker_constant(name: str) -> None:
    """``nM``/``kM``/``dM`` must not collide with a declared constant or fresh name."""
    text = example_path(name).read_text(encoding="utf-8")
    for value in ATTACKER_CONSTANTS.values():
        assert value not in text, f"{name} mentions the attacker constant {value}"


# -- they may answer a receive -----------------------------------------
def test_a_nonce_receive_can_be_answered_with_the_attacker_nonce() -> None:
    engine = searcher(BARE_NONCE)
    state = engine._initial_state("B", "B", "A")
    run = state.runs[1]
    recv = next(e for e in run.events if getattr(e, "label", None) == 1)
    bindings = {c.sigma["r1::na"].text() for c in engine._attacker_branches(state, (1, 1), run, recv)}
    assert "nM" in bindings, sorted(bindings)


@pytest.mark.parametrize(
    ("declared", "expected"),
    [("Nonce", "nM"), ("Key", "kM"), ("Data", "dM")],
)
def test_each_value_type_gets_its_own_constant(declared: str, expected: str) -> None:
    engine = searcher(BARE_NONCE)
    assert engine._candidates(declared, "v", frozenset())[0].text() == expected


def test_a_nonce_variable_is_not_offered_the_attacker_key() -> None:
    engine = searcher(BARE_NONCE)
    generated = [t.text() for t in engine._candidates("Nonce", "v", frozenset())]
    assert generated[0] == "nM"
    assert engine._candidates("Key", "v", frozenset())[0].text() == "kM"


def test_agent_and_ticket_variables_still_get_an_invented_name() -> None:
    engine = searcher(BARE_NONCE)
    assert [t.text() for t in engine._candidates("Agent", "peer", frozenset())] == ["peer@M"]
    assert [t.text() for t in engine._candidates("Ticket", "peer", frozenset())] == ["peer@M"]


# -- the soundness guards ------------------------------------------------
def test_an_attacker_constant_never_unifies_with_a_run_fresh_atom() -> None:
    """A run's fresh values are rendered ``name#run``; ``nM`` can never be one."""
    from protoverify.core.unify import solve

    for value in ATTACKER_CONSTANTS.values():
        assert "#" not in value
        assert Atom(value) != Atom(f"ni#{value}")
        # ... and unifying a variable with it never yields a fresh atom.
        assert solve(Atom(value), Atom("ni#1")) is None


def test_the_attacker_cannot_produce_a_honest_nonce_before_it_is_sent() -> None:
    """Before any run sends ``ni``, the attacker cannot build ``ni#1``."""
    protocol = parse_file(str(example_path("ns")))
    adversary = Attacker(
        agents=["I", "R", "M"], compromised=["M"], constants=[Atom(c) for c in protocol.constants]
    )
    knowledge = adversary.initial()
    assert not adversary.can_synthesize(Atom("ni#1"), knowledge)
    assert not adversary.can_synthesize(Atom("nr#1"), knowledge)


def test_no_fresh_atom_of_a_run_ever_enters_the_attacker_knowledge_directly() -> None:
    """Knowledge grows only by ``analyze`` of what actually crossed the wire."""
    adversary = Attacker(agents=["I", "R", "M"], compromised=["M"])
    knowledge = adversary.initial()
    for _ in range(4):
        knowledge = set(adversary.analyze(knowledge)[0])
        assert not any(t.text().startswith("ni#") for t in knowledge)


# -- verdicts -------------------------------------------------------------
@pytest.mark.slow
@pytest.mark.parametrize("name", EXAMPLES)
def test_adding_attacker_constants_changed_no_verdict(name: str) -> None:
    """The feature is sound but inert on the bundled examples.

    Every receive an honest run must satisfy is either sealed under a key the
    attacker does not hold, or already satisfiable with an atom it knew.  An
    attacker-generated nonce therefore opens no new trace here.  This test pins
    the current verdicts so a future regression is visible.
    """
    protocol = parse_file(str(example_path(name)))
    verdicts = {r.claim: r.status for r in Verifier(protocol, BOUNDS.get(name, Bounds())).verify()}
    assert verdicts == EXPECTED[name]


EXPECTED = {
    "ns": {"I1": "VERIFIED", "I2": "VERIFIED", "I3": "VERIFIED", "I4": "VERIFIED",
           "R1": "FALSIFIED", "R2": "FALSIFIED", "R3": "FALSIFIED", "R4": "FALSIFIED"},
    "nsl": dict.fromkeys(("I1", "I2", "I3", "I4", "R1", "R2", "R3", "R4"), "VERIFIED"),
    "challenge_response": dict.fromkeys(("A1", "A2", "A3", "A4", "B1", "B2"), "VERIFIED"),
    "challenge_response_no_id": {
        "A1": "FALSIFIED", "A2": "VERIFIED", "A3": "VERIFIED", "A4": "VERIFIED",
        "B1": "VERIFIED", "B2": "VERIFIED",
    },
    "replay": dict.fromkeys(("A1", "A2", "B1", "B2"), "FALSIFIED"),
    "yahalom": dict.fromkeys(("A1", "A2", "A3", "B1", "B2"), "VERIFIED"),
}
