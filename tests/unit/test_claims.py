"""Claim-semantics and run-instantiation tests."""

from __future__ import annotations

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.claims import (
    IMPLICATION_ORDER,
    concrete_messages,
    corresponds,
    data_view,
    evaluate,
    no_partner_sentence,
)
from protoverify.core.run import Run
from protoverify.core.terms import AsymEnc, Atom, Pk, Tuple, Var
from protoverify.parser import parse_file


def ns_protocol() -> object:
    return parse_file(str(example_path("ns")))


def make_runs() -> dict[int, Run]:
    protocol = ns_protocol()
    initiator = Run.create(1, protocol.role("I"), "A", "B", protocol.params)  # type: ignore[attr-defined]
    responder = Run.create(2, protocol.role("R"), "B", "A", protocol.params)  # type: ignore[attr-defined]
    return {1: initiator, 2: responder}


def claim(label: str) -> object:
    protocol = ns_protocol()
    return next(c for _, c in protocol.all_claims() if c.label == label)  # type: ignore[attr-defined]


def empty_sigma() -> dict[str, Var]:
    return {}


def test_run_scopes_variables_and_agents() -> None:
    run = make_runs()[1]
    term = run.instantiate(run.events[2].msg)  # type: ignore[attr-defined]
    assert term == AsymEnc(Tuple((Atom("A"), Var("r1::ni", "Nonce"))), Pk(Atom("B")))
    assert term.substitute(run.base_substitution()) == AsymEnc(
        Tuple((Atom("A"), Atom("ni#1"))), Pk(Atom("B"))
    )


def test_run_substitution_binds_fresh_values() -> None:
    run = make_runs()[1]
    assert run.base_substitution() == {"r1::ni": Atom("ni#1")}


def test_fresh_atoms_are_unique_per_run() -> None:
    runs = make_runs()
    assert runs[1].fresh_atom("ni") == Atom("ni#1")
    assert runs[2].fresh_atom("nr") == Atom("nr#2")


def test_two_runs_of_the_same_role_do_not_share_variables() -> None:
    protocol = ns_protocol()
    first = Run.create(1, protocol.role("I"), "A", "B", protocol.params)  # type: ignore[attr-defined]
    second = Run.create(2, protocol.role("I"), "A", "C", protocol.params)  # type: ignore[attr-defined]
    assert first.scope("ni") != second.scope("ni")
    assert first.fresh_atom("ni") != second.fresh_atom("ni")


def test_agent_environment_resolves_the_roles_own_parameter() -> None:
    run = make_runs()[1]
    assert run.agent_env() == {"I": "A", "R": "B"}


def test_concrete_messages_cover_every_message_event() -> None:
    run = make_runs()[1]
    assert [m.label for m in concrete_messages(run, {})] == ["1", "2", "3"]


def test_data_view_blinds_the_keys() -> None:
    left = AsymEnc(Tuple((Atom("A"), Atom("n"))), Pk(Atom("B")))
    right = AsymEnc(Tuple((Atom("A"), Atom("n"))), Pk(Atom("M")))
    assert data_view(left) == data_view(right)


def test_data_view_keeps_the_payload() -> None:
    assert data_view(AsymEnc(Atom("a"), Pk(Atom("B")))) != data_view(
        AsymEnc(Atom("b"), Pk(Atom("B")))
    )


def test_correspondence_requires_identical_messages_when_injective() -> None:
    """Niagree ignores the key material, Nisynch does not."""
    protocol = ns_protocol()
    initiator = Run.create(1, protocol.role("I"), "A", "M", protocol.params)  # type: ignore[attr-defined]
    responder = Run.create(2, protocol.role("R"), "B", "A", protocol.params)  # type: ignore[attr-defined]
    sigma = {"r1::ni": Atom("n"), "r1::nr": Atom("m"), "r2::ni": Atom("n"), "r2::nr": Atom("m")}
    # Message 1 is {A,n}pk(M) for the initiator and {A,n}pk(B) for the responder:
    # the data agrees, the concrete ciphertexts do not.
    assert not corresponds(initiator, responder, sigma, injective=True)
    assert data_view(concrete_messages(initiator, sigma)[0].term) == data_view(
        concrete_messages(responder, sigma)[0].term
    )


def test_full_correspondence_holds_for_a_matching_pair() -> None:
    runs = make_runs()
    sigma = {"r1::ni": Atom("n"), "r1::nr": Atom("m"), "r2::ni": Atom("n"), "r2::nr": Atom("m")}
    assert corresponds(runs[1], runs[2], sigma, injective=True)


def test_correspondence_fails_when_a_payload_differs() -> None:
    runs = make_runs()
    sigma = {"r1::ni": Atom("n"), "r1::nr": Atom("m"), "r2::ni": Atom("n"), "r2::nr": Atom("other")}
    assert not corresponds(runs[1], runs[2], sigma, injective=False)


def test_secret_claim_uses_the_attacker_predicate() -> None:
    runs = make_runs()
    verdict = evaluate(claim("I1"), runs[1], runs, {"r1::ni": Atom("n")}, None,  # type: ignore[arg-type]
                       lambda term: term == Atom("n"))
    assert not verdict.satisfied
    assert "learns n" in verdict.violation


def test_secret_claim_holds_when_the_attacker_knows_nothing() -> None:
    runs = make_runs()
    verdict = evaluate(claim("I1"), runs[1], runs, {"r1::ni": Atom("n")}, None,  # type: ignore[arg-type]
                       lambda term: False)
    assert verdict.satisfied


def test_alive_fails_without_a_partner_run() -> None:
    protocol = parse_file(str(example_path("challenge_response")))
    bob = Run.create(1, protocol.role("B"), "B", "A", protocol.params)
    alive = next(c for _, c in protocol.all_claims() if c.label == "B1")
    verdict = evaluate(alive, bob, {1: bob}, {}, "A", lambda term: False)
    assert not verdict.satisfied
    assert "never ran" in verdict.violation


def test_alive_holds_when_the_partner_ran() -> None:
    protocol = parse_file(str(example_path("challenge_response")))
    bob = Run.create(1, protocol.role("B"), "B", "A", protocol.params)
    alice = Run.create(2, protocol.role("A"), "A", "B", protocol.params)
    alive = next(c for _, c in protocol.all_claims() if c.label == "B1")
    assert evaluate(alive, bob, {1: bob, 2: alice}, {}, "A", lambda term: False).satisfied


def test_niagree_fails_when_the_partner_has_another_peer() -> None:
    runs = make_runs()
    runs[2].peer = "M"
    runs[2].agent = "M"
    verdict = evaluate(claim("R3"), runs[2], runs, {"r1::ni": Atom("n"), "r1::nr": Atom("m"),
                                                   "r2::ni": Atom("n"), "r2::nr": Atom("m")},
                       "I", lambda term: False)  # type: ignore[arg-type]
    assert not verdict.satisfied
    assert "does not hold" in verdict.violation


def test_niagree_holds_for_a_matching_pair() -> None:
    runs = make_runs()
    sigma = {"r1::ni": Atom("n"), "r1::nr": Atom("m"), "r2::ni": Atom("n"), "r2::nr": Atom("m")}
    verdict = evaluate(claim("R3"), runs[2], runs, sigma, "I", lambda term: False)  # type: ignore[arg-type]
    assert verdict.satisfied


def test_nisynch_is_stricter_than_niagree() -> None:
    runs = make_runs()
    sigma = {"r1::ni": Atom("n"), "r1::nr": Atom("m"), "r2::ni": Atom("n"), "r2::nr": Atom("m")}
    niagree = evaluate(claim("R3"), runs[2], runs, sigma, "I", lambda term: False)  # type: ignore[arg-type]
    nisynch = evaluate(claim("R4"), runs[2], runs, sigma, "I", lambda term: False)  # type: ignore[arg-type]
    assert niagree.satisfied and nisynch.satisfied
    sigma["r2::nr"] = Atom("m2")
    nisynch = evaluate(claim("R4"), runs[2], runs, sigma, "I", lambda term: False)  # type: ignore[arg-type]
    assert not nisynch.satisfied


def test_no_partner_sentence_mentions_both_agents() -> None:
    text = no_partner_sentence(make_runs()[2], "I")
    assert "B" in text and "A" in text


def test_implication_order_is_weakest_to_strongest() -> None:
    assert IMPLICATION_ORDER == ("Alive", "Weakagree", "Niagree", "Nisynch")
