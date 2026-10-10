"""Replay-checker tests: every trace the search returns must replay consistently."""

from __future__ import annotations

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.attacker import Attacker
from protoverify.core.replay import Delivery, ReplayError, replay
from protoverify.core.run import Run
from protoverify.core.search import Bounds, Verifier
from protoverify.core.terms import AsymEnc, Atom, Pk, Tuple
from protoverify.parser import parse_file

EXAMPLES = ["ns", "nsl", "replay", "challenge_response", "challenge_response_no_id"]


def ns() -> object:
    return parse_file(str(example_path("ns")))


def runs() -> tuple[dict[int, Run], dict[str, object]]:
    """A coherent Alice/Bob session: every message matches its partner."""
    protocol = ns()
    initiator = Run.create(1, protocol.role("I"), "A", "B", protocol.params)  # type: ignore[attr-defined]
    responder = Run.create(2, protocol.role("R"), "B", "A", protocol.params)  # type: ignore[attr-defined]
    return {1: initiator, 2: responder}, {
        "r1::ni": Atom("na"), "r1::nr": Atom("nb"),
        "r2::ni": Atom("na"), "r2::nr": Atom("nb"),
    }


def order() -> tuple[tuple[int, int], ...]:
    """A complete six-message execution of the coherent session."""
    return ((1, 2), (2, 2), (2, 3), (1, 3), (1, 4), (2, 4))


def deliveries() -> dict[tuple[int, int], Delivery]:
    return {
        (2, 2): Delivery("send", (1, 2)),
        (1, 3): Delivery("send", (2, 3)),
        (2, 4): Delivery("send", (1, 4)),
    }


def attacker() -> Attacker:
    return Attacker(agents=["A", "B", "M"], compromised=["M"])


def test_a_simple_two_run_trace_replays() -> None:
    table, sigma = runs()
    result = replay(table, sigma, order(), deliveries(), attacker(), "M")
    assert [s.type for s in result.steps] == ["send", "recv"] * 3
    assert [s.i for s in result.steps] == [1, 2, 3, 4, 5, 6]
    assert result.step_of == {k: i + 1 for i, k in enumerate(order())}


def test_attacker_step_must_be_synthesizable() -> None:
    table, sigma = runs()
    sigma["r2::ni"] = Atom("a-nonce-nobody-sent")
    with pytest.raises(ReplayError, match="cannot build"):
        replay(table, sigma, ((1, 2), (2, 2)), {(2, 2): Delivery("attacker")}, attacker(), "M")


def test_attacker_step_relay_is_recognised() -> None:
    table, sigma = runs()
    result = replay(table, sigma, ((1, 2), (2, 2)), {(2, 2): Delivery("attacker")}, attacker(), "M")
    assert result.steps[1].type == "attacker_forward"
    assert result.steps[1].frm == "M"
    assert "relays" in result.steps[1].note


def test_attacker_step_that_builds_a_new_message_is_an_injection() -> None:
    table, sigma = runs()
    result = replay(table, sigma, ((1, 2), (2, 2)), {(2, 2): Delivery("attacker")}, attacker(), "M")
    assert result.steps[1].type == "attacker_forward"
    sigma2 = dict(sigma)
    sigma2["r2::ni"] = Atom("A")
    result2 = replay(table, sigma2, ((1, 2), (2, 2)), {(2, 2): Delivery("attacker")},
                     attacker(), "M")
    assert result2.steps[1].type == "attacker_inject"
    assert "forges" in result2.steps[1].note


def test_unknown_run_is_rejected() -> None:
    table, sigma = runs()
    with pytest.raises(ReplayError, match="unknown run"):
        replay(table, sigma, ((9, 0),), {}, attacker(), "M")


def test_out_of_range_event_is_rejected() -> None:
    table, sigma = runs()
    with pytest.raises(ReplayError, match="has no event"):
        replay(table, sigma, ((1, 99),), {}, attacker(), "M")


def test_unresolved_receive_is_rejected() -> None:
    table, sigma = runs()
    with pytest.raises(ReplayError, match="never resolved"):
        replay(table, sigma, ((2, 2),), {}, attacker(), "M")


def test_delivery_from_a_later_event_is_rejected() -> None:
    table, sigma = runs()
    order = ((2, 2), (1, 2))
    deliveries = {(2, 2): Delivery("send", (1, 2))}
    with pytest.raises(ReplayError, match="comes from a later event"):
        replay(table, sigma, order, deliveries, attacker(), "M")


def test_foreign_fresh_value_is_rejected() -> None:
    table, sigma = runs()
    sigma["r2::ni"] = Atom("n#7")
    order = ((1, 2), (2, 2))
    deliveries = {(2, 2): Delivery("attacker")}
    with pytest.raises(ReplayError, match="unknown fresh value"):
        replay(table, sigma, order, deliveries, attacker(), "M")


def test_knowledge_grows_with_every_message() -> None:
    table, sigma = runs()
    result = replay(table, sigma, order(), deliveries(), attacker(), "M")
    sizes = [len(k) for k in result.knowledge]
    assert sizes == sorted(sizes)
    assert result.knows(attacker(), Atom("A"))
    assert not result.knows(attacker(), Atom("na"))


def test_every_trace_the_search_returns_replays() -> None:
    for name in EXAMPLES:
        protocol = parse_file(str(example_path(name)))
        for result in Verifier(protocol, Bounds()).verify():
            if result.trace is None:
                continue
            assert result.trace.steps
            assert result.trace.steps[0].i == 1


def test_replay_rejects_a_message_that_does_not_match_the_substitution() -> None:
    table, sigma = runs()
    sigma.pop("r2::ni")
    order = ((1, 2), (2, 2))
    deliveries = {(2, 2): Delivery("send", (1, 2))}
    with pytest.raises(ReplayError, match="still contains variables"):
        replay(table, sigma, order, deliveries, attacker(), "M")


def test_ground_message_is_built_from_the_substitution() -> None:
    table, sigma = runs()
    send = table[1].event(2)
    term = table[1].instantiate(send.msg).substitute(sigma)  # type: ignore[attr-defined]
    assert term == AsymEnc(Tuple((Atom("A"), Atom("na"))), Pk(Atom("B")))


def test_declarations_and_claims_produce_no_steps() -> None:
    table, sigma = runs()
    order = ((1, 0), (1, 1), (1, 2), (1, 5))
    deliveries = {}
    result = replay(table, sigma, order, deliveries, attacker(), "M")
    assert [s.i for s in result.steps] == [1]
