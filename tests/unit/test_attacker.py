"""Attacker tests: decomposition, synthesis, compromise and monotonicity."""

from __future__ import annotations

import pytest

from conftest import SRC  # noqa: F401  (path bootstrap)
from protoverify.core.attacker import Attacker, Knowledge
from protoverify.core.terms import (
    AsymEnc,
    Atom,
    Hash,
    Pk,
    SharedKey,
    Sign,
    Sk,
    SymEnc,
    Tuple,
    leaves,
)

A, B, M = Atom("A"), Atom("B"), Atom("M")


def make(compromised: tuple[str, ...] = ("M",)) -> Attacker:
    return Attacker(agents=["A", "B", "M"], compromised=compromised)


def closure(attacker: Attacker, *terms: object) -> Knowledge:
    """Return ``analyze(K0 + terms)`` -- what the attacker can actually see."""
    return attacker.analyze(set(attacker.initial()) | set(terms))[0]


def test_initial_knowledge_contains_names_and_public_keys() -> None:
    k0 = make().initial()
    assert {Atom("A"), Atom("B"), Atom("M")} <= k0
    assert {Pk(A), Pk(B), Pk(M)} <= k0


def test_compromised_agent_publishes_its_secret_key() -> None:
    assert Sk(M) in make().initial()
    assert Sk(A) not in make().initial()


def test_compromised_agent_derives_shared_keys() -> None:
    k0 = make().initial()
    assert SharedKey(A, M) in k0
    assert SharedKey(A, B) not in k0


def test_analyze_projects_tuple_components() -> None:
    attacker = make()
    _, new = attacker.analyze([Tuple((A, Atom("na")))])
    assert set(new) == {A, Atom("na")}


def test_analyze_is_idempotent() -> None:
    attacker = make()
    first = closure(attacker, Tuple((A, Atom("na"))))
    second, new = attacker.analyze(first)
    assert first == second
    assert new == ()


def test_analyze_is_monotone() -> None:
    attacker = make()
    base = closure(attacker, AsymEnc(Atom("na"), Pk(M)))
    extended = closure(attacker, AsymEnc(Atom("na"), Pk(M)), AsymEnc(Atom("nb"), Pk(M)))
    assert base <= extended


def test_nested_encryption_is_unwrapped_layer_by_layer() -> None:
    attacker = make()
    inner = SymEnc(Atom("na"), Sk(M))
    outer = AsymEnc(inner, Pk(M))
    k = closure(attacker, outer)
    assert Atom("na") in k
    assert inner in k


def test_key_hidden_inside_the_ciphertext_is_not_available() -> None:
    attacker = make()
    msg = AsymEnc(Atom("k"), SymEnc(Sk(B), Sk(M)))
    assert Sk(B) not in closure(attacker, msg)


def test_asymmetric_decryption_needs_the_private_key() -> None:
    attacker = make()
    msg = AsymEnc(Atom("na"), Pk(B))
    assert Atom("na") not in closure(attacker, msg)
    assert Atom("na") in closure(attacker, msg, Sk(B))


def test_symmetric_decryption_needs_the_key() -> None:
    attacker = make()
    assert Atom("na") in closure(attacker, SymEnc(Atom("na"), Sk(M)))
    assert Atom("nb") not in closure(attacker, SymEnc(Atom("nb"), Sk(B)))


def test_signatures_are_not_confidential() -> None:
    assert Atom("na") in closure(make(), Sign(Atom("na"), Sk(A)))


def test_hash_is_inverted() -> None:
    k = closure(make(), Hash(AsymEnc(Atom("na"), Pk(M)), "h"))
    assert Atom("na") in k


def test_public_key_reveals_the_owner() -> None:
    assert A in closure(make(), Pk(A))


def test_derivations_are_recorded_for_the_animation() -> None:
    attacker = make()
    attacker.analyze([AsymEnc(Atom("nb"), Pk(M)), Sk(M)], step=4, log=True)
    assert len(attacker.log.steps) == 1
    record = attacker.log.steps[0]
    assert record.step == 4
    assert Atom("nb") in record.newly_known
    assert any(d.rule == "decrypt" for d in record.derivations)
    assert any("decrypt" in d.describe() for d in record.derivations)


def test_logging_ignores_steps_that_learn_nothing() -> None:
    attacker = make()
    attacker.analyze(list(attacker.initial()), step=1, log=True)
    assert attacker.log.steps == []


def test_synthesis_of_a_known_term() -> None:
    attacker = make()
    assert attacker.can_synthesize(A, attacker.initial())


def test_synthesis_of_an_unknown_nonce_fails() -> None:
    assert not make().can_synthesize(Atom("na"), make().initial())


def test_synthesis_of_a_forged_encryption() -> None:
    attacker = make()
    k = closure(attacker, AsymEnc(Atom("na"), Pk(M)))
    assert attacker.can_synthesize(AsymEnc(Atom("na"), Pk(M)), k)
    assert attacker.can_synthesize(AsymEnc(Atom("na"), Pk(B)), k)
    assert not attacker.can_synthesize(AsymEnc(Atom("nb"), Pk(M)), k)


def test_synthesis_of_a_tuple_and_a_hash() -> None:
    attacker = make()
    k = closure(attacker, AsymEnc(Atom("na"), Pk(M)), AsymEnc(Atom("nb"), Pk(M)))
    assert attacker.can_synthesize(Tuple((Atom("na"), Atom("nb"))), k)
    assert attacker.can_synthesize(Hash(Atom("na"), "h"), k)


def test_synthesis_requires_the_private_key_to_sign() -> None:
    attacker = make()
    k = closure(attacker, Sign(Atom("m"), Sk(A)))
    assert attacker.can_synthesize(Sign(Atom("m"), Sk(A)), k)
    assert not attacker.can_synthesize(Sign(Atom("m"), Sk(B)), k)


def test_synthesis_requires_a_shared_key() -> None:
    attacker = make()
    assert not attacker.can_synthesize(SymEnc(Atom("m"), SharedKey(A, B)), attacker.initial())


def test_synthesizable_implies_derivable() -> None:
    """Every synthesizable term has all its components in the closure."""
    attacker = make()
    seen = closure(attacker, AsymEnc(Atom("na"), Pk(M)), Hash(Atom("na"), "h"))
    for term in (Atom("na"), Tuple((A, Atom("na"))), Hash(Atom("na"), "h")):
        assert attacker.can_synthesize(term, seen)
        assert set(leaves(term)) <= seen


def test_no_key_material_can_be_forged() -> None:
    attacker = make()
    k = closure(attacker, AsymEnc(Atom("na"), Pk(M)))
    assert not attacker.can_synthesize(Sk(B), k)
    assert not attacker.can_synthesize(Sk(A), k)


def test_honesty_predicate() -> None:
    attacker = make()
    assert attacker.is_honest("A")
    assert not attacker.is_honest("M")


def test_constants_are_public() -> None:
    attacker = Attacker(agents=["A"], constants=[Atom("k")])
    assert Atom("k") in attacker.initial()


@pytest.mark.parametrize("compromised", [("M",), ("M", "B")])
def test_analysis_terminates_for_every_compromise_model(compromised: tuple[str, ...]) -> None:
    attacker = make(compromised)
    k = closure(attacker, AsymEnc(SymEnc(Atom("x"), Sk(M)), Pk(M)))
    assert Atom("x") in k
