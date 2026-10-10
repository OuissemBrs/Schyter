"""Unification and typing tests."""

from __future__ import annotations

from conftest import SRC  # noqa: F401  (path bootstrap)
from protoverify.core.terms import AsymEnc, Atom, Hash, Pk, SharedKey, Sign, Sk, SymEnc, Tuple, Var
from protoverify.core.types import TypeEnv, compatible, tags_of
from protoverify.core.unify import solve, unify


def test_identical_terms_unify_with_the_empty_substitution() -> None:
    t = AsymEnc(Atom("a"), Pk(Atom("B")))
    assert solve(t, t) == {}


def test_fresh_variable_binds_to_a_ground_term() -> None:
    assert solve(Var("x", "Nonce"), Atom("n")) == {"x": Atom("n")}


def test_binding_is_symmetric() -> None:
    assert solve(Atom("n"), Var("x", "Nonce")) == {"x": Atom("n")}


def test_chained_bindings_are_resolved() -> None:
    sigma = solve(Var("x", "Nonce"), Var("y", "Nonce"))
    assert sigma == {"x": Var("y", "Nonce")}
    sigma2 = unify(Tuple((Var("y", "Nonce"),)), Tuple((Atom("n"),)), sigma)
    assert sigma2 is not None
    assert Var("x", "Nonce").substitute(sigma2) == Atom("n")


def test_occurs_check_rejects_self_embedding() -> None:
    assert solve(Var("x", "Any"), AsymEnc(Var("x", "Any"), Pk(Atom("A")))) is None


def test_occurs_check_rejects_indirect_cycles() -> None:
    assert solve(Var("x", "Any"), Tuple((Var("y", "Any"), Atom("a")))) == {"x": Tuple((Var("y", "Any"), Atom("a")))}
    second = solve(Tuple((Var("x", "Any"), Atom("a"))), Var("y", "Any"))
    assert second == {"y": Tuple((Var("x", "Any"), Atom("a")))}
    assert solve(Var("x", "Any"), Var("y", "Any")) == {"x": Var("y", "Any")}


def test_structural_mismatch_returns_none() -> None:
    assert solve(AsymEnc(Atom("a"), Pk(Atom("B"))), SymEnc(Atom("a"), Atom("B"))) is None


def test_different_hash_names_do_not_unify() -> None:
    assert solve(Hash(Atom("a"), "h"), Hash(Atom("a"), "g")) is None


def test_tuple_arity_must_match() -> None:
    assert solve(Tuple((Atom("a"), Atom("b"))), Tuple((Atom("a"),))) is None


def test_agent_variable_rejects_an_encrypted_term() -> None:
    assert solve(Var("a", "Agent"), AsymEnc(Atom("m"), Pk(Atom("B")))) is None


def test_agent_variable_accepts_an_agent_atom() -> None:
    assert solve(Var("a", "Agent"), Atom("Bob")) == {"a": Atom("Bob")}


def test_agent_and_nonce_variables_do_not_unify() -> None:
    assert solve(Var("a", "Agent"), Var("n", "Nonce")) is None


def test_ticket_matches_anything() -> None:
    assert solve(Var("t", "Ticket"), AsymEnc(Atom("m"), Pk(Atom("B")))) is not None
    assert solve(Var("t", "Ticket"), Var("n", "Nonce")) is not None


def test_unify_extends_an_existing_substitution() -> None:
    out = unify(Var("x", "Nonce"), Atom("n"), {"y": Atom("m")})
    assert out == {"y": Atom("m"), "x": Atom("n")}


def test_unify_respects_previous_bindings() -> None:
    assert unify(Var("x", "Nonce"), Atom("other"), {"x": Atom("other")}) == {"x": Atom("other")}
    assert unify(Var("x", "Nonce"), Atom("n"), {"x": Atom("other")}) is None


def test_key_terms_unify_positionally() -> None:
    assert solve(Pk(Var("a", "Agent")), Pk(Atom("A"))) == {"a": Atom("A")}
    assert solve(Sk(Var("a", "Agent")), Sk(Atom("A"))) == {"a": Atom("A")}
    assert solve(SharedKey(Var("a", "Agent"), Atom("B")), SharedKey(Atom("A"), Atom("B"))) == {
        "a": Atom("A")
    }


def test_signature_structure() -> None:
    assert solve(Sign(Var("m", "Nonce"), Sk(Atom("A"))), Sign(Atom("n"), Sk(Atom("A")))) == {
        "m": Atom("n")
    }


def test_unifying_a_variable_with_a_key_works() -> None:
    assert solve(Var("k", "Key"), Pk(Atom("A"))) == {"k": Pk(Atom("A"))}


def test_type_env_knows_builtins_and_user_types() -> None:
    env = TypeEnv.builtin()
    assert env.knows("Nonce") and env.knows("Ticket")
    assert not env.knows("Mine")
    assert env.with_user_types(frozenset({"Mine"})).knows("Mine")


def test_tags_of_terms() -> None:
    assert tags_of(Atom("a")) == frozenset({"agent", "nonce", "key", "data"})
    assert tags_of(Pk(Atom("a"))) == frozenset({"agent", "key", "data"})
    assert tags_of(Tuple((Atom("a"),))) == frozenset({"nonce", "data"})


def test_compatible_helper() -> None:
    assert compatible("Agent", Atom("a"))
    assert not compatible("Agent", Tuple((Atom("a"),)))
    assert compatible("Ticket", Hash(Atom("a")))
