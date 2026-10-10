"""Term algebra tests."""

from __future__ import annotations

import pytest

from conftest import SRC  # noqa: F401  (path bootstrap)
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
    Var,
    ground,
    intern,
    leaves,
    short_name,
)


def test_terms_are_hashable_and_comparable_by_structure() -> None:
    assert Atom("a") == Atom("a")
    assert Atom("a") != Atom("b")
    assert len({Atom("a"), Atom("a"), Atom("b")}) == 2


def test_terms_are_immutable() -> None:
    with pytest.raises(AttributeError):
        Atom("a").name = "b"  # type: ignore[misc]


def test_size_counts_constructor_nodes() -> None:
    assert Atom("a").size() == 1
    assert Pk(Atom("a")).size() == 2
    assert AsymEnc(Tuple((Atom("a"), Atom("b"))), Pk(Atom("c"))).size() == 6


def test_vars_collects_names() -> None:
    t = Tuple((Var("x", "Nonce"), AsymEnc(Var("y", "Nonce"), Pk(Atom("A")))))
    assert t.vars() == frozenset({"x", "y"})


def test_subterms_are_in_prefix_order() -> None:
    t = AsymEnc(Var("x", "Nonce"), Pk(Atom("A")))
    assert t.subterms() == (t, Var("x", "Nonce"), Pk(Atom("A")), Atom("A"))


def test_at_follows_a_path() -> None:
    t = AsymEnc(Tuple((Var("x", "Nonce"), Var("y", "Nonce"))), Pk(Atom("A")))
    assert t.at((0, 1)) == Var("y", "Nonce")
    assert t.at((1,)) == Pk(Atom("A"))


def test_substitute_is_recursive() -> None:
    t = AsymEnc(Tuple((Var("x", "Nonce"), Var("y", "Nonce"))), Pk(Var("k", "Agent")))
    out = t.substitute({"x": Atom("1"), "k": Atom("kk")})
    assert out == AsymEnc(Tuple((Atom("1"), Var("y", "Nonce"))), Pk(Atom("kk")))


def test_substitute_is_idempotent_on_ground_terms() -> None:
    t = Pk(Atom("A"))
    assert t.substitute({"x": Atom("1")}) is t


def test_substitute_chases_bindings() -> None:
    sigma = {"x": Var("y", "Nonce"), "y": Atom("1")}
    assert Var("x", "Nonce").substitute(sigma) == Atom("1")


def test_map_atoms_rewrites_only_atoms() -> None:
    t = AsymEnc(Tuple((Atom("I"), Pk(Atom("R")))), Var("v", "Nonce"))
    out = t.map_atoms(lambda n: {"I": "Alice", "R": "Bob"}.get(n, n))
    assert out == AsymEnc(Tuple((Atom("Alice"), Pk(Atom("Bob")))), Var("v", "Nonce"))


def test_ground_detects_variables() -> None:
    assert ground(Pk(Atom("A")))
    assert not ground(Tuple((Atom("a"), Var("x", "Nonce"))))


def test_leaves_are_atomic_subterms() -> None:
    t = AsymEnc(Tuple((Atom("na"), Var("nb", "Nonce"))), Pk(Atom("B")))
    assert leaves(t) == (Atom("na"), Var("nb", "Nonce"), Pk(Atom("B")))


def test_intern_returns_the_same_object() -> None:
    first = intern(AsymEnc(Atom("a"), Pk(Atom("B"))))
    second = intern(AsymEnc(Atom("a"), Pk(Atom("B"))))
    assert first is second


def test_text_rendering_matches_the_documentation() -> None:
    assert Tuple((Atom("a"), Atom("b"), Atom("c"))).text() == "(a,b,c)"
    assert SymEnc(Atom("m"), Atom("k")).text() == "{m}k(k)"
    assert AsymEnc(Atom("m"), Pk(Atom("R"))).text() == "{m}pk(R)"
    assert Sign(Atom("m"), Sk(Atom("A"))).text() == "{m}sk(A)"
    assert Hash(Atom("m"), "h").text() == "h(m)"
    assert Pk(Atom("A")).text() == "pk(A)"
    assert Sk(Atom("A")).text() == "sk(A)"
    assert SharedKey(Atom("A"), Atom("B")).text() == "k(A,B)"


def test_nested_text_has_no_parentheses_inside_operators() -> None:
    assert AsymEnc(Tuple((Atom("I"), Atom("ni"))), Pk(Atom("R"))).text() == "{I,ni}pk(R)"


def test_var_text_strips_the_run_qualifier() -> None:
    assert Var("r3::ni", "Nonce").text() == "ni"
    assert short_name("r3::ni") == "ni"
    assert short_name("ni") == "ni"
