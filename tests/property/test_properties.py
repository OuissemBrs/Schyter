"""Property-based tests (hypothesis) for the term algebra and the attacker."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from conftest import SRC  # noqa: F401  (path bootstrap)
from protoverify.core.attacker import Attacker
from protoverify.core.terms import (
    AsymEnc,
    Atom,
    Hash,
    Pk,
    SharedKey,
    Sign,
    Sk,
    SymEnc,
    Term,
    Tuple,
    Var,
    leaves,
)
from protoverify.core.types import compatible
from protoverify.core.unify import solve

AGENTS = ["A", "B", "C", "M"]
atoms = st.sampled_from([Atom(name) for name in AGENTS] + [Atom(f"n{i}") for i in range(4)])
vars_ = st.builds(Var, st.sampled_from(["x", "y", "z"]), st.sampled_from(["Nonce", "Agent", "Any"]))


TYPES = st.sampled_from(["Nonce", "Agent", "Any"])
NAMES = st.sampled_from(["x", "y", "z"])


@st.composite
def terms(draw: st.DrawFn) -> Term:
    """Small symbolic terms in which every variable name has one single type.

    Real programs declare each variable exactly once, so generating the same
    variable twice with two different types would model a program that cannot be
    written.  One type is therefore drawn per term and used for all its variables.
    """
    type_name = draw(TYPES)
    variable = st.builds(Var, NAMES, st.just(type_name))
    base = st.one_of(atoms, variable)
    return draw(
        st.recursive(
            base,
            lambda children: st.one_of(
                st.builds(Tuple, st.lists(children, min_size=2, max_size=3).map(tuple)),
                st.builds(Pk, children),
                st.builds(Sk, children),
                st.builds(SymEnc, children, atoms),
                st.builds(AsymEnc, children, st.builds(Pk, atoms)),
                st.builds(Sign, children, st.builds(Sk, atoms)),
                st.builds(Hash, children),
                st.builds(SharedKey, atoms, atoms),
            ),
            max_leaves=6,
        )
    )


def attacker(compromised: tuple[str, ...] = ("M",)) -> Attacker:
    return Attacker(agents=AGENTS, compromised=compromised)


@given(term=terms())
def test_size_matches_the_tree_depth(term: Term) -> None:
    assert term.size() == 1 + sum(c.size() for c in term.children())


@given(term=terms(), data=st.data())
def test_substitute_is_idempotent(term: Term, data: st.DataObject) -> None:
    sigma = {v: data.draw(atoms) for v in term.vars()}
    once = term.substitute(sigma)
    assert once.substitute(sigma) == once


@given(term=terms())
def test_subterms_start_with_the_term_itself(term: Term) -> None:
    subs = term.subterms()
    assert subs[0] == term
    assert len(subs) <= term.size()


@given(term=terms())
def test_leaves_are_atomic(term: Term) -> None:
    assert all(isinstance(x, (Atom, Var, Pk, Sk, SharedKey)) for x in leaves(term))


@given(term=terms())
def test_analyze_is_idempotent(term: Term) -> None:
    model = attacker()
    once, _ = model.analyze([term])
    twice, new = model.analyze(once)
    assert once == twice
    assert new == ()


@given(term=terms())
def test_analyze_is_monotone(term: Term) -> None:
    model = attacker()
    small, _ = model.analyze([Atom("A")])
    big, _ = model.analyze([Atom("A"), term])
    assert small <= big


@given(term=terms())
def test_analyze_keeps_the_input(term: Term) -> None:
    closure, _ = attacker().analyze([term])
    assert term in closure


@given(term=terms(), other=st.one_of(atoms, st.builds(Pk, atoms)))
def test_synthesizable_implies_derivable(term: Term, other: Term) -> None:
    model = attacker()
    closure, _ = model.analyze([other])
    if model.can_synthesize(term, closure):
        assert set(leaves(term)) <= closure


@given(left=terms(), right=terms())
def test_unifying_both_sides_yields_equal_terms(left: Term, right: Term) -> None:
    sigma = solve(left, right)
    if sigma is not None:
        assert left.substitute(sigma) == right.substitute(sigma)


@given(left=terms(), right=terms())
def test_unification_is_symmetric(left: Term, right: Term) -> None:
    forward = solve(left, right)
    backward = solve(right, left)
    assert (forward is None) == (backward is None)
    if forward is not None and backward is not None:
        assert left.substitute(forward) == right.substitute(forward)
        assert right.substitute(backward) == left.substitute(backward)


@given(term=terms())
def test_occurs_check_never_admits_a_cycle(term: Term) -> None:
    sigma = solve(Var("x", "Any"), term)
    if sigma is not None:
        bound = sigma.get("x")
        assert bound is None or "x" not in bound.vars()


@given(name=st.sampled_from(["x", "y"]), term=terms())
def test_typed_variables_only_take_compatible_values(name: str, term: Term) -> None:
    """A bound variable never takes a value of an incompatible type."""
    if isinstance(term, Var) and term.name == name:
        return  # same name: the two variables already denote the same value
    sigma = solve(Var(name, "Agent"), term)
    if sigma is not None:
        assert compatible("Agent", term)


@given(term=terms())
def test_substitution_of_the_empty_sigma_is_a_no_op(term: Term) -> None:
    assert term.substitute({}) is term


@settings(max_examples=30, deadline=None)
@given(compromised=st.frozensets(st.sampled_from(AGENTS), max_size=2))
def test_analysis_terminates_under_every_compromise_model(compromised: frozenset[str]) -> None:
    model = attacker(tuple(sorted(compromised)))
    message = AsymEnc(SymEnc(Atom("x"), Sk(Atom("M"))), Pk(Atom("B")))
    closure, _ = model.analyze([message])
    assert isinstance(closure, frozenset)
