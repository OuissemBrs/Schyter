"""Unification with an occurs check and a type discipline.

Two ingredients keep the unifier sound and useful:

*substitution is transitive* -- applying a substitution re-substitutes inside
whatever a variable is bound to, so ``x := pk(y)`` followed by ``y := a``
really does make ``x`` equal to ``pk(a)``;

*type requirements are collected and checked at the end*.  Every binding records
"this variable must satisfy this type"; once a solution is found, every recorded
requirement is checked against the fully substituted value.  Chained bindings
(``x := y``, ``y := pk(a)``) are therefore type-checked against the value each
alias finally receives, which a purely local check would miss.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from .terms import AsymEnc, Atom, Hash, Pk, SharedKey, Sign, Sk, SymEnc, Term, Tuple, Var
from .types import compatible

__all__ = ["Sigma", "apply_sigma", "atoms", "solve", "unify"]

#: A substitution maps qualified variable names to terms.
Sigma = dict[str, Term]

#: variable name -> the types that name must satisfy.
Requirements = dict[str, set[str]]


def solve(a: Term, b: Term) -> Sigma | None:
    """Return the most general unifier of ``a`` and ``b``, or ``None``."""
    return unify(a, b, {})


def unify(a: Term, b: Term, sigma: Mapping[str, Term] | None = None) -> Sigma | None:
    """Extend ``sigma`` so that ``a`` and ``b`` become equal.

    Returns the extended substitution (a copy), or ``None`` when the two terms
    cannot be made equal.  The occurs check is applied at every binding, so a
    successful result is always a finite, well-formed substitution.
    """
    work: Sigma = dict(sigma) if sigma else {}
    required: Requirements = {}
    if not _match(a, b, work, required):
        return None
    return work if _types_hold(required, work) else None


def apply_sigma(t: Term, sigma: Mapping[str, Term]) -> Term:
    """Substitute ``sigma`` into ``t`` (see :meth:`Term.substitute`)."""
    return t.substitute(sigma)


def _match(a: Term, b: Term, s: Sigma, required: Requirements) -> bool:
    """Destructively extend ``s`` until ``a`` and ``b`` unify."""
    a = a.substitute(s)
    b = b.substitute(s)
    if a == b:
        return True
    if isinstance(a, Var):
        return _bind(a, b, s, required)
    if isinstance(b, Var):
        return _bind(b, a, s, required)
    if type(a) is not type(b):
        return False
    return _match_same(a, b, s, required)


def _match_same(a: Term, b: Term, s: Sigma, required: Requirements) -> bool:
    """Match two terms of the very same constructor."""
    if isinstance(a, Hash):
        hashed = cast(Hash, b)
        return a.name == hashed.name and _match(a.term, hashed.term, s, required)
    if isinstance(a, Tuple):
        tup = cast(Tuple, b)
        if len(a.items) != len(tup.items):
            return False
        return all(_match(x, y, s, required) for x, y in zip(a.items, tup.items, strict=True))
    if isinstance(a, SymEnc):
        symmetric = cast(SymEnc, b)
        return _match(a.msg, symmetric.msg, s, required) and _match(
            a.key, symmetric.key, s, required
        )
    if isinstance(a, AsymEnc):
        asymmetric = cast(AsymEnc, b)
        return _match(a.msg, asymmetric.msg, s, required) and _match(
            a.key, asymmetric.key, s, required
        )
    if isinstance(a, Sign):
        signature = cast(Sign, b)
        return _match(a.msg, signature.msg, s, required) and _match(
            a.key, signature.key, s, required
        )
    if isinstance(a, SharedKey):
        key = cast(SharedKey, b)
        return _match_shared(a, key, s, required)
    if isinstance(a, (Pk, Sk)):
        single = cast(Pk | Sk, b)
        return _match(a.agent, single.agent, s, required)
    return False


def _match_shared(
    a: SharedKey, b: SharedKey, s: Sigma, required: Requirements
) -> bool:
    """Match two shared keys, which are symmetric: ``k(A,B)`` is ``k(B,A)``.

    The written order is kept on the terms, because it depends on whether an
    agent variable is bound yet, so symmetry is applied here.  Both orderings are
    tried on a *copy* of the substitution and the one that succeeds is kept, so a
    failed first attempt cannot leave bindings behind.
    """
    if _match(a.left, b.left, s, required) and _match(a.right, b.right, s, required):
        return True
    trial = dict(s)
    trial_required = {name: set(types) for name, types in required.items()}
    if _match(a.left, b.right, trial, trial_required) and _match(
        a.right, b.left, trial, trial_required
    ):
        s.clear()
        s.update(trial)
        required.clear()
        required.update(trial_required)
        return True
    return False


def _bind(var: Var, term: Term, s: Sigma, required: Requirements) -> bool:
    """Bind ``var`` to ``term`` after checking types and the occurs rule."""
    if not compatible(var.type_name, term):
        return False
    if isinstance(term, Var) and term.name == var.name:
        return True
    if var.name in term.vars():
        return False  # occurs check
    s[var.name] = term
    required.setdefault(var.name, set()).add(var.type_name)
    return True


def _types_hold(required: Requirements, s: Sigma) -> bool:
    """Check every recorded type requirement against the final substitution.

    The value a variable finally receives is followed through the whole alias
    chain, so ``x := y`` with ``x : Nonce`` and ``y : Agent`` is rejected even
    though neither binding looks wrong on its own.
    """
    return all(
        compatible(type_name, _resolve(name, s)) for name, types in required.items()
        for type_name in types
    )


def _resolve(name: str, s: Sigma) -> Term:
    """Follow ``name`` through the substitution to its final value."""
    seen: set[str] = set()
    current: Term = Var(name, "Any")
    while isinstance(current, Var) and current.name in s and current.name not in seen:
        seen.add(current.name)
        current = s[current.name]
    return current


def atoms(t: Term) -> tuple[Atom, ...]:
    """Return every :class:`Atom` occurring in ``t``."""
    return tuple(a for a in t.subterms() if isinstance(a, Atom))
