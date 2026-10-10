"""Immutable, hashable symbolic terms used by the ProtoVerify engine.

The term algebra is a pure free-term algebra (no equational theory except the
syntactic equality of constructors).  Terms are frozen, slotted dataclasses so
they are hashable by structure, which makes them usable as dict/set members and
keeps comparisons in the unification and attacker closures cheap.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

__all__ = [
    "UNSET",
    "AsymEnc",
    "Atom",
    "Hash",
    "Pk",
    "SharedKey",
    "Sign",
    "Sk",
    "SymEnc",
    "Term",
    "Tuple",
    "Var",
    "ground",
    "intern",
    "intern_all",
    "leaves",
]


class UNSET:
    """Sentinel used where ``None`` is a meaningful value."""


class Term:
    """Base class of every symbolic term."""

    __slots__ = ()

    # -- structure -----------------------------------------------------
    def children(self) -> tuple[Term, ...]:
        """Return the immediate sub-terms of this term."""
        return ()

    def size(self) -> int:
        """Return the number of constructor nodes in this term."""
        return 1 + sum(c.size() for c in self.children())

    def vars(self) -> frozenset[str]:
        """Return the set of qualified variable names occurring in this term."""
        if isinstance(self, Var):
            return frozenset((self.name,))
        out: set[str] = set()
        for c in self.children():
            out |= c.vars()
        return frozenset(out)

    def subterms(self) -> tuple[Term, ...]:
        """Return ``self`` followed by every proper sub-term, in prefix order."""
        out: list[Term] = [self]
        for c in self.children():
            out.extend(c.subterms())
        return tuple(out)

    def at(self, path: tuple[int, ...]) -> Term:
        """Return the sub-term reached by following child indices ``path``."""
        node = self
        for i in path:
            node = node.children()[i]
        return node

    # -- rewriting -----------------------------------------------------
    def substitute(self, sigma: Mapping[str, Term]) -> Term:
        """Return this term with every bound variable replaced."""
        if not sigma or not self.vars():
            return self
        return _substitute(self, sigma, {})

    def map_atoms(self, f: Callable[[str], str]) -> Term:
        """Return this term with every :class:`Atom` name passed through ``f``."""
        return _map_atoms(self, f, {})

    # -- display -------------------------------------------------------
    def text(self, nested: bool = False) -> str:
        """Render the term; tuples drop their parentheses when ``nested``."""
        raise NotImplementedError

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.text()


def _substitute(t: Term, sigma: Mapping[str, Term], memo: dict[Term, Term]) -> Term:
    cached = memo.get(t)
    if cached is not None:
        return cached
    if isinstance(t, Var):
        target = _resolve_var(t, sigma, frozenset())
        result = t if target is t else _substitute(target, sigma, memo)
        memo[t] = result
        return result
    if not t.children():
        memo[t] = t
        return t
    new = _rebuild(t, tuple(_substitute(c, sigma, memo) for c in t.children()))
    memo[t] = new
    return new


def _resolve_var(var: Var, sigma: Mapping[str, Term], seen: frozenset[str]) -> Term:
    """Follow a chain of variable bindings until a non-variable is reached."""
    if var.name in seen:
        return var
    target = sigma.get(var.name)
    if target is None:
        return var
    if isinstance(target, Var):
        if target.name == var.name:
            return var
        return _resolve_var(target, sigma, seen | {var.name})
    return target


def _map_atoms(t: Term, f: Callable[[str], str], memo: dict[Term, Term]) -> Term:
    cached = memo.get(t)
    if cached is not None:
        return cached
    if isinstance(t, Atom):
        new: Term = Atom(f(t.name))
    elif not t.children():
        new = t
    else:
        new = _rebuild(t, tuple(_map_atoms(c, f, memo) for c in t.children()))
    memo[t] = new
    return new


def _rebuild(t: Term, kids: tuple[Term, ...]) -> Term:
    """Rebuild ``t`` with new children, returning ``t`` itself when unchanged."""
    if isinstance(t, Tuple):
        return Tuple(kids)
    if isinstance(t, SymEnc):
        return SymEnc(kids[0], kids[1])
    if isinstance(t, AsymEnc):
        return AsymEnc(kids[0], kids[1])
    if isinstance(t, Sign):
        return Sign(kids[0], kids[1])
    if isinstance(t, Hash):
        return Hash(kids[0], t.name)
    if isinstance(t, Pk):
        return Pk(kids[0])
    if isinstance(t, Sk):
        return Sk(kids[0])
    if isinstance(t, SharedKey):
        return SharedKey(kids[0], kids[1])
    raise TypeError(f"cannot rebuild {type(t).__name__}")  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Atom(Term):
    """A constant: an agent name, a fresh value (``ni#1``) or a declared constant."""

    name: str

    def text(self, nested: bool = False) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Var(Term):
    """A protocol variable.  ``name`` is qualified as ``<run-prefix>::<name>``.

    The declared type is metadata, not part of the term's identity: two variables
    with the same name are the same value even when they were declared with
    different (compatible) types, which is what makes ``substitute`` idempotent.
    """

    name: str
    type_name: str = field(default="Any", compare=False)

    def text(self, nested: bool = False) -> str:
        return short_name(self.name)


@dataclass(frozen=True, slots=True)
class Tuple(Term):
    """An ordered tuple ``(a, b, c)``."""

    items: tuple[Term, ...]

    def children(self) -> tuple[Term, ...]:
        return self.items

    def text(self, nested: bool = False) -> str:
        body = ",".join(c.text(True) for c in self.items)
        return body if nested else f"({body})"


@dataclass(frozen=True, slots=True)
class SymEnc(Term):
    """Symmetric encryption ``{m}k``."""

    msg: Term
    key: Term

    def children(self) -> tuple[Term, ...]:
        return (self.msg, self.key)

    def text(self, nested: bool = False) -> str:
        return f"{{{self.msg.text(True)}}}k({self.key.text(True)})"


@dataclass(frozen=True, slots=True)
class AsymEnc(Term):
    """Asymmetric encryption ``{m}pk(A)``."""

    msg: Term
    key: Term

    def children(self) -> tuple[Term, ...]:
        return (self.msg, self.key)

    def text(self, nested: bool = False) -> str:
        return f"{{{self.msg.text(True)}}}{self.key.text(True)}"


@dataclass(frozen=True, slots=True)
class Sign(Term):
    """A digital signature ``{m}sk(A)``.  Signatures are not confidential."""

    msg: Term
    key: Term

    def children(self) -> tuple[Term, ...]:
        return (self.msg, self.key)

    def text(self, nested: bool = False) -> str:
        key = self.key.agent.text(True) if isinstance(self.key, Sk) else self.key.text(True)
        return f"{{{self.msg.text(True)}}}sk({key})"


@dataclass(frozen=True, slots=True)
class Hash(Term):
    """A one-way hash ``h(m)``."""

    term: Term
    name: str = "h"

    def children(self) -> tuple[Term, ...]:
        return (self.term,)

    def text(self, nested: bool = False) -> str:
        return f"{self.name}({self.term.text(True)})"


@dataclass(frozen=True, slots=True)
class Pk(Term):
    """A public key ``pk(A)``."""

    agent: Term

    def children(self) -> tuple[Term, ...]:
        return (self.agent,)

    def text(self, nested: bool = False) -> str:
        return f"pk({self.agent.text(True)})"


@dataclass(frozen=True, slots=True)
class Sk(Term):
    """A long-term secret key ``sk(A)``."""

    agent: Term

    def children(self) -> tuple[Term, ...]:
        return (self.agent,)

    def text(self, nested: bool = False) -> str:
        return f"sk({self.agent.text(True)})"


@dataclass(frozen=True, slots=True)
class SharedKey(Term):
    """A pairwise shared key ``k(A,B)``."""

    left: Term
    right: Term

    def children(self) -> tuple[Term, ...]:
        return (self.left, self.right)

    def text(self, nested: bool = False) -> str:
        return f"k({self.left.text(True)},{self.right.text(True)})"


# ---------------------------------------------------------------------------
# Interning
# ---------------------------------------------------------------------------

_CACHE: dict[Term, Term] = {}


def intern(term: Term) -> Term:
    """Return a canonical instance of ``term``.

    Terms are value objects, so interning is purely an optimisation: it keeps
    identity comparisons (which the attacker closure and the search rely on for
    set membership) fast by making structurally equal terms the same object.
    """
    cached = _CACHE.get(term)
    if cached is not None:
        return cached
    _CACHE[term] = term
    return term


def intern_all(terms: Iterable[Term]) -> list[Term]:
    """Intern every term of ``terms``."""
    return [intern(t) for t in terms]


def short_name(qualified: str) -> str:
    """Strip the run qualifier (``r3::ni`` -> ``ni``)."""
    _, sep, tail = qualified.rpartition("::")
    return tail if sep else qualified


def ground(term: Term) -> bool:
    """True when ``term`` contains no variables."""
    return not term.vars()


def leaves(term: Term) -> tuple[Term, ...]:
    """Return the atomic sub-terms (atoms, keys, and variables) of ``term``."""
    if isinstance(term, (Atom, Var, Pk, Sk, SharedKey)):
        return (term,)
    out: list[Term] = []
    for c in term.children():
        out.extend(leaves(c))
    return tuple(out)
