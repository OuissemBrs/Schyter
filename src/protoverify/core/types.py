"""Typing discipline for ProtoVerify.

The typing rule is deliberately coarse (documented in ``docs/spdl.md``):

* a variable of type ``Agent`` unifies only with agent-denoting terms;
* a variable of type ``Nonce``/``Key``/``Data`` unifies with the corresponding
  non-agent terms;
* the built-in opaque type ``Ticket`` unifies with *any* term, which models a
  "ticket"/session identifier that carries no algebraic structure;
* ``Any`` (the default) unifies with everything.

Atoms are polymorphic: the same constructor denotes an agent name, a fresh
value or a declared constant depending on context, so an atom satisfies every
non-agent tag.
"""

from __future__ import annotations

from dataclasses import dataclass

from .terms import AsymEnc, Atom, Hash, Pk, SharedKey, Sign, Sk, SymEnc, Term, Tuple, Var

__all__ = ["BUILTIN_TYPES", "KIND_TAGS", "TypeEnv", "compatible", "tags_of"]

#: Tags attached to each type kind.
KIND_TAGS: dict[str, frozenset[str]] = {
    "agent": frozenset({"agent"}),
    "nonce": frozenset({"nonce"}),
    "key": frozenset({"key"}),
    "data": frozenset({"data"}),
    "ticket": frozenset({"agent", "nonce", "key", "data"}),
    "any": frozenset({"agent", "nonce", "key", "data"}),
}

#: Types that always exist.
BUILTIN_TYPES: tuple[str, ...] = ("Nonce", "Agent", "Key", "Data", "Ticket", "Any")

KIND_OF: dict[str, str] = {
    "Nonce": "nonce",
    "Agent": "agent",
    "Key": "key",
    "Data": "data",
    "Ticket": "ticket",
    "Any": "any",
}


@dataclass(frozen=True, slots=True)
class TypeEnv:
    """The set of type names known to a protocol."""

    names: frozenset[str]

    @classmethod
    def builtin(cls) -> TypeEnv:
        """Return the environment containing only the built-in types."""
        return cls(frozenset(BUILTIN_TYPES))

    def with_user_types(self, declared: frozenset[str]) -> TypeEnv:
        """Return a copy extended by ``declared`` user type names."""
        return TypeEnv(self.names | declared)

    def knows(self, name: str) -> bool:
        """True when ``name`` is a declared type."""
        return name in self.names

    def kind(self, name: str) -> str:
        """Return the kind of ``name`` (unknown types behave like ``Data``)."""
        return KIND_OF.get(name, "data")

    def tags(self, name: str) -> frozenset[str]:
        """Return the tag set of the type ``name``."""
        return KIND_TAGS[self.kind(name)]


def tags_of(term: Term) -> frozenset[str]:
    """Return the type tags satisfied by the *value* ``term``."""
    if isinstance(term, Var):
        return KIND_TAGS[KIND_OF.get(term.type_name, "any")]
    if isinstance(term, Atom):
        return KIND_TAGS["any"]
    if isinstance(term, (Pk, Sk, SharedKey)):
        return frozenset({"agent", "key", "data"})
    if isinstance(term, (Tuple, SymEnc, AsymEnc, Sign, Hash)):
        return frozenset({"nonce", "data"})
    return frozenset({"any"})  # pragma: no cover


def compatible(type_name: str, term: Term) -> bool:
    """True when a variable of type ``type_name`` may be bound to ``term``."""
    if isinstance(term, Var):
        return bool(_var_tags(type_name) & tags_of(term))
    if isinstance(term, Atom):
        # Atoms are polymorphic; every declared type accepts them, except that an
        # Agent variable is happy with any constant as well.
        return True
    return bool(_var_tags(type_name) & tags_of(term))


def _var_tags(type_name: str) -> frozenset[str]:
    return KIND_TAGS[KIND_OF.get(type_name, "any")]
