"""The frozen AST produced by :mod:`protoverify.parser.parser`."""

from __future__ import annotations

from dataclasses import dataclass

from ..core.terms import Term
from ..core.types import TypeEnv
from .errors import Pos

__all__ = [
    "CLAIM_KINDS",
    "MESSAGE_EVENTS",
    "ClaimEvent",
    "Event",
    "FreshEvent",
    "Protocol",
    "RecvEvent",
    "Role",
    "SendEvent",
    "VarEvent",
]

CLAIM_KINDS: tuple[str, ...] = ("Secret", "Alive", "Weakagree", "Niagree", "Nisynch")


@dataclass(frozen=True, slots=True)
class SendEvent:
    """``send_L(A, B, t)`` -- ``A`` is the sending role's agent, ``B`` its peer."""

    label: int
    src: Term
    dst: Term
    msg: Term
    pos: Pos


@dataclass(frozen=True, slots=True)
class RecvEvent:
    """``recv_L(A, B, t)`` -- ``B`` is this role's agent; ``A`` is only a belief.

    The receiver does **not** check that ``A`` is the true sender, which is what
    lets the attacker impersonate a peer.
    """

    label: int
    src: Term
    dst: Term
    msg: Term
    pos: Pos


@dataclass(frozen=True, slots=True)
class FreshEvent:
    """``fresh x: T;`` -- declares a value that must be globally unique."""

    name: str
    type_name: str
    pos: Pos


@dataclass(frozen=True, slots=True)
class VarEvent:
    """``var x: T;`` -- declares a variable whose value is learned."""

    name: str
    type_name: str
    pos: Pos


@dataclass(frozen=True, slots=True)
class ClaimEvent:
    """``claim_L(Role, Kind[, term|Partner])``."""

    label: str
    claimant: str
    kind: str
    argument: Term | None
    partner: str | None
    pos: Pos


Event = SendEvent | RecvEvent | FreshEvent | VarEvent | ClaimEvent

#: Event kinds that carry a protocol message.
MESSAGE_EVENTS = (SendEvent, RecvEvent)


@dataclass(frozen=True, slots=True)
class Role:
    """One role (one protocol party) of a protocol."""

    name: str
    events: tuple[Event, ...]
    pos: Pos

    @property
    def fresh_names(self) -> tuple[str, ...]:
        """Return the names declared ``fresh`` by this role, in order."""
        return tuple(e.name for e in self.events if isinstance(e, FreshEvent))

    @property
    def var_names(self) -> tuple[str, ...]:
        """Return the names declared ``var`` by this role, in order."""
        return tuple(e.name for e in self.events if isinstance(e, VarEvent))

    @property
    def claims(self) -> tuple[ClaimEvent, ...]:
        """Return the claims of this role, in order."""
        return tuple(e for e in self.events if isinstance(e, ClaimEvent))

    @property
    def messages(self) -> tuple[SendEvent | RecvEvent, ...]:
        """Return the message events of this role, in program order."""
        return tuple(e for e in self.events if isinstance(e, MESSAGE_EVENTS))


@dataclass(frozen=True, slots=True)
class Protocol:
    """A complete protocol description."""

    name: str
    params: tuple[str, ...]
    roles: tuple[Role, ...]
    user_types: frozenset[str]
    constants: tuple[str, ...]
    hash_functions: tuple[str, ...]
    secrets: tuple[str, ...]
    type_env: TypeEnv
    pos: Pos

    def role(self, name: str) -> Role:
        """Return the role called ``name``; raises ``KeyError`` when absent."""
        for r in self.roles:
            if r.name == name:
                return r
        raise KeyError(name)

    def has_role(self, name: str) -> bool:
        """True when a role called ``name`` exists."""
        return any(r.name == name for r in self.roles)

    def all_claims(self) -> tuple[tuple[str, ClaimEvent], ...]:
        """Return every ``(role_name, claim)`` pair of the protocol."""
        return tuple((r.name, c) for r in self.roles for c in r.claims)
