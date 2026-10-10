"""Role instances ("runs") of a protocol.

A run binds one role of the protocol to a concrete *agent* (the role's own
parameter) and a concrete *peer* (every other role parameter).  Variable names
are qualified with the run id (``r3::ni``) so that several runs of the same role
can coexist in one search state without their variables clashing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..parser.ast import (
    ClaimEvent,
    Event,
    FreshEvent,
    RecvEvent,
    Role,
    SendEvent,
    VarEvent,
)
from .terms import Atom, Term, Var

__all__ = ["RUN_PREFIX", "Run"]

RUN_PREFIX = "r"


@dataclass(slots=True)
class Run:
    """One execution of one role by one concrete agent."""

    id: int
    role: Role
    agent: str
    peer: str
    params: tuple[str, ...] = ()
    _var_types: dict[str, str] = field(default_factory=dict)

    @classmethod
    def create(
        cls, run_id: int, role: Role, agent: str, peer: str, params: tuple[str, ...]
    ) -> Run:
        """Build a run and pre-bind every ``fresh`` declaration it makes."""
        return cls(
            id=run_id,
            role=role,
            agent=agent,
            peer=peer,
            params=params,
            _var_types=var_types(role),
        )

    # -- naming ----------------------------------------------------------
    @property
    def prefix(self) -> str:
        """The run qualifier used for variable names."""
        return f"{RUN_PREFIX}{self.id}"

    def scope(self, name: str) -> str:
        """Qualify the role-local variable ``name`` for this run."""
        return f"{self.prefix}::{name}"

    def fresh_atom(self, name: str) -> Atom:
        """Return the unique atom standing for the fresh value ``name``."""
        return Atom(f"{name}#{self.id}")

    def var_type(self, name: str) -> str:
        """Return the declared type of the role-local variable ``name``."""
        return self._var_types.get(name, "Any")

    # -- scoping ---------------------------------------------------------
    def agent_env(self) -> dict[str, str]:
        """Map role parameters to concrete agents.

        The role's own parameter becomes :attr:`agent`; every other parameter
        becomes :attr:`peer` (a broadcast model, exact for two-role protocols).
        """
        env: dict[str, str] = {}
        for param in self.params:
            env[param] = self.agent if param == self.role.name else self.peer
        return env

    def instantiate(self, term: Term) -> Term:
        """Scope variables to this run and resolve agent parameters."""
        qualified = _qualify(term, self)
        return qualified.map_atoms(lambda n: self.agent_env().get(n, n))

    def base_substitution(self) -> dict[str, Term]:
        """Return the bindings introduced by this run's ``fresh`` statements."""
        return {self.scope(ev.name): self.fresh_atom(ev.name) for ev in self.role.events
                if isinstance(ev, FreshEvent)}

    # -- events ----------------------------------------------------------
    @property
    def events(self) -> tuple[Event, ...]:
        """Return the role's events (claims included)."""
        return self.role.events

    def event(self, index: int) -> Event:
        """Return the event at ``index`` of this run."""
        return self.role.events[index]

    def message_events(self) -> tuple[SendEvent | RecvEvent, ...]:
        """Return the message events of this run, in program order."""
        return self.role.messages

    def declared_vars(self) -> tuple[VarEvent, ...]:
        """Return the ``var`` declarations of this run."""
        return tuple(e for e in self.role.events if isinstance(e, VarEvent))

    def claims(self) -> tuple[ClaimEvent, ...]:
        """Return the claims of this run."""
        return self.role.claims


def var_types(role: Role) -> dict[str, str]:
    """Return the declared type of every variable of ``role``."""
    return {
        ev.name: ev.type_name
        for ev in role.events
        if isinstance(ev, (FreshEvent, VarEvent))
    }


def _qualify(term: Term, run: Run) -> Term:
    """Rewrite every variable of ``term`` into this run's scope."""
    names = term.vars()
    if not names:
        return term
    sigma = {n: Var(run.scope(n), run.var_type(n)) for n in names}
    return term.substitute(sigma)
