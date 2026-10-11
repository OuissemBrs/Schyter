"""The claim-driven symbolic search.

For every claim the searcher

1. creates one run of the claimant role with the requested partner agent;
2. maintains a causal DAG over *message* events only (intra-run program order
   plus send-to-recv message edges) and repeatedly branches over **which ready
   event fires next**:
   * a ``send`` simply fires and enlarges the attacker's knowledge;
   * a ``recv`` branches three ways -- **attacker** (the message is synthesizable
     from the knowledge available at that point), **existing run** (the receive
     unifies with a send of a run that already exists) and **new run** (a fresh
     run is instantiated to produce the message).  A fourth option starts a
     session nobody is waiting for, which is what makes man-in-the-middle
     relaying expressible;
3. prunes on run count, trace length, cycles, freshness, budgets and a
   canonicalising memo table;
4. when every message event has fired, the concrete trace is re-verified by the
   independent :mod:`protoverify.core.replay` checker before the claim is
   evaluated.

The attacker may invent values for ``Agent``/``Ticket`` variables but is never
allowed to guess a nonce: a nonce can only be bound to something the attacker
already *knows*, typically a nonce it decrypted out of an earlier message.
"""

from __future__ import annotations

import itertools
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Any

from ..parser.ast import ClaimEvent, FreshEvent, Protocol, RecvEvent, Role, SendEvent
from ..parser.checks import resolve_partner
from . import claims as claim_semantics
from .attacker import ATTACKER_CONSTANTS, Attacker, Knowledge
from .ordering import EventKey, Ordering
from .replay import Delivery, ReplayError, ReplayResult, replay
from .run import Run
from .terms import Atom, Term, Var, short_name
from .trace import AgentInfo, Edge, RunInfo, Status, Trace
from .types import TypeEnv
from .unify import unify

__all__ = ["GUESSABLE_TYPES", "Bounds", "ClaimResult", "Searcher", "Verifier"]

#: Types whose values the attacker may choose freely when answering a receive.
GUESSABLE_TYPES = frozenset({"Agent", "Ticket"})

#: Upper bounds that keep the guess space finite.
MAX_CANDIDATES = 12
MAX_GUESSES = 128


def _accepts(generated_kind: str, declared: str) -> bool:
    """True when a value of kind ``generated_kind`` may fill a ``declared`` variable.

    ``Ticket`` and ``Any`` are the permissive types and accept anything; a
    ``Nonce`` variable does not accept the attacker's key.  (Atoms themselves are
    polymorphic -- see ``core.types`` -- so this rule is stricter on purpose: the
    attacker should not present its key as if it were a nonce.)
    """
    return TypeEnv.builtin().kind(declared) in (generated_kind, "ticket", "any")


@dataclass(frozen=True, slots=True)
class Bounds:
    """The limits of a bounded verification run."""

    max_runs: int = 4
    max_trace_len: int = 20
    timeout: float = 30.0
    max_states: int = 200_000
    max_runs_per_role: int = 1

    def to_json(self) -> dict[str, Any]:
        """Return the bounds as they appear in a trace document."""
        return {"max_runs": self.max_runs, "max_len": self.max_trace_len}


@dataclass(frozen=True, slots=True)
class ClaimResult:
    """The outcome of verifying a single claim."""

    role: str
    claim: str
    status: str
    states: int
    seconds: float
    trace: Trace | None = None
    reason: str = ""
    kind: str = ""

    @property
    def falsified(self) -> bool:
        """True when the claim was disproved."""
        return self.status == Status.FALSIFIED.value

    @property
    def verified(self) -> bool:
        """True when no counterexample exists within the explored bounds."""
        return self.status == Status.VERIFIED.value

    @property
    def unknown(self) -> bool:
        """True when a budget was exhausted before the answer was known."""
        return self.status == Status.UNKNOWN.value


@dataclass(slots=True)
class _State:
    """A node of the search tree."""

    runs: dict[int, Run]
    next_id: int
    poset: Ordering
    sigma: dict[str, Term]
    order: tuple[EventKey, ...]
    deliveries: dict[EventKey, Delivery]
    knowledge: Knowledge

    def copy(self, **changes: Any) -> _State:
        """Return a copy of this state with ``changes`` applied."""
        return replace(self, **changes)


class Searcher:
    """Bounded claim-driven search over the space of concrete traces."""

    def __init__(
        self,
        protocol: Protocol,
        attacker: Attacker,
        bounds: Bounds,
        *,
        attacker_agent: str = "M",
        agent_pool: Sequence[str] = (),
    ) -> None:
        self.protocol = protocol
        self.attacker = attacker
        self.bounds = bounds
        self.attacker_agent = attacker_agent
        self.honest_pool = tuple(a for a in agent_pool if a != attacker_agent)
        self.full_pool = tuple(dict.fromkeys([*agent_pool, attacker_agent]))
        self._generated = tuple(
            (value, TypeEnv.builtin().kind(declared))
            for declared, value in sorted(ATTACKER_CONSTANTS.items())
        )

    # -- public API -------------------------------------------------------
    def verify_claim(self, role_name: str, claim: ClaimEvent) -> ClaimResult:
        """Search for a trace falsifying ``claim``; report the outcome."""
        return self.verify_role(role_name, [claim])[0]

    def verify_role(self, role_name: str, claims: Sequence[ClaimEvent]) -> list[ClaimResult]:
        """Verify every claim of ``role_name``, sharing one search per partner.

        Claims of the same role and partner always share a search: every
        terminal trace of that search is evaluated against *all* of them, so a
        claim that is falsified early never hides a later counterexample and a
        claim that survives is only reported VERIFIED once the whole (bounded)
        space has been exhausted.
        """
        started = time.monotonic()
        agent = self._default_agent(role_name)
        results: dict[str, ClaimResult] = {}
        if not self.attacker.is_honest(agent):
            reason = f"role {role_name} has no honest instantiation left"
            return [
                ClaimResult(role_name, c.label, Status.VERIFIED.value, 0,
                            time.monotonic() - started, None, reason, c.kind)
                for c in claims
            ]
        for partner, group in _group(claims, self.protocol).items():
            states, found, reason = self._search_group(role_name, agent, partner, group)
            for claim in group:
                trace = found.get(claim.label)
                if trace is not None:
                    status = Status.FALSIFIED.value
                elif reason:
                    status = Status.UNKNOWN.value
                else:
                    status = Status.VERIFIED.value
                results[claim.label] = ClaimResult(
                    role_name, claim.label, status, states,
                    time.monotonic() - started, trace, reason, claim.kind,
                )
        return [results[c.label] for c in claims]

    def _search_group(
        self,
        role_name: str,
        agent: str,
        partner: str | None,
        claims: Sequence[ClaimEvent],
    ) -> tuple[int, dict[str, Trace], str]:
        """Explore the traces of one (role, partner) claim group."""
        deadline = time.monotonic() + self.bounds.timeout
        visited: set[tuple[Any, ...]] = set()
        found: dict[str, Trace] = {}
        states = 0
        reason = ""
        for peer in self.peer_pool(agent):
            states, reason = self._explore(
                claims, role_name, partner, self._initial_state(role_name, agent, peer),
                states, deadline, visited, found,
            )
            if reason or len(found) == len(claims):
                return states, found, reason
        return states, found, reason

    def peer_pool(self, agent: str) -> tuple[str, ...]:
        """Honest agents the claimant run may take as its partner.

        Every claim is conditioned on the claimant run being honest, agent *and*
        partner (spec 6): a session that deliberately talks to the attacker is
        covered by that agent's own secrecy claims, not by its partner-agreement
        claims.  An agent is never its own partner.
        """
        pool = tuple(a for a in self.honest_pool if a != agent)
        return pool or (agent,)

    # -- setup ------------------------------------------------------------
    def _default_agent(self, role_name: str) -> str:
        for param in self.protocol.params:
            if param == role_name:
                return param
        return self.protocol.params[0]

    def _initial_state(self, role_name: str, agent: str, peer: str) -> _State:
        role = self.protocol.role(role_name)
        run = Run.create(1, role, agent, peer, self.protocol.params)
        poset = _empty_poset(role)
        return _State(
            runs={run.id: run},
            next_id=2,
            poset=poset,
            sigma=run.base_substitution(),
            order=(),
            deliveries={},
            knowledge=self.attacker.initial(),
        )

    # -- the main loop ----------------------------------------------------
    def _explore(
        self,
        claims: Sequence[ClaimEvent],
        role_name: str,
        partner: str | None,
        start: _State,
        states_so_far: int,
        deadline: float,
        visited: set[tuple[Any, ...]],
        found: dict[str, Trace],
    ) -> tuple[int, str]:
        """Drain the search tree reachable from ``start``.

        Returns the number of states explored and a non-empty reason when a
        budget stopped the exploration before the space was exhausted.
        """
        stack: list[_State] = [start]
        states = states_so_far
        while stack:
            states += 1
            if states > self.bounds.max_states:
                return states, "state budget exhausted"
            if time.monotonic() > deadline:
                return states, f"timeout after {self.bounds.timeout:g}s"
            state = stack.pop()
            key = self._canonical(state)
            if key in visited:
                continue
            visited.add(key)
            ready = self._ready(state)
            if not ready:
                self._collect(claims, role_name, partner, state, found)
                if len(found) == len(claims):
                    return states, ""
                continue
            for event in ready:
                stack.extend(self._advance(state, event))
        return states, ""

    def _ready(self, state: _State) -> tuple[EventKey, ...]:
        """Message events that may fire next, in deterministic order."""
        executed = set(state.order)
        return tuple(
            key
            for key in state.poset.linearize()
            if key not in executed
            and all(p in executed for p in state.poset.predecessors(key))
        )

    def _advance(self, state: _State, key: EventKey) -> list[_State]:
        """Fire an event, or resolve an undecided receive, yielding successors."""
        event = state.runs[key[0]].event(key[1])
        if isinstance(event, SendEvent):
            return [self._fire(state, key)]
        if isinstance(event, RecvEvent):
            if key in state.deliveries:
                return [self._fire(state, key)]
            return self._resolve_recv(state, key)
        return []  # pragma: no cover - the DAG only holds message events

    def _fire(self, state: _State, key: EventKey) -> _State:
        """Record that ``key`` has now happened, in this exact position."""
        order = (*state.order, key)
        run = state.runs[key[0]]
        event = run.event(key[1])
        if not isinstance(event, SendEvent):
            return state.copy(order=order)
        term = run.instantiate(event.msg).substitute(state.sigma)
        closure, _ = self.attacker.analyze(state.knowledge | {term})
        return state.copy(order=order, knowledge=closure)

    # -- resolving a receive ----------------------------------------------
    def _resolve_recv(self, state: _State, key: EventKey) -> list[_State]:
        """All ways of obtaining the message a ``recv`` event is waiting for."""
        run = state.runs[key[0]]
        event = run.event(key[1])
        assert isinstance(event, RecvEvent)
        children = list(self._attacker_branches(state, key, run, event))
        for send_run_id, send_slot in self._sends_in(state, event.label):
            child = self._match_send(state, key, send_run_id, send_slot)
            if child is not None:
                children.append(child)
        children.extend(self._new_run_branches(state, key, run, event))
        children.extend(self._spontaneous_runs(state, key))
        return children

    def _sends_in(self, state: _State, label: int) -> list[tuple[int, int]]:
        """Every send event that could deliver a message labelled ``label``."""
        out: list[tuple[int, int]] = []
        for run_id, run in sorted(state.runs.items()):
            for index, event in enumerate(run.events):
                if isinstance(event, SendEvent) and event.label == label:
                    out.append((run_id, index))
        return out

    def _attacker_branches(
        self, state: _State, key: EventKey, run: Run, event: RecvEvent
    ) -> list[_State]:
        """Let the attacker deliver ``event.msg`` by building it from its knowledge.

        A receive event may introduce variables the attacker has to fill in.  It
        may invent an agent name for an ``Agent``/``Ticket`` variable, and it may
        use its *own* generated constants (:data:`attacker.ATTACKER_CONSTANTS`)
        for a ``Nonce``/``Key``/``Data`` variable -- values it created itself, so
        producing them is sound.  Beyond that a value can only ever be bound to
        something the attacker *already knows*: usually a nonce it decrypted out
        of an earlier message.  Guessing an honest party's unknown fresh value
        would be unsound and is never attempted, which is why ``nM`` can never
        stand in for ``ni#1``.
        """
        term = run.instantiate(event.msg).substitute(state.sigma)
        out: list[_State] = []
        for guess in self._guesses(run, term, state.knowledge):
            sigma = {**state.sigma, **guess}
            concrete = term.substitute(sigma)
            if not self.attacker.can_synthesize(concrete, state.knowledge):
                continue
            closure, _ = self.attacker.analyze(state.knowledge | {concrete})
            out.append(
                state.copy(
                    sigma=sigma,
                    knowledge=closure,
                    order=(*state.order, key),
                    deliveries={**state.deliveries, key: Delivery("attacker")},
                )
            )
        return out

    def _guesses(self, run: Run, term: Term, knowledge: Knowledge) -> list[dict[str, Term]]:
        """Candidate bindings for the free variables of ``term``."""
        free = sorted(term.vars())
        per_var: list[list[Term]] = []
        for name in free:
            candidates = self._candidates(run.var_type(name), name, knowledge)
            if not candidates:
                return []
            per_var.append(candidates)
        guesses: list[dict[str, Term]] = []
        for combo in itertools.product(*per_var):
            guesses.append(dict(zip(free, combo, strict=True)))
            if len(guesses) >= MAX_GUESSES:
                break
        return guesses

    def _candidates(self, declared: str, name: str, knowledge: Knowledge) -> list[Term]:
        """The values the attacker may bind a ``declared``-typed variable to.

        Three sources, in order: the agent name it invents for ``Agent`` and
        ``Ticket`` variables, its own generated constants for the value types,
        and the atoms it has already learned.  The result is de-duplicated,
        because the generated constants are also part of ``K0`` and would
        otherwise be offered twice.
        """
        if declared in GUESSABLE_TYPES:
            return [Atom(f"{short_name(name)}@{self.attacker_agent}")]
        out: list[Term] = []
        for value, kind in self._generated:
            if _accepts(kind, declared):
                out.append(Atom(value))
        for term in self._candidate_values(knowledge):
            if term not in out:
                out.append(term)
        return out

    def _candidate_values(self, knowledge: Knowledge) -> list[Term]:
        """Values the attacker may *replay* into a receive event.

        Only *values* qualify: binding a nonce variable to a key or to a
        ciphertext would be nonsense, so the candidates are the atoms the
        attacker knows -- agent names, its own constants and the nonces it has
        decrypted.  Nothing here is an honest party's fresh value unless that
        value was actually sent, which is exactly what this list records.
        """
        values: list[Term] = [t for t in knowledge if isinstance(t, Atom)]
        values.sort(key=lambda t: t.text())
        return values[:MAX_CANDIDATES]

    def _match_send(
        self, state: _State, recv_key: EventKey, send_run_id: int, send_slot: int
    ) -> _State | None:
        """Deliver a receive event from a send of an already existing run."""
        if send_run_id == recv_key[0]:
            return None
        recv_run = state.runs[recv_key[0]]
        recv_event = recv_run.event(recv_key[1])
        send_run = state.runs[send_run_id]
        send_event = send_run.event(send_slot)
        assert isinstance(recv_event, RecvEvent) and isinstance(send_event, SendEvent)
        unified = self._unify_pair(state, send_run, send_event, recv_run, recv_event)
        if unified is None:
            return None
        sigma, poset = unified
        if not poset.add_edge((send_run_id, send_slot), recv_key, "message"):
            return None
        return state.copy(
            sigma=sigma,
            poset=poset,
            deliveries={**state.deliveries, recv_key: Delivery("send", (send_run_id, send_slot))},
        )

    def _new_run_branches(
        self, state: _State, recv_key: EventKey, recv_run: Run, recv_event: RecvEvent
    ) -> list[_State]:
        """Instantiate a brand new run whose send satisfies a receive event."""
        if len(state.runs) >= self.bounds.max_runs:
            return []
        out: list[_State] = []
        for role in self.protocol.roles:
            if self._role_runs(state, role.name) >= self.bounds.max_runs_per_role:
                continue
            slots = [i for i, e in enumerate(role.events)
                     if isinstance(e, SendEvent) and e.label == recv_event.label]
            if not slots or not self._fits(state, role):
                continue
            for agent, peer in self._assignments():
                for slot in slots:
                    child = self._new_run_branch(state, recv_key, recv_run, recv_event,
                                                 role, agent, peer, slot)
                    if child is not None:
                        out.append(child)
        return out

    def _spontaneous_runs(self, state: _State, pending: EventKey) -> list[_State]:
        """Start a session nobody is waiting for yet.

        A receive event is frequently blocked because the message it needs has
        not been produced -- Lowe's attack starts with Mallory relaying Alice's
        very first message to Bob.  Introducing an extra run lets the search
        produce that message; the bound on the number of runs keeps the blow-up
        in check.  The new run's first message is ordered *before* the blocked
        receive so that both interleavings are explored.
        """
        if len(state.runs) >= self.bounds.max_runs:
            return []
        out: list[_State] = []
        for role in self.protocol.roles:
            if self._role_runs(state, role.name) >= self.bounds.max_runs_per_role:
                continue
            if not self._fits(state, role):
                continue
            first = _first_message(role)
            if first is None:
                continue
            for agent, peer in self._assignments():
                child = self._spontaneous_run(state, role, agent, peer, pending)
                if child is not None:
                    out.append(child)
        return out

    def _spontaneous_run(
        self, state: _State, role: Role, agent: str, peer: str, pending: EventKey
    ) -> _State | None:
        """Instantiate ``role``, ordering its first message before ``pending``."""
        run = Run.create(state.next_id, role, agent, peer, self.protocol.params)
        poset = _extend(state.poset, run)
        first = _first_message(role)
        if first is not None and not poset.add_edge((run.id, first), pending, "order"):
            return None
        return _State(
            runs={**state.runs, run.id: run},
            next_id=state.next_id + 1,
            poset=poset,
            sigma={**state.sigma, **run.base_substitution()},
            order=state.order,
            deliveries=dict(state.deliveries),
            knowledge=state.knowledge,
        )

    def _new_run_branch(
        self,
        state: _State,
        recv_key: EventKey,
        recv_run: Run,
        recv_event: RecvEvent,
        role: Role,
        agent: str,
        peer: str,
        slot: int,
    ) -> _State | None:
        """Create a new run and try to deliver ``recv_event`` from its send ``slot``."""
        run = Run.create(state.next_id, role, agent, peer, self.protocol.params)
        send_event = role.events[slot]
        assert isinstance(send_event, SendEvent)
        unified = self._unify_pair(state, run, send_event, recv_run, recv_event,
                                   extra=run.base_substitution())
        if unified is None:
            return None
        sigma, poset = unified
        poset = _extend(poset, run)
        if not poset.add_edge((run.id, slot), recv_key, "message"):
            return None
        return _State(
            runs={**state.runs, run.id: run},
            next_id=state.next_id + 1,
            poset=poset,
            sigma=sigma,
            order=state.order,
            deliveries={**state.deliveries, recv_key: Delivery("send", (run.id, slot))},
            knowledge=state.knowledge,
        )

    # -- bounds and helpers ------------------------------------------------
    def _role_runs(self, state: _State, role_name: str) -> int:
        return sum(1 for r in state.runs.values() if r.role.name == role_name)

    def _fits(self, state: _State, role: Role) -> bool:
        """True when adding one more run of ``role`` stays inside the trace bound."""
        return len(state.runs) + len(role.messages) <= self.bounds.max_trace_len

    def _assignments(self) -> Iterable[tuple[str, str]]:
        """Every (agent, peer) pair a new run may use; nobody plays against itself."""
        for agent in self.full_pool:
            for peer in self.full_pool:
                if peer != agent:
                    yield agent, peer

    def _unify_pair(
        self,
        state: _State,
        send_run: Run,
        send_event: SendEvent,
        recv_run: Run,
        recv_event: RecvEvent,
        extra: dict[str, Term] | None = None,
    ) -> tuple[dict[str, Term], Ordering] | None:
        """Unify a send and a receive term under the current substitution."""
        base = dict(state.sigma)
        if extra:
            base.update(extra)
        left = send_run.instantiate(send_event.msg).substitute(base)
        right = recv_run.instantiate(recv_event.msg).substitute(base)
        sigma = unify(left, right, base)
        if sigma is None:
            return None
        if not self._fresh_available(state, sigma):
            return None
        return sigma, state.poset.copy()

    def _fresh_available(self, state: _State, sigma: dict[str, Term]) -> bool:
        """Reject bindings that mention a fresh value no instantiated run owns.

        A run creates all of its fresh values at the very start of its program,
        so as soon as the run exists its nonces are available; the message edges
        guarantee they are not used before the owning run produced them.
        """
        live = {
            run.fresh_atom(event.name).name
            for run in state.runs.values()
            for event in run.events
            if isinstance(event, FreshEvent)
        }
        for term in sigma.values():
            for atom in term.subterms():
                if isinstance(atom, Atom) and _looks_fresh(atom.name) and atom.name not in live:
                    return False
        return True

    # -- finishing a trace -------------------------------------------------
    def _collect(
        self,
        claims: Sequence[ClaimEvent],
        role_name: str,
        partner: str | None,
        state: _State,
        found: dict[str, Trace],
    ) -> None:
        """Replay a terminal trace and record a trace for every falsified claim."""
        try:
            replayed = replay(state.runs, state.sigma, state.order, state.deliveries,
                              self.attacker, self.attacker_agent)
        except ReplayError:  # pragma: no cover - a defensive guard
            return
        claimant = state.runs[1]
        del role_name
        for claim in claims:
            if claim.label in found:
                continue
            verdict = claim_semantics.evaluate(
                claim, claimant, state.runs, state.sigma, partner,
                lambda term: replayed.knows(self.attacker, term),
            )
            if not verdict.satisfied:
                found[claim.label] = self._build_trace(claim, state, replayed, verdict.violation)

    def _build_trace(
        self, claim: ClaimEvent, state: _State, replayed: ReplayResult, violation: str
    ) -> Trace:
        """Turn the verified search state into a renderer-ready trace."""
        runs = tuple(
            RunInfo(id=r.id, role=r.role.name, agent=r.agent, peer=r.peer)
            for r in sorted(state.runs.values(), key=lambda r: r.id)
        )
        agents: dict[str, AgentInfo] = {}
        for run in state.runs.values():
            agents.setdefault(run.agent, AgentInfo(run.agent, "honest"))
            agents.setdefault(run.peer, AgentInfo(run.peer, "honest"))
        agents[self.attacker_agent] = AgentInfo(self.attacker_agent, "attacker")
        edges = tuple(
            Edge(src=replayed.step_of[src], dst=replayed.step_of[dst], kind=kind)
            for src, dst, kind in state.poset.edges()
            if kind == "message" and src in replayed.step_of and dst in replayed.step_of
        )
        return Trace(
            protocol=self.protocol.name,
            claim=claim.label,
            status=Status.FALSIFIED.value,
            claim_kind=claim.kind,
            bounds=self.bounds.to_json(),
            agents=tuple(agents[a] for a in sorted(agents)),
            runs=runs,
            steps=tuple(replayed.steps),
            edges=edges,
            violation=violation,
        )

    # -- memoisation -------------------------------------------------------
    def _canonical(self, state: _State) -> tuple[Any, ...]:
        """Canonicalise a state so that isomorphic runs share a memo entry."""
        ids = sorted(state.runs)
        remap = {old: new + 1 for new, old in enumerate(ids)}
        var_map, atom_map = self._rename_maps(state, remap)
        sigma = tuple(
            sorted(
                (var_map[k].text() if k in var_map else k, _renamed(v, var_map, atom_map).text())
                for k, v in state.sigma.items()
            )
        )
        runs = tuple(
            (remap[rid], state.runs[rid].role.name, state.runs[rid].agent, state.runs[rid].peer)
            for rid in ids
        )
        order = tuple((remap[r], i) for r, i in state.order)
        deliveries = tuple(
            sorted(
                (remap[r], i, d.kind,
                 remap[d.source[0]] if d.source else 0,
                 d.source[1] if d.source else -1)
                for (r, i), d in state.deliveries.items()
            )
        )
        return (runs, sigma, order, deliveries)

    def _rename_maps(
        self, state: _State, remap: dict[int, int]
    ) -> tuple[dict[str, Term], dict[str, str]]:
        var_map: dict[str, Term] = {}
        atom_map: dict[str, str] = {}
        for old in sorted(state.runs):
            run = state.runs[old]
            for event in run.events:
                name = getattr(event, "name", None)
                if name is None:
                    continue
                var_map[run.scope(name)] = Var(f"r{remap[old]}::{name}", run.var_type(name))
                atom_map[run.fresh_atom(name).name] = f"{name}#{remap[old]}"
        return var_map, atom_map


class Verifier:
    """Ties a parsed protocol to an attacker model and runs every claim."""

    def __init__(
        self,
        protocol: Protocol,
        bounds: Bounds | None = None,
        compromised: Iterable[str] = (),
        *,
        attacker_agent: str = "M",
    ) -> None:
        self.protocol = protocol
        self.bounds = bounds or Bounds()
        self.attacker_agent = attacker_agent
        self.compromised = frozenset(dict.fromkeys([*compromised, attacker_agent]))
        self.attacker = Attacker(
            agents=self.agent_pool(),
            compromised=self.compromised,
            constants=[Atom(c) for c in protocol.constants],
        )
        self.searcher = Searcher(
            protocol,
            self.attacker,
            self.bounds,
            attacker_agent=attacker_agent,
            agent_pool=self.agent_pool(),
        )

    def agent_pool(self) -> tuple[str, ...]:
        """Every agent name the search may assign to a role."""
        names: list[str] = list(self.protocol.params)
        for name in self.protocol.constants:
            if name not in names:
                names.append(name)
        for name in sorted(self.compromised):
            if name not in names:
                names.append(name)
        return tuple(names)

    def verify(self, only: Sequence[str] | None = None, *, share: bool = True) -> list[ClaimResult]:
        """Verify every claim of the protocol.

        By default one search serves all the claims of a ``(role, partner)`` group
        (see :meth:`Searcher.verify_role`).  ``share=False`` forces one search per
        claim instead; the results must be identical, which is what
        ``tests/integration/test_shared_search.py`` checks.  It is exposed as
        ``protoverify verify --no-share`` so the optimisation can be audited from
        the command line.
        """
        results: list[ClaimResult] = []
        for role_name in dict.fromkeys(r for r, _ in self.protocol.all_claims()):
            claims = [
                c
                for r, c in self.protocol.all_claims()
                if r == role_name and (not only or c.label in only)
            ]
            if not claims:
                continue
            if share:
                results.extend(self.searcher.verify_role(role_name, claims))
            else:
                for claim in claims:
                    results.extend(self.searcher.verify_role(role_name, [claim]))
        return results


# ---------------------------------------------------------------------------
# module helpers
# ---------------------------------------------------------------------------


def _renamed(term: Term, var_map: dict[str, Term], atom_map: dict[str, str]) -> Term:
    out = term.substitute(var_map) if var_map else term
    return out.map_atoms(lambda n: atom_map.get(n, n)) if atom_map else out


def _first_message(role: Role) -> int | None:
    """Index of the first message event of ``role``, if it has one."""
    for index, event in enumerate(role.events):
        if isinstance(event, (SendEvent, RecvEvent)):
            return index
    return None


def _empty_poset(role: Role) -> Ordering:
    """Return the causal DAG holding ``role``'s message events in program order."""
    poset = Ordering()
    keys = _message_keys(1, role)
    for key in keys:
        poset.add_node(key)
    poset.add_path(keys, "order")
    return poset


def _extend(poset: Ordering, run: Run) -> Ordering:
    """Add ``run``'s message events and their program order to a copy of ``poset``."""
    clone = poset.copy()
    keys = _message_keys(run.id, run.role)
    for key in keys:
        clone.add_node(key)
    clone.add_path(keys, "order")
    return clone


def _message_keys(run_id: int, role: Role) -> list[EventKey]:
    """Event keys of every message event of ``role``, in program order."""
    return [
        (run_id, index)
        for index, event in enumerate(role.events)
        if isinstance(event, (SendEvent, RecvEvent))
    ]


def _looks_fresh(name: str) -> bool:
    """True when ``name`` has the shape ``<fresh>#<run id>``."""
    head, sep, tail = name.rpartition("#")
    return bool(sep) and tail.isdigit() and bool(head)


def _group(
    claims: Sequence[ClaimEvent], protocol: Protocol
) -> dict[str | None, list[ClaimEvent]]:
    """Group claims by partner role so that one search can serve all of them."""
    groups: dict[str | None, list[ClaimEvent]] = {}
    for claim in claims:
        groups.setdefault(resolve_partner(protocol, claim), []).append(claim)
    return groups
