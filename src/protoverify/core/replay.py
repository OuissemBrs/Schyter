"""The independent forward replay checker.

The search proposes a trace; this module re-executes it from scratch using only
the run table, the substitution and the attacker's Dolev-Yao rules.  If replay
fails, the search discards the branch, which guards the engine against its own
bookkeeping bugs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..parser.ast import RecvEvent, SendEvent
from .attacker import Attacker, Knowledge
from .ordering import EventKey
from .run import Run
from .terms import Atom, SharedKey, Term
from .trace import Step

__all__ = ["Delivery", "ReplayError", "ReplayResult", "replay"]

_FRESH = re.compile(r"^(?P<name>.+)#(?P<run>\d+)$")

#: Term kinds worth showing on the knowledge panel: values and shared keys.
_VALUE_TERMS = (Atom, SharedKey)


class ReplayError(AssertionError):
    """Raised when a proposed trace does not replay consistently."""


@dataclass(frozen=True, slots=True)
class Delivery:
    """How a ``recv`` event obtained its message."""

    kind: str  # "attacker" or "send"
    source: EventKey | None = None


@dataclass(slots=True)
class ReplayResult:
    """The verified trace plus the attacker's knowledge at every step."""

    steps: list[Step] = field(default_factory=list)
    knowledge: list[Knowledge] = field(default_factory=list)
    step_of: dict[EventKey, int] = field(default_factory=dict)

    def knows(self, attacker: Attacker, term: Term) -> bool:
        """True when the attacker can build ``term`` at the end of the trace."""
        final = self.knowledge[-1] if self.knowledge else frozenset()
        return attacker.can_synthesize(term, final)


def replay(
    runs: dict[int, Run],
    sigma: dict[str, Term],
    order: tuple[EventKey, ...],
    deliveries: dict[EventKey, Delivery],
    attacker: Attacker,
    attacker_agent: str,
) -> ReplayResult:
    """Re-execute ``order`` and return the verified steps.

    Raises :class:`ReplayError` when the trace is inconsistent: an unknown event,
    a message that does not match the substitution, a delivery that could not
    have happened, a fresh value no run owns, or an attacker step whose message
    is not synthesizable from the attacker's knowledge at that point.
    """
    result = ReplayResult()
    knowledge: set[Term] = set(attacker.initial())
    position = {key: i for i, key in enumerate(order)}
    delivered_from: list[tuple[str, str]] = []
    _check_deliveries(order, deliveries, position)
    for key in order:
        event = _event_of(runs, key)
        if not isinstance(event, (SendEvent, RecvEvent)):
            continue
        term = _ground_message(runs, key, event, sigma)
        _check_freshness(runs, term)
        closure, _ = attacker.analyze(knowledge | {term})
        learned = _newly_learned(closure, knowledge)
        step = _step_for(runs, key, event, term, deliveries, attacker,
                         attacker_agent, knowledge, delivered_from, learned)
        delivered_from.append((step.frm, step.msg))
        knowledge = set(closure)
        result.step_of[key] = len(result.steps) + 1
        result.steps.append(_numbered(step, result.step_of[key]))
        result.knowledge.append(frozenset(knowledge))
    return result


def _newly_learned(closure: Knowledge, before: set[Term]) -> tuple[str, ...]:
    """The value-terms the attacker's knowledge gained from one message.

    The difference is taken between the Dolev-Yao closures before and after the
    message, so a nonce sealed inside a ciphertext addressed to somebody else is
    *not* reported as learned; only what ``analyze`` can actually derive shows up.
    """
    gained = [t for t in closure - frozenset(before) if isinstance(t, _VALUE_TERMS)]
    return tuple(sorted({t.text() for t in gained}, key=str))


def _numbered(step: Step, index: int) -> Step:
    """Return ``step`` with its final 1-based position filled in."""
    return Step(
        i=index,
        type=step.type,
        run=step.run,
        frm=step.frm,
        to=step.to,
        label=step.label,
        msg=step.msg,
        attacker_new=step.attacker_new,
        note=step.note,
    )


def _event_of(runs: dict[int, Run], key: EventKey) -> object:
    """Return the event ``key`` addresses, validating the reference."""
    run = runs.get(key[0])
    if run is None:
        raise ReplayError(f"trace refers to unknown run {key[0]}")
    if not 0 <= key[1] < len(run.events):
        raise ReplayError(f"run {key[0]} has no event {key[1]}")
    return run.event(key[1])


def _ground_message(
    runs: dict[int, Run], key: EventKey, event: SendEvent | RecvEvent, sigma: dict[str, Term]
) -> Term:
    """Return the concrete message of ``key``; reject a half-substituted one."""
    term = runs[key[0]].instantiate(event.msg).substitute(sigma)
    if term.vars():
        raise ReplayError(f"message still contains variables: {term.text()}")
    return term


def _step_for(
    runs: dict[int, Run],
    key: EventKey,
    event: SendEvent | RecvEvent,
    term: Term,
    deliveries: dict[EventKey, Delivery],
    attacker: Attacker,
    attacker_agent: str,
    knowledge: set[Term],
    delivered: list[tuple[str, str]],
    learned: tuple[str, ...],
) -> Step:
    """Build and validate the trace step for one message event."""
    run = runs[key[0]]
    label = str(event.label)
    if isinstance(event, SendEvent):
        return _honest_step(run, label, term, learned, "send")
    delivery = deliveries.get(key)
    if delivery is None:
        raise ReplayError(f"receive event {key} was never resolved")
    if delivery.kind != "attacker":
        return _relay_step(runs, key, term, label, delivery, attacker_agent)
    if not attacker.can_synthesize(term, frozenset(knowledge)):
        raise ReplayError(
            f"the attacker cannot build {term.text()} from its knowledge at this point"
        )
    relayed = (run.peer, term.text()) in delivered
    return _attacker_step(
        run, label, term, learned, attacker_agent,
        "forward" if relayed else "forge",
    )


def _honest_step(run: Run, label: str, term: Term, learned: tuple[str, ...], verb: str) -> Step:
    """Build the step of a message an honest run sent or received directly."""
    return Step(
        i=0,
        type="send" if verb == "send" else "recv",
        run=run.id,
        frm=run.agent if verb == "send" else run.peer,
        to=run.peer if verb == "send" else run.agent,
        label=label,
        msg=term.text(),
        attacker_new=learned if verb == "send" else (),
        note=_note(run, label, verb),
    )


def _attacker_step(
    run: Run, label: str, term: Term, learned: tuple[str, ...], attacker_agent: str, verb: str
) -> Step:
    """Build the step of a message the attacker supplied itself."""
    return Step(
        i=0,
        type="attacker_forward" if verb == "forward" else "attacker_inject",
        run=None,
        frm=attacker_agent,
        to=run.agent,
        label=label,
        msg=term.text(),
        attacker_new=learned,
        note=_note(run, label, verb, attacker=attacker_agent),
    )


def _relay_step(
    runs: dict[int, Run],
    key: EventKey,
    term: Term,
    label: str,
    delivery: Delivery,
    attacker_agent: str,
) -> Step:
    """Describe a receive whose message came from another run's send.

    When the sending agent is not the receiver's own peer, a third party must
    have relayed it, so the step is attributed to the attacker.
    """
    run = runs[key[0]]
    source = delivery.source
    assert source is not None
    sender = runs[source[0]].agent
    if sender == run.peer:
        return _honest_step(run, label, term, (), "receive")
    return _attacker_step(run, label, term, (), attacker_agent, "forward")


def _note(run: Run, label: str, verb: str, *, attacker: str = "") -> str:
    """Compose the one-line natural-language caption of a step."""
    if attacker:
        if verb == "forward":
            return f"{attacker} relays message {label} on to {run.agent}, pretending to be {run.peer}."
        return f"{attacker} forges message {label} and injects it into {run.agent}'s session."
    if verb == "send":
        return f"{run.agent} sends message {label} to {run.peer}."
    return f"{run.agent} receives message {label} from {run.peer}."


def _check_freshness(runs: dict[int, Run], term: Term) -> None:
    """Reject a message mentioning a fresh value no instantiated run owns.

    A run creates all of its fresh values at the very start of its program, so
    an existing run always owns its nonces; the message edges in the causal order
    guarantee that a nonce is only ever mentioned after the owning run produced
    the message that could have leaked it.
    """
    for atom in term.subterms():
        if not isinstance(atom, Atom):
            continue
        match = _FRESH.match(atom.name)
        if match is None:
            continue
        if int(match.group("run")) not in runs:
            raise ReplayError(f"message {term.text()} mentions unknown fresh value {atom.name}")


def _check_deliveries(
    order: tuple[EventKey, ...], deliveries: dict[EventKey, Delivery], position: dict[EventKey, int]
) -> None:
    """Every send delivery must come from an event that really happened before."""
    for key, delivery in deliveries.items():
        if delivery.kind != "send" or delivery.source is None:
            continue
        if key not in position or delivery.source not in position:
            raise ReplayError(f"delivery of {key} refers to an event outside the trace")
        if position[delivery.source] >= position[key]:
            raise ReplayError(f"delivery of {key} comes from a later event {delivery.source}")


def is_recv(event: object) -> bool:
    """True when ``event`` is a receive event (small public predicate)."""
    return isinstance(event, RecvEvent)
