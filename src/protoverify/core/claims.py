"""Formal claim semantics.

The five claims ProtoVerify understands are documented in ``docs/claims.md``.
For a claimant run ``r`` (executed by ``r.agent`` for peer ``r.peer``) and a
partner role ``P``:

``Secret(t)``
    in no consistent trace in which every agent of ``r`` is honest does the
    attacker know ``t``.
``Alive(P)``
    if ``r`` completes, ``P`` executed at least one event.
``Weakagree(P)``
    a run of ``P`` exists whose agent is ``r.peer`` and whose peer is ``r.agent``.
``Niagree(P)``
    ``Weakagree(P)`` and every message of ``r`` matches the corresponding
    message of that run up to the choice of keys (non-injective comparison).
``Nisynch(P)``
    ``Niagree(P)``, injective, with byte-identical message contents.

These give the hierarchy ``Nisynch => Niagree => Weakagree => Alive``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..parser.ast import ClaimEvent, RecvEvent, SendEvent
from .run import Run
from .terms import AsymEnc, Atom, Hash, Pk, SharedKey, Sign, Sk, SymEnc, Term, Tuple

__all__ = [
    "IMPLICATION_ORDER",
    "EventView",
    "Verdict",
    "alive_verdict",
    "concrete_messages",
    "corresponds",
    "data_view",
    "evaluate",
    "niagree",
    "nisynch",
    "no_partner_sentence",
    "weakagree",
]

#: Claims ordered from weakest to strongest.
IMPLICATION_ORDER: tuple[str, ...] = ("Alive", "Weakagree", "Niagree", "Nisynch")

_BLIND = Atom("<key>")


@dataclass(frozen=True, slots=True)
class Verdict:
    """The outcome of evaluating a claim on one concrete trace."""

    satisfied: bool
    violation: str = ""


@dataclass(frozen=True, slots=True)
class EventView:
    """A concrete message event of a run."""

    index: int
    label: str
    sending: bool
    term: Term

    @property
    def view(self) -> Term:
        """The full content of the message."""
        return self.term


def concrete_messages(run: Run, sigma: dict[str, Term]) -> tuple[EventView, ...]:
    """Return the concrete message events of ``run`` under ``sigma``."""
    out: list[EventView] = []
    for index, event in enumerate(run.events):
        if isinstance(event, (SendEvent, RecvEvent)):
            out.append(
                EventView(
                    index=index,
                    label=str(event.label),
                    sending=isinstance(event, SendEvent),
                    term=run.instantiate(event.msg).substitute(sigma),
                )
            )
    return tuple(out)


def data_view(term: Term) -> Term:
    """Erase key material from ``term`` for the non-injective comparison."""
    if isinstance(term, (Pk, Sk, SharedKey)):
        return _BLIND
    if isinstance(term, (SymEnc, AsymEnc, Sign)):
        return type(term)(data_view(term.msg), _BLIND)
    if isinstance(term, Hash):
        return Hash(data_view(term.term), term.name)
    if isinstance(term, Tuple):
        return Tuple(tuple(data_view(i) for i in term.items))
    return term


def evaluate(
    claim: ClaimEvent,
    claimant: Run,
    runs: dict[int, Run],
    sigma: dict[str, Term],
    partner_role: str | None,
    attacker_knows: Callable[[Term], bool],
) -> Verdict:
    """Evaluate ``claim`` for ``claimant`` on the concrete trace ``runs``."""
    if claim.kind == "Secret":
        return secret_verdict(claim, claimant, sigma, attacker_knows)
    if partner_role is None:  # pragma: no cover - the static checker rejects this
        return Verdict(True)
    if claim.kind == "Alive":
        return alive_verdict(claimant, runs, partner_role)
    checker = {"Weakagree": weakagree, "Niagree": niagree, "Nisynch": nisynch}[claim.kind]
    if checker(claimant, runs, partner_role, sigma):
        return Verdict(True)
    return Verdict(False, _mismatch_sentence(claimant, runs, partner_role, claim))


def secret_verdict(
    claim: ClaimEvent, claimant: Run, sigma: dict[str, Term],
    attacker_knows: Callable[[Term], bool],
) -> Verdict:
    """Evaluate a ``Secret`` claim."""
    if claim.argument is None:  # pragma: no cover - the static checker rejects this
        return Verdict(True)
    term = claimant.instantiate(claim.argument).substitute(sigma)
    if attacker_knows(term):
        return Verdict(
            False,
            f"The attacker learns {term.text()}, which {claimant.agent} claimed to be secret.",
        )
    return Verdict(True)


def alive_verdict(claimant: Run, runs: dict[int, Run], partner_role: str) -> Verdict:
    """Evaluate an ``Alive`` claim."""
    if any(r.role.name == partner_role for r in runs.values()):
        return Verdict(True)
    return Verdict(False, no_partner_sentence(claimant, partner_role))


def weakagree(
    claimant: Run, runs: dict[int, Run], partner_role: str, sigma: dict[str, Term]
) -> bool:
    """True when the partner role ran the protocol with ``claimant`` as its peer."""
    return _partner_run(claimant, runs, partner_role) is not None


def niagree(
    claimant: Run, runs: dict[int, Run], partner_role: str, sigma: dict[str, Term]
) -> bool:
    """True when ``Weakagree`` holds and the messages agree up to the keys."""
    partner = _partner_run(claimant, runs, partner_role)
    return partner is not None and corresponds(claimant, partner, sigma, injective=False)


def nisynch(
    claimant: Run, runs: dict[int, Run], partner_role: str, sigma: dict[str, Term]
) -> bool:
    """True when ``Niagree`` holds and the concrete messages are identical."""
    partner = _partner_run(claimant, runs, partner_role)
    return partner is not None and corresponds(claimant, partner, sigma, injective=True)


def _partner_run(claimant: Run, runs: dict[int, Run], partner_role: str) -> Run | None:
    """Return a partner run that is genuinely paired with ``claimant``."""
    for other in runs.values():
        if other is claimant or other.role.name != partner_role:
            continue
        if other.agent == claimant.peer and other.peer == claimant.agent:
            return other
    return None


def corresponds(run: Run, other: Run, sigma: dict[str, Term], *, injective: bool) -> bool:
    """True when ``other`` matches ``run`` event by event.

    ``injective`` additionally requires the concrete message contents to be
    identical; otherwise keys are erased before comparison.
    """
    left = concrete_messages(run, sigma)
    right = concrete_messages(other, sigma)
    if len(left) != len(right):
        return False
    for a, b in zip(left, right, strict=True):
        if a.label != b.label or a.sending == b.sending:
            return False
        if injective:
            if a.term != b.term:
                return False
        elif data_view(a.term) != data_view(b.term):
            return False
    return True


def no_partner_sentence(claimant: Run, partner_role: str) -> str:
    """Explain that the claimant finished while its partner never ran."""
    return (
        f"{claimant.agent} completed the protocol believing its {partner_role} was "
        f"{claimant.peer}, but that {partner_role} never ran that session."
    )


def _mismatch_sentence(claimant: Run, runs: dict[int, Run], partner_role: str,
                       claim: ClaimEvent) -> str:
    """Explain why the agreement claims fail on this trace."""
    candidates = [r for r in runs.values() if r is not claimant and r.role.name == partner_role]
    if not candidates:
        return no_partner_sentence(claimant, partner_role)
    seen = ", ".join(sorted(f"{r.agent} talking to {r.peer}" for r in candidates))
    return (
        f"{claimant.agent} believes its {partner_role} partner is {claimant.peer}, "
        f"but the {partner_role} run(s) of this trace are {seen}; "
        f"claim {claim.label} ({claim.kind}) does not hold."
    )
