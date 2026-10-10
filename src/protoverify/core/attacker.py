"""The Dolev-Yao attacker: knowledge closure (``analyze``) and term synthesis.

The two directions are kept strictly apart, as the specification requires:

``analyze(K)``
    the smallest set ``K'`` with ``K`` contained in ``K'`` that is closed under
    the *decomposition* rules (tuple projection, symmetric and asymmetric
    decryption, signature and hash inversion, public-key projection and
    shared-key derivation).  Signatures are not confidential, so signing never
    hides a message from the attacker.

``can_synthesize(t, K)``
    a recursive, memoised check that ``t`` can be *built* from the closed set
    ``K`` using the composition rules.  It is always called on an
    ``analyze``-closed set.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .terms import (
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
)

__all__ = ["Attacker", "Derivation", "Knowledge", "KnowledgeStep"]

#: A Dolev-Yao knowledge set.
Knowledge = frozenset[Term]


@dataclass(frozen=True, slots=True)
class Derivation:
    """One decomposition step recorded by :meth:`Attacker.analyze`."""

    derived: Term
    rule: str
    source: Term

    def describe(self) -> str:
        """Return a one-line English rendering of the inference."""
        return f"{self.derived.text()} <- {self.rule}({self.source.text()})"


@dataclass(frozen=True, slots=True)
class KnowledgeStep:
    """The knowledge gained when one message entered the attacker's view."""

    step: int
    newly_known: tuple[Term, ...]
    derivations: tuple[Derivation, ...]


@dataclass(slots=True)
class _KnowledgeLog:
    """Ordered record of everything the attacker learned."""

    steps: list[KnowledgeStep] = field(default_factory=list)

    def record(self, step: int, newly: list[Term], derivations: list[Derivation]) -> None:
        self.steps.append(KnowledgeStep(step, tuple(newly), tuple(derivations)))


class Attacker:
    """A Dolev-Yao adversary with an initial public knowledge base."""

    def __init__(
        self,
        agents: Iterable[str],
        compromised: Iterable[str] = (),
        constants: Iterable[Term] = (),
    ) -> None:
        self.agents: tuple[str, ...] = tuple(dict.fromkeys(agents))
        self.compromised: frozenset[str] = frozenset(compromised)
        self.constants: tuple[Term, ...] = tuple(dict.fromkeys(constants))
        self.log = _KnowledgeLog()
        self._memo: dict[tuple[Term, frozenset[Term]], bool] = {}

    # -- initial knowledge ------------------------------------------------
    def initial(self) -> Knowledge:
        """Return the attacker's initial knowledge ``K0``."""
        known: set[Term] = set(self.constants)
        for agent in self.agents:
            known.add(Atom(agent))
            known.add(Pk(Atom(agent)))
        for agent in sorted(self.compromised):
            known.add(Sk(Atom(agent)))
            known.add(Atom(agent))
        for a in self.agents:
            for b in self.agents:
                if a in self.compromised or b in self.compromised:
                    known.add(SharedKey(Atom(a), Atom(b)))
        return frozenset(known)

    def is_honest(self, agent: str) -> bool:
        """True when ``agent`` is not under attacker control."""
        return agent not in self.compromised

    # -- decomposition ----------------------------------------------------
    def analyze(
        self,
        known: Iterable[Term],
        *,
        step: int | None = None,
        log: bool = False,
    ) -> tuple[Knowledge, tuple[Term, ...]]:
        """Return ``(closure, newly_derived)`` for the knowledge set ``known``.

        ``newly_derived`` lists the terms that were *not* in ``known`` but are
        in the closure, in derivation order.  When ``log`` is true the same
        information is appended to :attr:`log` under step number ``step``.
        """
        start: set[Term] = set(known)
        closure: set[Term] = set(start)
        newly: list[Term] = []
        derivations: list[Derivation] = []
        pending = list(start)
        while pending:
            term = pending.pop()
            for derived, rule, source in self._decompose(term, closure):
                if derived not in closure:
                    closure.add(derived)
                    newly.append(derived)
                    derivations.append(Derivation(derived, rule, source))
                    pending.append(derived)
        if log and (newly or derivations):
            self.log.record(step if step is not None else 0, newly, derivations)
        return frozenset(closure), tuple(newly)

    def _decompose(self, term: Term, closure: set[Term]) -> list[tuple[Term, str, Term]]:
        """Apply every decomposition rule that fires on ``term``."""
        if isinstance(term, Tuple):
            return [(item, "project", term) for item in term.items]
        if isinstance(term, SymEnc):
            return [(term.msg, "decrypt", term)] if term.key in closure else []
        if isinstance(term, AsymEnc):
            key = term.key
            if isinstance(key, Pk) and isinstance(key.agent, Atom):
                return [(term.msg, "decrypt", term)] if Sk(key.agent) in closure else []
            return []
        if isinstance(term, Sign):
            return [(term.msg, "unsign", term)]
        if isinstance(term, Hash):
            return [(term.term, "unhash", term)]
        if isinstance(term, Pk):
            return [(term.agent, "pk", term)]
        if isinstance(term, SharedKey):
            left, right = term.left, term.right
            if isinstance(left, Atom) and isinstance(right, Atom) and (
                left in closure or right in closure
            ):
                return [(term, "shared-key", term)]
        return []

    # -- composition ------------------------------------------------------
    def can_synthesize(self, term: Term, known: Knowledge) -> bool:
        """True when ``term`` can be built from the ``analyze``-closed set ``known``."""
        memo: dict[Term, bool] = {}
        return self._synthesize(term, known, memo)

    def _synthesize(self, term: Term, known: Knowledge, memo: dict[Term, bool]) -> bool:
        cached = memo.get(term)
        if cached is not None:
            return cached
        result = self._synthesize_uncached(term, known, memo)
        memo[term] = result
        return result

    def _synthesize_uncached(self, term: Term, known: Knowledge, memo: dict[Term, bool]) -> bool:
        if term in known:
            return True
        if isinstance(term, (Atom, Var)):
            return False
        if isinstance(term, (Sk, Pk, SharedKey)):
            # Keys are atomic: the attacker either holds them or cannot build them.
            return False
        if isinstance(term, Tuple):
            return all(self._synthesize(item, known, memo) for item in term.items)
        if isinstance(term, (SymEnc, AsymEnc, Sign)):
            key = term.key
            if isinstance(term, AsymEnc) and not isinstance(key, Pk):
                return False
            return self._synthesize(term.msg, known, memo) and key in known
        if isinstance(term, Hash):
            return self._synthesize(term.term, known, memo)
        return False  # pragma: no cover


def closure_of(attacker: Attacker, known: Iterable[Term]) -> Knowledge:
    """Return the decomposition closure of ``known`` under ``attacker``."""
    closure, _ = attacker.analyze(known)
    return closure
