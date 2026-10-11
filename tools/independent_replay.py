"""Independent replay of a trace, using only terms.py, unify.py and attacker.py.

This script deliberately does **not** import ``core.replay``, ``core.search`` or
``core.claims``.  It re-derives the semantics of a trace from scratch:

* roles come from ``parser`` (grammar only, no semantics),
* every run's message templates are re-scoped by hand with ``Term.substitute`` and
  ``Term.map_atoms``,
* variable bindings are recovered by ``unify.solve`` between the template and the
  concrete message recorded in the trace,
* the attacker's knowledge is recomputed with ``attacker.Attacker.analyze`` and
  ``attacker.Attacker.can_synthesize`` alone.

Any step that cannot be justified this way is reported with the reason.

Usage::

    python tools/independent_replay.py out/golden/ns_R1.json examples/ns.spdl
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from dataclasses import dataclass, field

sys.path.insert(0, "src")

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
)
from protoverify.core.unify import solve
from protoverify.parser.ast import Protocol, RecvEvent, Role, SendEvent
from protoverify.parser.parser import parse_file

ATTACKER_DEFAULT = "M"


@dataclass(slots=True)
class Run:
    """A run rebuilt from the trace, with the semantics re-implemented."""

    id: int
    role: Role
    agent: str
    peer: str
    params: tuple[str, ...]
    sigma: dict[str, Term] = field(default_factory=dict)

    def scope(self, name: str) -> str:
        return f"r{self.id}::{name}"

    def agent_env(self) -> dict[str, str]:
        return {p: (self.agent if p == self.role.name else self.peer) for p in self.params}

    def fresh_terms(self) -> list[Term]:
        """The unique atoms this run creates, as declared by its ``fresh`` events."""
        from protoverify.parser.ast import FreshEvent

        return [
            Atom(f"{e.name}#{self.id}")
            for e in self.role.events
            if isinstance(e, FreshEvent)
        ]

    def template(self, event: SendEvent | RecvEvent, sigma: dict[str, Term]) -> Term:
        """Scope ``event.msg`` to this run and apply the fresh + learned bindings."""
        scoped = event.msg.substitute(
            {n: Var(self.scope(n), "Any") for n in event.msg.vars()}
        )
        return scoped.substitute({**self.sigma, **sigma}).map_atoms(
            lambda n: self.agent_env().get(n, n)
        )


class Failure(Exception):
    """Raised as soon as a step cannot be justified."""


def load(trace_path: pathlib.Path) -> dict:
    return json.loads(trace_path.read_text(encoding="utf-8"))


def rebuild_runs(trace: dict, protocol: Protocol) -> dict[int, Run]:
    runs = {
        info["id"]: Run(
            id=info["id"],
            role=protocol.role(info["role"]),
            agent=info["agent"],
            peer=info["peer"],
            params=protocol.params,
        )
        for info in trace["runs"]
    }
    for run in runs.values():
        from protoverify.parser.ast import FreshEvent

        run.sigma = {
            run.scope(event.name): Atom(f"{event.name}#{run.id}")
            for event in run.role.events
            if isinstance(event, FreshEvent)
        }
    return runs


def derive_bindings(runs: dict[int, Run], trace: dict) -> dict[int, dict[str, Term]]:
    """Recover each run's variable bindings by unifying templates with the trace."""
    bindings: dict[int, dict[str, Term]] = {r.id: dict(r.sigma) for r in runs.values()}
    for step in trace["steps"]:
        if step["type"] in ("send", "recv") and step["run"] is not None:
            run = runs[step["run"]]
            event = _message_event(run, step["label"])
            concrete = _reparse(step["msg"])
            unified = solve(run.template(event, bindings[run.id]), concrete)
            if unified is None:
                raise Failure(
                    f"step {step['i']}: run {run.id} cannot produce {step['msg']}"
                )
            bindings[run.id] = {**bindings[run.id], **unified}
        elif step["type"].startswith("attacker"):
            # The attacker supplied this message: unify it with the receiving run's
            # receive template to learn what variables it must have bound.
            for run in runs.values():
                if run.agent != step["to"]:
                    continue
                event = _message_event(run, step["label"])
                if not isinstance(event, RecvEvent):
                    continue
                concrete = _reparse(step["msg"])
                unified = solve(run.template(event, bindings[run.id]), concrete)
                if unified is not None:
                    bindings[run.id] = {**bindings[run.id], **unified}
        else:  # pragma: no cover - the schema rejects other types
            raise Failure(f"step {step['i']}: unknown type {step['type']}")
    return bindings


def _message_event(run: Run, label: str) -> SendEvent | RecvEvent:
    for event in run.role.events:
        if isinstance(event, (SendEvent, RecvEvent)) and str(event.label) == str(label):
            return event
    raise Failure(f"run {run.id} has no message labelled {label}")


def _reparse(text: str) -> Term:
    """Rebuild a Term from its rendered form with a tiny hand-written parser.

    Using our own parser here (instead of ``protoverify.parser``) keeps the check
    honest: the rendered trace text is re-read independently of the code that
    produced it.
    """
    tokens = re.findall(r"\{|\}|\(|\)|,|[A-Za-z0-9_.#@-]+", text)
    pos = 0

    def peek() -> str:
        return tokens[pos] if pos < len(tokens) else ""

    def take() -> str:
        nonlocal pos
        token = peek()
        pos += 1
        return token

    def expect(value: str) -> None:
        got = take()
        if got != value:
            raise Failure(f"expected {value!r} in {text!r}, found {got!r}")

    def comma_list() -> list[Term]:
        items = [unary()]
        while peek() == ",":
            take()
            items.append(unary())
        return items

    def operands() -> tuple[str, list[Term]]:
        """Read ``ident`` plus its optional ``( ... )`` argument list."""
        ident = take()
        if peek() == "(":
            take()
            args = comma_list()
            expect(")")
            return ident, args
        return ident, []

    def unary() -> Term:
        token = take()
        if token == "{":
            parts = comma_list()
            expect("}")
            payload = parts[0] if len(parts) == 1 else Tuple(tuple(parts))
            return _apply(*operands(), payload=payload)
        if token == "(":
            inner = comma_list()
            expect(")")
            return inner[0] if len(inner) == 1 else Tuple(tuple(inner))
        if peek() == "(":
            ident = token
            take()
            args = comma_list()
            expect(")")
            return _apply(ident, args, payload=None)
        return Atom(token)

    def _apply(ident: str, args: list[Term], payload: Term | None) -> Term:
        """Build the term denoted by ``ident`` applied to ``args``/``payload``."""
        if ident == "pk":
            return Pk(args[0]) if payload is None else AsymEnc(payload, Pk(args[0]))
        if ident == "sk":
            return Sk(args[0]) if payload is None else Sign(payload, Sk(args[0]))
        if ident == "k":
            # ``{m}k(kk)`` carries a bare key atom, ``{m}k(k(A,B))`` a shared key.
            key = args[0] if len(args) == 1 else SharedKey(args[0], args[1])
            return key if payload is None else SymEnc(payload, key)
        if ident == "h":
            return Hash(args[0] if payload is None else payload, "h")
        if payload is None:
            raise Failure(f"{ident!r} is not a term constructor")
        return SymEnc(payload, Atom(ident))

    result = comma_list()
    if pos != len(tokens):
        raise Failure(f"trailing input in {text!r}")
    return result[0] if len(result) == 1 else Tuple(tuple(result))


def check(trace_path: pathlib.Path, protocol_path: pathlib.Path) -> list[str]:
    """Replay the trace and return the report lines (empty list means failure)."""
    trace = load(trace_path)
    protocol = parse_file(str(protocol_path))
    runs = rebuild_runs(trace, protocol)
    attacker_name = next(
        (a["id"] for a in trace["agents"] if a["kind"] == "attacker"), ATTACKER_DEFAULT
    )
    bindings = derive_bindings(runs, trace)
    adversary = Attacker(
        agents=[a["id"] for a in trace["agents"]],
        compromised=[attacker_name],
        constants=[Atom(c) for c in protocol.constants],
    )
    knowledge = set(adversary.initial())
    seen: list[tuple[str, str]] = []
    report = [f"trace {trace_path.name}: {trace['protocol']}/{trace['claim']}"]
    for step in trace["steps"]:
        term = _reparse(step["msg"])
        closure, _ = adversary.analyze(knowledge | {term})
        new = sorted({t.text() for t in closure - frozenset(knowledge)
                      if isinstance(t, (Atom, SharedKey))})
        if list(step["attacker_new"]) != new:
            raise Failure(
                f"step {step['i']}: recorded attacker_new={step['attacker_new']} "
                f"but analyze() derives {new}"
            )
        _check_sound(step, new, knowledge, adversary)
        _verify_step(step, term, runs, bindings, knowledge, adversary, attacker_name)
        seen.append((step["from"], step["msg"]))
        knowledge = set(closure)
        report.append(
            f"  step {step['i']:>2} {step['type']:<17} {step['from']}->{step['to']} "
            f"{step['msg']}  learned={new}"
        )
    report.append(
        f"  verdict: attacker can build ni#2 = "
        f"{adversary.can_synthesize(Atom('ni#2'), frozenset(knowledge))}"
    )
    return report


def _check_sound(step: dict, learned: list[str], knowledge: set[Term], adversary: Attacker) -> None:
    """A step may only report learning things the attacker did not already know."""
    for text in learned:
        term = _reparse(text)
        if adversary.can_synthesize(term, frozenset(knowledge)):
            raise Failure(
                f"step {step['i']}: {text} is reported as newly learned but the "
                f"attacker already knew it before this step"
            )


def _verify_step(
    step: dict,
    term: Term,
    runs: dict[int, Run],
    bindings: dict[int, dict[str, Term]],
    knowledge: set[Term],
    adversary: Attacker,
    attacker_name: str,
) -> None:
    """Justify one step or raise :class:`Failure`."""
    if step["type"] == "send":
        run = runs[step["run"]]
        event = _message_event(run, step["label"])
        if not isinstance(event, SendEvent):
            raise Failure(f"step {step['i']}: run {run.id} has no send labelled {step['label']}")
        expected = run.template(event, bindings[run.id])
        if expected != term:
            raise Failure(f"step {step['i']}: run {run.id} should send {expected.text()}")
        if step["from"] != run.agent or step["to"] != run.peer:
            raise Failure(f"step {step['i']}: endpoints do not match run {run.id}")
        return
    if step["type"] == "recv":
        run = runs[step["run"]]
        event = _message_event(run, step["label"])
        if not isinstance(event, RecvEvent):
            raise Failure(f"step {step['i']}: run {run.id} has no recv labelled {step['label']}")
        expected = run.template(event, bindings[run.id])
        if expected != term:
            raise Failure(f"step {step['i']}: run {run.id} should accept {expected.text()}")
        if step["to"] != run.agent:
            raise Failure(f"step {step['i']}: a recv must deliver to the run's own agent")
        return
    if not step["type"].startswith("attacker"):
        raise Failure(f"step {step['i']}: unknown type {step['type']}")
    if step["from"] != attacker_name or step["run"] is not None:
        raise Failure(f"step {step['i']}: attacker steps come from {attacker_name}")
    if not adversary.can_synthesize(term, frozenset(knowledge)):
        raise Failure(
            f"step {step['i']}: attacker cannot build {step['msg']} from its knowledge"
        )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    try:
        for line in check(pathlib.Path(argv[0]), pathlib.Path(argv[1])):
            print(line)
    except Failure as exc:
        print(f"FAIL {argv[0]}: {exc}")
        return 1
    print("OK: every step is justified by terms/unify/attacker alone")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
