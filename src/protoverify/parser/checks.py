"""Static checks run before any search takes place.

The checks reject programs whose meaning the engine could otherwise silently
misinterpret:

* variables must be declared before they are used inside a role;
* a ``fresh`` name may not be declared by two different roles;
* every claim must reference a declared role, and its partner defaults to the
  unique other role of a two-role protocol;
* every message label must be paired: exactly one ``send_N`` and one ``recv_N``;
* every type name must be declared (built-in or via ``usertype``);
* role names must come from the protocol parameter list, so that the per-run
  agent environment is well defined.
"""

from __future__ import annotations

from collections import Counter

from ..core.terms import Term, Var
from .ast import CLAIM_KINDS, ClaimEvent, FreshEvent, Protocol, RecvEvent, Role, SendEvent, VarEvent
from .errors import Pos, ProtoVerifyError, StaticCheckError

__all__ = ["StaticCheckError", "check", "check_or_raise", "resolve_partner"]


def check(protocol: Protocol) -> list[StaticCheckError]:
    """Return every static problem found in ``protocol`` (empty when valid)."""
    errors: list[StaticCheckError] = []
    _check_header(protocol, errors)
    _check_labels(protocol, errors)
    _check_fresh_uniqueness(protocol, errors)
    for role in protocol.roles:
        _check_role(protocol, role, errors)
    return errors


def check_or_raise(protocol: Protocol) -> None:
    """Raise :class:`ProtoVerifyError` when ``protocol`` fails a static check."""
    errors = check(protocol)
    if errors:
        detail = "\n  ".join(e.error for e in errors)
        raise ProtoVerifyError(f"static check failed:\n  {detail}")


def resolve_partner(protocol: Protocol, ev: ClaimEvent) -> str | None:
    """Return the partner role of ``ev``, defaulting to the unique other role."""
    if ev.partner is not None:
        return ev.partner
    others = [r.name for r in protocol.roles if r.name != ev.claimant]
    return others[0] if len(others) == 1 else None


def _err(errors: list[StaticCheckError], pos: Pos, message: str) -> None:
    errors.append(StaticCheckError(f"{pos}: {message}"))


def _check_header(protocol: Protocol, errors: list[StaticCheckError]) -> None:
    if not protocol.params:
        _err(errors, protocol.pos, f"protocol {protocol.name!r} declares no role parameters")
    counts = Counter(r.name for r in protocol.roles)
    for role in protocol.roles:
        if counts[role.name] > 1:
            _err(errors, role.pos, f"role {role.name!r} is declared more than once")
        if role.name not in protocol.params:
            _err(
                errors,
                role.pos,
                f"role {role.name!r} must also appear in the protocol parameter list "
                f"({', '.join(protocol.params) or 'none'})",
            )
        if not role.messages:
            _err(errors, role.pos, f"role {role.name!r} contains no message event")


def _check_labels(protocol: Protocol, errors: list[StaticCheckError]) -> None:
    sends: Counter[int] = Counter()
    recvs: Counter[int] = Counter()
    for role in protocol.roles:
        for ev in role.events:
            if isinstance(ev, SendEvent):
                sends[ev.label] += 1
            elif isinstance(ev, RecvEvent):
                recvs[ev.label] += 1
    for label in sorted(set(sends) | set(recvs)):
        if sends[label] != 1:
            _err(errors, protocol.pos, f"message label {label} is sent {sends[label]} time(s), expected 1")
        if recvs[label] != 1:
            _err(
                errors,
                protocol.pos,
                f"message label {label} is received {recvs[label]} time(s), expected 1",
            )


def _check_fresh_uniqueness(protocol: Protocol, errors: list[StaticCheckError]) -> None:
    owners: dict[str, str] = {}
    for role in protocol.roles:
        for ev in role.events:
            if not isinstance(ev, FreshEvent):
                continue
            if ev.name in owners:
                _err(
                    errors,
                    ev.pos,
                    f"fresh value {ev.name!r} is declared by both role {owners[ev.name]!r} and "
                    f"role {role.name!r}; fresh names must be unique across roles",
                )
            else:
                owners[ev.name] = role.name


def _check_role(protocol: Protocol, role: Role, errors: list[StaticCheckError]) -> None:
    declared: set[str] = set()
    later: set[str] = {e.name for e in role.events if isinstance(e, (FreshEvent, VarEvent))}
    for ev in role.events:
        if isinstance(ev, (FreshEvent, VarEvent)):
            if not protocol.type_env.knows(ev.type_name):
                _err(errors, ev.pos, f"undeclared type {ev.type_name!r}")
            declared.add(ev.name)
            later.discard(ev.name)
        elif isinstance(ev, (SendEvent, RecvEvent)):
            _check_message_terms(role, declared, later, ev, errors)
        elif isinstance(ev, ClaimEvent):
            _check_claim(protocol, role, declared, later, ev, errors)


def _check_message_terms(
    role: Role,
    declared: set[str],
    later: set[str],
    ev: SendEvent | RecvEvent,
    errors: list[StaticCheckError],
) -> None:
    _check_term(role, declared, later, ev.msg, ev.pos, errors)
    for side in (ev.src, ev.dst):
        _check_term(role, declared, later, side, ev.pos, errors)


def _check_claim(
    protocol: Protocol,
    role: Role,
    declared: set[str],
    later: set[str],
    ev: ClaimEvent,
    errors: list[StaticCheckError],
) -> None:
    if ev.kind not in CLAIM_KINDS:  # pragma: no cover - the parser rejects these first
        _err(errors, ev.pos, f"unknown claim kind {ev.kind!r}")
        return
    if ev.claimant != role.name:
        _err(
            errors,
            ev.pos,
            f"claim {ev.label!r} is declared inside role {role.name!r} but names role "
            f"{ev.claimant!r} as its claimant",
        )
    if not protocol.has_role(ev.claimant):
        _err(errors, ev.pos, f"claim {ev.label!r} references undefined role {ev.claimant!r}")
    partner = resolve_partner(protocol, ev)
    if ev.kind == "Secret":
        if ev.argument is None:
            _err(errors, ev.pos, f"claim {ev.label!r} (Secret) needs a term argument")
        else:
            _check_term(role, declared, later, ev.argument, ev.pos, errors)
        return
    if ev.kind != "Alive" and partner is None:
        _err(
            errors,
            ev.pos,
            f"claim {ev.label!r} ({ev.kind}) needs an explicit partner: the protocol has "
            f"{len(protocol.roles)} roles",
        )
    if partner is not None and partner == role.name:
        _err(errors, ev.pos, f"claim {ev.label!r} names its own role as partner")
    if partner is not None and not protocol.has_role(partner):
        _err(errors, ev.pos, f"claim {ev.label!r} references undefined partner role {partner!r}")


def _check_term(
    role: Role,
    declared: set[str],
    later: set[str],
    t: Term,
    pos: Pos,
    errors: list[StaticCheckError],
) -> None:
    """Reject variables that are used before (or without) their declaration."""
    for var in sorted(_vars(t), key=lambda v: v.name):
        if var.name in declared:
            continue
        if var.name in later:
            _err(
                errors,
                pos,
                f"variable {var.name!r} is used in role {role.name!r} before it is declared",
            )
        else:
            _err(
                errors,
                pos,
                f"undefined identifier {var.name!r} in role {role.name!r}: "
                f"declare it with 'var {var.name}: <Type>;'",
            )


def _vars(t: Term) -> tuple[Var, ...]:
    return tuple(x for x in t.subterms() if isinstance(x, Var))
