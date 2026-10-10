"""Parser and static-check tests."""

from __future__ import annotations

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.core.terms import (
    AsymEnc,
    Atom,
    Hash,
    Pk,
    SharedKey,
    Sign,
    Sk,
    SymEnc,
    Tuple,
    Var,
)
from protoverify.parser import check, parse, parse_file
from protoverify.parser.ast import (
    CLAIM_KINDS,
    ClaimEvent,
    RecvEvent,
    SendEvent,
    VarEvent,
)
from protoverify.parser.errors import SPDLError

MINIMAL = """
usertype Ticket;
hashfunction h;
const c: Ticket;
protocol p(A,B) {
  role A {
    fresh na: Nonce;  var nb: Nonce;
    send_1(A,B, {A,na}pk(B));
    recv_2(B,A, na);
    claim_x(A,Secret,na);
    claim_y(A,Nisynch,B);
  }
  role B {
    var na: Nonce;  fresh nb: Nonce;
    recv_1(A,B, {A,na}pk(B));
    send_2(B,A, na);
    claim_z(B,Alive);
  }
}
"""


def test_parses_reference_protocol() -> None:
    proto = parse_file(str(example_path("ns")))
    assert proto.name == "ns"
    assert proto.params == ("I", "R")
    assert [r.name for r in proto.roles] == ["I", "R"]
    assert check(proto) == []


def test_declarations() -> None:
    proto = parse(MINIMAL)
    assert proto.user_types == frozenset({"Ticket"})
    assert proto.hash_functions == ("h",)
    assert proto.constants == ("c",)
    assert proto.type_env.knows("Ticket")


def test_secret_declaration_with_and_without_type() -> None:
    proto = parse(
        "secret s;\nsecret t: Key;\nprotocol p(A){role A{send_1(A,A,s);recv_1(A,A,t);}}"
    )
    assert proto.secrets == ("s", "t")


def test_events_are_parsed_in_order() -> None:
    role = parse(MINIMAL).role("A")
    kinds = [type(e).__name__ for e in role.events]
    assert kinds == ["FreshEvent", "VarEvent", "SendEvent", "RecvEvent", "ClaimEvent", "ClaimEvent"]


def test_send_and_recv_terms() -> None:
    role = parse(MINIMAL).role("A")
    send = role.events[2]
    assert isinstance(send, SendEvent)
    assert send.label == 1
    assert send.src == Atom("A")
    assert send.dst == Atom("B")
    assert send.msg == AsymEnc(Tuple((Atom("A"), Var("na", "Nonce"))), Pk(Atom("B")))


def test_variable_resolution_uses_declared_type() -> None:
    role = parse(MINIMAL).role("A")
    recv = role.events[3]
    assert isinstance(recv, RecvEvent)
    assert recv.msg == Var("na", "Nonce")


@pytest.mark.parametrize(
    "source",
    [
        "const c: Ticket",
        "const c Ticket;",
        "protocol p(A){role A{send_1(A,A,c)}}",
        "protocol p(A){role A{send_1(A,A,c);recv_1(A,A,c);claim_x(A,Secret);}role A{}",
    ],
)
def test_parse_errors_point_at_the_problem(source: str) -> None:
    with pytest.raises(SPDLError):
        parse(source)


def test_missing_comma_error_message() -> None:
    with pytest.raises(SPDLError) as exc:
        parse("const c: Key;\nprotocol p(A,B){role A{send_1(A,B c);recv_1(A,B,c);}}")
    assert "expected ',' after the receiver in a message event" in str(exc.value)
    assert "found identifier 'c'" in str(exc.value)


def test_missing_closing_paren_error_message() -> None:
    with pytest.raises(SPDLError) as exc:
        parse("const c: Key;\nprotocol p(A,B){role A{send_1(A,B,c;recv_1(A,B,c);}}")
    assert "expected ')' after term in message 1" in str(exc.value)
    assert "line 2" in str(exc.value)


def test_unexpected_character_error_message() -> None:
    with pytest.raises(SPDLError) as exc:
        parse("protocol p(A,B){role A{ ? }}")
    assert "unexpected character '?'" in str(exc.value)


def test_unknown_claim_kind() -> None:
    with pytest.raises(SPDLError) as exc:
        parse("protocol p(A,B){role A{send_1(A,B,c);recv_1(A,B,c);claim_q(A,Nope);}}")
    assert "unknown claim kind 'Nope'" in str(exc.value)
    assert "Secret, Alive, Weakagree, Niagree, Nisynch" in str(exc.value)


def test_undefined_identifier_is_reported_by_the_static_checker() -> None:
    from protoverify.parser import check

    proto = parse("protocol p(A,B){role A{send_1(A,B,zzz);recv_1(A,B,c);}}")
    assert any("undefined identifier 'zzz'" in e.error for e in check(proto))


def test_duplicate_const() -> None:
    with pytest.raises(SPDLError) as exc:
        parse("const c: Ticket;\nconst c: Ticket;\nprotocol p(A){role A{send_1(A,A,c);recv_1(A,A,c);}}")
    assert "duplicate declaration of 'c'" in str(exc.value)


def test_duplicate_variable_in_role() -> None:
    with pytest.raises(SPDLError) as exc:
        parse("protocol p(A){role A{var x: Nonce;var x: Nonce;send_1(A,A,c);recv_1(A,A,c);}}")
    assert "declared twice in this role" in str(exc.value)


@pytest.mark.parametrize(
    "term,expected",
    [
        ("c", Atom("c")),
        ("k(A,B)", SharedKey(Atom("A"), Atom("B"))),
        ("pk(A)", Pk(Atom("A"))),
        ("h(A)", Hash(Atom("A"), "h")),
        ("{A}c", SymEnc(Atom("A"), Atom("c"))),
        ("{A}pk(B)", AsymEnc(Atom("A"), Pk(Atom("B")))),
        ("{A}sk(B)", Sign(Atom("A"), Sk(Atom("B")))),
        ("{A}h(B)", Hash(Atom("A"), "h")),
    ],
)
def test_term_constructors(term: str, expected: object) -> None:
    proto = parse(f"const c: Key;\nprotocol p(A,B){{role A{{send_1(A,B,{term});recv_1(A,B,c);}}}}")
    send = proto.role("A").events[0]
    assert isinstance(send, SendEvent)
    assert send.msg == expected


def test_sk_application() -> None:
    proto = parse("const c: Key;\nprotocol p(A,B){role A{send_1(A,B,sk(A));recv_1(A,B,c);}}")
    send = proto.role("A").events[0]
    assert isinstance(send, SendEvent)
    assert send.msg == Sk(Atom("A"))


def test_nested_term() -> None:
    proto = parse(
        "const c: Key;\nprotocol p(A,B){role A{send_1(A,B,({A,c}k(A,B),h({c}pk(B))));recv_1(A,B,c);}}"
    )
    send = proto.role("A").events[0]
    assert isinstance(send, SendEvent)
    assert send.msg == Tuple(
        (
            SymEnc(Tuple((Atom("A"), Atom("c"))), SharedKey(Atom("A"), Atom("B"))),
            Hash(AsymEnc(Atom("c"), Pk(Atom("B"))), "h"),
        )
    )


def test_tuple_and_nested_rendering() -> None:
    assert Tuple((Atom("a"), Atom("b"))).text() == "(a,b)"
    assert Tuple((Atom("a"), Atom("b"))).text(True) == "a,b"
    assert SymEnc(Tuple((Atom("a"), Atom("b"))), Atom("k")).text() == "{a,b}k(k)"


def test_claim_kinds_are_the_documented_five() -> None:
    assert CLAIM_KINDS == ("Secret", "Alive", "Weakagree", "Niagree", "Nisynch")


def test_all_claims_collected() -> None:
    proto = parse(MINIMAL)
    assert [c.label for _, c in proto.all_claims()] == ["x", "y", "z"]


def test_claim_event_fields() -> None:
    proto = parse(MINIMAL)
    y = next(c for _, c in proto.all_claims() if c.label == "y")
    assert isinstance(y, ClaimEvent)
    assert (y.claimant, y.kind, y.partner) == ("A", "Nisynch", "B")
    z = next(c for _, c in proto.all_claims() if c.label == "z")
    assert (z.kind, z.argument, z.partner) == ("Alive", None, None)


def test_var_event() -> None:
    proto = parse(MINIMAL)
    assert proto.role("A").events[1] == VarEvent("nb", "Nonce", proto.role("A").events[1].pos)
