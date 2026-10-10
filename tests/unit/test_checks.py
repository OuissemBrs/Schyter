"""Static-check tests."""

from __future__ import annotations

import pytest

from conftest import SRC  # noqa: F401  (path bootstrap)
from protoverify.parser import check, check_or_raise, parse
from protoverify.parser.errors import ProtoVerifyError

HEAD = "const c: Key;\n"
PAIR = "send_1(A,B,c);recv_1(A,B,c);"


def errors(body: str) -> list[str]:
    return [e.error for e in check(parse(HEAD + body))]


def test_valid_protocol_has_no_errors() -> None:
    assert errors(f"protocol p(A,B){{role A{{{PAIR}}}}}") == []


def test_variable_used_before_declaration() -> None:
    msgs = errors("protocol p(A,B){role A{send_1(A,B,x);var x: Nonce;recv_1(A,B,c);}}")
    assert any("before it is declared" in m for m in msgs)


def test_fresh_must_be_unique_across_roles() -> None:
    msgs = errors(
        "protocol p(A,B){role A{fresh n: Nonce;send_1(A,B,c);recv_1(A,B,c);}"
        "role B{fresh n: Nonce;send_2(B,A,c);recv_2(B,A,c);}}"
    )
    assert any("fresh names must be unique across roles" in m for m in msgs)


def test_claim_must_reference_a_defined_role() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{{PAIR}claim_q(Z,Alive);}}}}")
    assert any("undefined role 'Z'" in m for m in msgs)


def test_claim_partner_must_exist() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{{PAIR}claim_q(A,Niagree,Z);}}}}")
    assert any("undefined partner role 'Z'" in m for m in msgs)


def test_labels_must_pair_one_send_and_one_recv() -> None:
    msgs = errors("protocol p(A,B){role A{send_1(A,B,c);send_2(A,B,c);}"
                  "role B{recv_2(B,A,c);recv_3(B,A,c);}}")
    assert any("message label 1 is received 0 time(s)" in m for m in msgs)
    assert any("message label 3 is sent 0 time(s)" in m for m in msgs)


def test_undeclared_type_is_rejected() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{fresh n: Weird;{PAIR}}}}}")
    assert any("undeclared type 'Weird'" in m for m in msgs)


def test_role_must_appear_in_parameter_list() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{{PAIR}}}role C{{send_2(C,A,c);recv_2(C,A,c);}}}}")
    assert any("must also appear in the protocol parameter list" in m for m in msgs)


def test_duplicate_role_rejected() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{{PAIR}}}role A{{send_2(A,B,c);recv_2(A,B,c);}}}}")
    assert any("declared more than once" in m for m in msgs)


def test_claim_must_be_inside_its_own_role() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{{PAIR}claim_q(B,Alive);}}}}")
    assert any("but names role 'B' as its claimant" in m for m in msgs)


def test_secret_claim_needs_a_term() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{{PAIR}claim_q(A,Secret);}}}}")
    assert any("needs a term argument" in m for m in msgs)


def test_secret_claim_argument_must_be_declared() -> None:
    msgs = errors(f"protocol p(A,B){{role A{{{PAIR}claim_q(A,Secret,q);}}}}")
    assert any("undefined identifier 'q'" in m for m in msgs)


def test_partner_defaults_for_two_role_protocols() -> None:
    msgs = errors(
        f"protocol p(A,B){{role A{{{PAIR}claim_q(A,Niagree);}}role B{{send_2(B,A,c);recv_2(B,A,c);}}}}"
    )
    assert msgs == []


def test_three_role_protocol_needs_explicit_partner() -> None:
    msgs = errors(
        "protocol p(A,B,C){role A{send_1(A,B,c);recv_1(A,B,c);claim_q(A,Niagree);}"
        "role B{send_2(B,A,c);recv_2(B,A,c);}role C{send_3(C,A,c);recv_3(C,A,c);}}"
    )
    assert any("needs an explicit partner" in m for m in msgs)


def test_role_without_messages_rejected() -> None:
    msgs = errors("protocol p(A,B){role A{send_1(A,B,c);recv_1(A,B,c);}role B{fresh n: Nonce;}}")
    assert any("contains no message event" in m for m in msgs)


def test_check_or_raise_reports_all_errors() -> None:
    proto = parse(HEAD + "protocol p(A,B){role A{send_1(A,B,z);recv_1(A,B,c);}}")
    with pytest.raises(ProtoVerifyError) as exc:
        check_or_raise(proto)
    assert "static check failed" in str(exc.value)
