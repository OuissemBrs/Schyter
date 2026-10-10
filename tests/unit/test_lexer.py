"""Lexer tests: token kinds, source positions, comments and bad characters."""

from __future__ import annotations

import pytest

from conftest import SRC  # noqa: F401  (path bootstrap)
from protoverify.parser.errors import SPDLError
from protoverify.parser.lexer import Kind, tokenize


def test_positions_are_one_based() -> None:
    toks = tokenize("protocol ns")
    assert [(t.text, t.pos.line, t.pos.col) for t in toks[:2]] == [
        ("protocol", 1, 1),
        ("ns", 1, 10),
    ]


def test_line_and_column_track_newlines() -> None:
    toks = tokenize("a\n  bc")
    assert [(t.text, t.pos.line, t.pos.col) for t in toks[:2]] == [("a", 1, 1), ("bc", 2, 3)]


def test_line_comment_is_skipped() -> None:
    toks = tokenize("a // comment\nb")
    assert [t.text for t in toks if t.kind is not Kind.EOF] == ["a", "b"]


def test_block_comment_is_skipped() -> None:
    toks = tokenize("a /* two\nlines */ b")
    assert [t.text for t in toks if t.kind is not Kind.EOF] == ["a", "b"]


def test_unterminated_block_comment_is_an_error() -> None:
    with pytest.raises(SPDLError, match="unterminated block comment"):
        tokenize("a /* forever")


def test_bad_character_reports_position() -> None:
    with pytest.raises(SPDLError) as exc:
        tokenize("ok\n  @")
    assert "unexpected character '@'" in str(exc.value)
    assert exc.value.pos.line == 2
    assert exc.value.pos.col == 3


def test_error_renders_source_line_and_caret() -> None:
    with pytest.raises(SPDLError) as exc:
        tokenize("first\nsecond $")
    rendered = str(exc.value)
    assert "line 2, col 8: unexpected character '$'" in rendered
    assert rendered.splitlines()[1].strip() == "second $"
    assert rendered.splitlines()[2].strip() == "^"


def test_token_kinds() -> None:
    toks = tokenize("send_1 ( A , 42 ) ;")
    kinds = [t.kind for t in toks if t.kind is not Kind.EOF]
    assert kinds == [Kind.IDENT, Kind.PUNCT, Kind.IDENT, Kind.PUNCT, Kind.NUMBER,
                     Kind.PUNCT, Kind.PUNCT]


def test_underscore_and_digits_in_identifiers() -> None:
    toks = tokenize("claim_I1 sk_2")
    assert [t.text for t in toks if t.kind is Kind.IDENT] == ["claim_I1", "sk_2"]


def test_eof_token_always_present() -> None:
    assert tokenize("")[0].kind is Kind.EOF


def test_token_describe() -> None:
    toks = tokenize("x 1 ,")
    assert toks[0].describe() == "identifier 'x'"
    assert toks[1].describe() == "number '1'"
    assert toks[3].kind is Kind.EOF
    assert toks[3].describe() == "end of input"
