"""A hand-written lexer for the SPDL subset understood by ProtoVerify.

Every token carries a 1-based ``(line, col)`` position so that parser errors can
point a caret at the exact offending character.  Comments (``//`` and
``/* ... */``) are discarded by the lexer.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .errors import Pos, SPDLError

__all__ = ["Kind", "Token", "tokenize"]


class Kind(Enum):
    """The lexical categories produced by :func:`tokenize`."""

    IDENT = "identifier"
    NUMBER = "number"
    PUNCT = "punctuation"
    EOF = "end of input"


@dataclass(frozen=True, slots=True)
class Token:
    """A single lexical token."""

    kind: Kind
    text: str
    pos: Pos

    def is_punct(self, value: str) -> bool:
        """True when this token is the punctuation ``value``."""
        return self.kind is Kind.PUNCT and self.text == value

    def is_ident(self, value: str) -> bool:
        """True when this token is the identifier ``value`` (case-sensitive)."""
        return self.kind is Kind.IDENT and self.text == value

    def describe(self) -> str:
        """A short human-readable rendering used in error messages."""
        if self.kind is Kind.EOF:
            return "end of input"
        if self.kind is Kind.IDENT:
            return f"identifier {self.text!r}"
        if self.kind is Kind.NUMBER:
            return f"number {self.text!r}"
        return f"{self.text!r}"


_PUNCT = set("{}()[],;:=")


@dataclass(slots=True)
class _Cursor:
    """Mutable lexer cursor over the whole source text."""

    text: str
    index: int = 0
    line: int = 1
    col: int = 1

    def pos(self) -> Pos:
        return Pos(self.line, self.col)

    def advance(self, count: int = 1) -> None:
        for _ in range(count):
            if self.index >= len(self.text):
                return
            ch = self.text[self.index]
            self.index += 1
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1

    def peek(self, offset: int = 0) -> str:
        i = self.index + offset
        return self.text[i] if i < len(self.text) else ""


def tokenize(source: str) -> list[Token]:
    """Return the token list of ``source`` (always ending with an ``EOF``)."""
    cur = _Cursor(text=source)
    tokens: list[Token] = []
    while True:
        _skip_trivia(cur)
        ch = cur.peek()
        if ch == "":
            tokens.append(Token(Kind.EOF, "", cur.pos()))
            return tokens
        if ch.isalpha() or ch == "_":
            tokens.append(_read_ident(cur))
        elif ch.isdigit():
            tokens.append(_read_number(cur))
        elif ch in _PUNCT:
            tokens.append(_read_punct(cur))
        else:
            raise SPDLError(
                f"unexpected character {ch!r}",
                cur.pos(),
                _source_line(source, cur.line),
            )


def _skip_trivia(cur: _Cursor) -> None:
    """Consume whitespace and comments."""
    while True:
        ch = cur.peek()
        if ch.isspace():
            cur.advance()
            continue
        if ch == "/" and cur.peek(1) == "/":
            while cur.peek() not in ("", "\n"):
                cur.advance()
            continue
        if ch == "/" and cur.peek(1) == "*":
            start = cur.pos()
            start_line = cur.line
            cur.advance(2)
            while not (cur.peek() == "*" and cur.peek(1) == "/"):
                if cur.peek() == "":
                    raise SPDLError("unterminated block comment", start, "")
                cur.advance()
            cur.advance(2)
            _ = start_line
            continue
        return


def _read_ident(cur: _Cursor) -> Token:
    pos = cur.pos()
    start = cur.index
    while cur.peek().isalnum() or cur.peek() == "_":
        cur.advance()
    return Token(Kind.IDENT, cur.text[start : cur.index], pos)


def _read_number(cur: _Cursor) -> Token:
    pos = cur.pos()
    start = cur.index
    while cur.peek().isdigit():
        cur.advance()
    return Token(Kind.NUMBER, cur.text[start : cur.index], pos)


def _read_punct(cur: _Cursor) -> Token:
    pos = cur.pos()
    ch = cur.peek()
    cur.advance()
    return Token(Kind.PUNCT, ch, pos)


def _source_line(source: str, line: int) -> str:
    lines = source.splitlines()
    return lines[line - 1] if 0 < line <= len(lines) else ""
