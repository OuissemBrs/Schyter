"""A recursive-descent parser for the SPDL subset.

The grammar accepted here is documented in ``docs/spdl.md``.  No parser
generator is used; every production is a hand-written method that reports a
:class:`SPDLError` pointing at the offending token.
"""

from __future__ import annotations

import pathlib

from ..core.terms import AsymEnc, Atom, Hash, Pk, SharedKey, Sign, Sk, SymEnc, Term, Tuple, Var
from ..core.types import TypeEnv
from .ast import (
    CLAIM_KINDS,
    ClaimEvent,
    FreshEvent,
    Protocol,
    RecvEvent,
    Role,
    SendEvent,
    VarEvent,
)
from .errors import Pos, SPDLError
from .lexer import Kind, Token, tokenize

__all__ = ["Parser", "parse", "parse_file"]

_CLAIM_AGENT_KINDS = frozenset({"Alive", "Weakagree", "Niagree", "Nisynch"})

Event = FreshEvent | VarEvent | SendEvent | RecvEvent | ClaimEvent


class Parser:
    """Recursive-descent parser over a token list."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.tokens = tokenize(source)
        self.pos = 0
        self.params: tuple[str, ...] = ()
        self.constants: set[str] = set()
        self.const_types: dict[str, str] = {}
        self.secrets: set[str] = set()
        self.hash_functions: set[str] = set()
        self.user_types: set[str] = set()
        self.var_types: dict[str, str] = {}

    # -- token helpers -------------------------------------------------
    @property
    def current(self) -> Token:
        """The token the parser is currently looking at."""
        return self.tokens[self.pos]

    def advance(self) -> Token:
        """Consume and return the current token."""
        tok = self.current
        if tok.kind is not Kind.EOF:
            self.pos += 1
        return tok

    def line_of(self, pos: Pos) -> str:
        """Return the 1-based source line ``pos`` points at."""
        if 1 <= pos.line <= len(self.lines):
            return self.lines[pos.line - 1]
        return ""

    def error(self, message: str, tok: Token | None = None) -> SPDLError:
        """Build an :class:`SPDLError` anchored at ``tok`` (default: current)."""
        tok = tok or self.current
        return SPDLError(message, tok.pos, self.line_of(tok.pos))

    def expect_punct(self, value: str, context: str) -> Token:
        """Consume ``value`` or raise ``expected 'value' <context>``."""
        if not self.current.is_punct(value):
            raise self.error(f"expected {value!r} {context}, found {self.current.describe()}")
        return self.advance()

    def expect_ident(self, what: str) -> Token:
        """Consume an identifier or raise ``expected <what>``."""
        if self.current.kind is not Kind.IDENT:
            raise self.error(f"expected {what}, found {self.current.describe()}")
        return self.advance()

    def at_punct(self, value: str) -> bool:
        """True when the current token is the punctuation ``value``."""
        return self.current.is_punct(value)

    # -- top level -----------------------------------------------------
    def parse_program(self) -> Protocol:
        """Parse the whole token stream into a :class:`Protocol`."""
        while self.current.kind is Kind.IDENT and not self.current.is_ident("protocol"):
            self.parse_declaration()
        if not self.current.is_ident("protocol"):
            raise self.error("expected a 'protocol' declaration, found " + self.current.describe())
        protocol = self.parse_protocol()
        if self.current.kind is not Kind.EOF:
            raise self.error(f"expected end of input, found {self.current.describe()}")
        return protocol

    def parse_declaration(self) -> None:
        """Parse one ``usertype``/``const``/``hashfunction``/``secret`` declaration."""
        tok = self.advance()
        name = tok.text
        if name == "usertype":
            self.user_types.add(self.expect_ident("a type name after 'usertype'").text)
        elif name == "const":
            self.parse_const(tok)
        elif name == "hashfunction":
            self.hash_functions.add(self.expect_ident("a name after 'hashfunction'").text)
        elif name == "secret":
            self.parse_secret()
        else:
            raise self.error(
                "expected 'usertype', 'const', 'hashfunction', 'secret' or 'protocol', "
                f"found {tok.describe()}",
                tok,
            )
        self.expect_punct(";", f"after the '{name}' declaration")

    def parse_const(self, kw: Token) -> None:
        name_tok = self.expect_ident(f"a constant name after '{kw.text}'")
        self.expect_punct(":", "after a constant name")
        type_tok = self.expect_ident("a type after ':'")
        if name_tok.text in self.constants:
            raise self.error(f"duplicate declaration of {name_tok.text!r}", name_tok)
        self.constants.add(name_tok.text)
        self.const_types[name_tok.text] = type_tok.text

    def parse_secret(self) -> None:
        name_tok = self.expect_ident("a secret name after 'secret'")
        type_name = "Key"
        if self.at_punct(":"):
            self.advance()
            type_name = self.expect_ident("a type after ':'").text
        self.secrets.add(name_tok.text)
        self.constants.add(name_tok.text)
        self.const_types[name_tok.text] = type_name

    def parse_protocol(self) -> Protocol:
        kw = self.advance()  # 'protocol'
        name_tok = self.expect_ident("a protocol name after 'protocol'")
        self.expect_punct("(", "after the protocol name")
        self.params = self.parse_name_list("a protocol parameter list")
        self.expect_punct(")", "after the protocol parameter list")
        self.expect_punct("{", "after the protocol header")
        roles: list[Role] = []
        while not self.at_punct("}"):
            if self.current.kind is Kind.EOF:
                raise self.error("expected '}' to close the protocol body")
            roles.append(self.parse_role())
        self.expect_punct("}", "to close the protocol body")
        type_env = TypeEnv.builtin().with_user_types(frozenset(self.user_types))
        return Protocol(
            name=name_tok.text,
            params=self.params,
            roles=tuple(roles),
            user_types=frozenset(self.user_types),
            constants=tuple(sorted(self.constants)),
            hash_functions=tuple(sorted(self.hash_functions)),
            secrets=tuple(sorted(self.secrets)),
            type_env=type_env,
            pos=kw.pos,
        )

    def parse_name_list(self, context: str) -> tuple[str, ...]:
        names = [self.expect_ident(f"a name in {context}").text]
        while self.at_punct(","):
            self.advance()
            names.append(self.expect_ident(f"a name in {context}").text)
        return tuple(names)

    def parse_role(self) -> Role:
        kw = self.advance()  # 'role'
        name_tok = self.expect_ident("a role name after 'role'")
        self.expect_punct("{", "after the role name")
        self.var_types = {}
        events: list[Event] = []
        while not self.at_punct("}"):
            if self.current.kind is Kind.EOF:
                raise self.error("expected '}' to close the role body")
            events.append(self.parse_event())
        self.expect_punct("}", "to close the role body")
        return Role(name=name_tok.text, events=tuple(events), pos=kw.pos)

    # -- events --------------------------------------------------------
    def parse_event(self) -> Event:
        tok = self.expect_ident("an event keyword (fresh, var, send_N, recv_N or claim_L)")
        head, sep, rest = tok.text.partition("_")
        if head in ("fresh", "var") and not sep:
            return self.parse_fresh_or_var(tok, head)
        if head == "send" and rest:
            return self.parse_message(tok, rest, sending=True)
        if head == "recv" and rest:
            return self.parse_message(tok, rest, sending=False)
        if head == "claim" and sep:
            return self.parse_claim(tok, rest)
        raise self.error(f"unknown event keyword {tok.text!r}", tok)

    def parse_fresh_or_var(self, kw: Token, kind: str) -> FreshEvent | VarEvent:
        name_tok = self.expect_ident(f"a variable name after '{kw.text}'")
        self.expect_punct(":", f"after the {kind} variable name")
        type_tok = self.expect_ident("a type after ':'")
        self.expect_punct(";", f"after the '{kind} {name_tok.text}' declaration")
        if name_tok.text in self.var_types:
            raise self.error(f"variable {name_tok.text!r} is declared twice in this role", name_tok)
        self.var_types[name_tok.text] = type_tok.text
        if kind == "fresh":
            return FreshEvent(name_tok.text, type_tok.text, kw.pos)
        return VarEvent(name_tok.text, type_tok.text, kw.pos)

    def parse_message(self, kw: Token, label_text: str, *, sending: bool) -> SendEvent | RecvEvent:
        if not label_text.isdigit():
            raise self.error(f"expected a numeric label after '{kw.text}_', found {label_text!r}", kw)
        label = int(label_text)
        self.expect_punct("(", f"after the message keyword {kw.text}")
        src = self.parse_unary()
        self.expect_punct(",", "after the sender in a message event")
        dst = self.parse_unary()
        self.expect_punct(",", "after the receiver in a message event")
        msg = self.parse_term()
        self.expect_punct(")", f"after term in message {label}")
        self.expect_punct(";", f"after message {label}")
        if sending:
            return SendEvent(label, src, dst, msg, kw.pos)
        return RecvEvent(label, src, dst, msg, kw.pos)

    def parse_claim(self, kw: Token, label: str) -> ClaimEvent:
        self.expect_punct("(", f"after the claim keyword {kw.text}")
        claimant = self.expect_ident("a role name as the first claim argument").text
        self.expect_punct(",", f"after the claimant role in claim {label}")
        kind_tok = self.expect_ident(
            "a claim kind (Secret, Alive, Weakagree, Niagree or Nisynch)"
        )
        kind = kind_tok.text
        if kind not in CLAIM_KINDS:
            raise self.error(
                f"unknown claim kind {kind!r}; expected one of {', '.join(CLAIM_KINDS)}",
                kind_tok,
            )
        argument: Term | None = None
        partner: str | None = None
        if self.at_punct(","):
            self.advance()
            if kind == "Secret":
                argument = self.parse_term()
            else:
                partner = self.expect_ident("a partner role name").text
        self.expect_punct(")", f"after the arguments of claim {label}")
        self.expect_punct(";", f"after claim {label}")
        return ClaimEvent(label, claimant, kind, argument, partner, kw.pos)

    # -- terms ---------------------------------------------------------
    def parse_term(self) -> Term:
        """Parse a comma-separated sequence of unary terms into a term."""
        parts = [self.parse_unary()]
        while self.at_punct(","):
            self.advance()
            parts.append(self.parse_unary())
        return parts[0] if len(parts) == 1 else Tuple(tuple(parts))

    def parse_unary(self) -> Term:
        """Parse one atom, encryption, tuple, grouping, or function application."""
        if self.at_punct("{"):
            return self.parse_braced()
        if self.at_punct("("):
            self.advance()
            inner = self.parse_term()
            self.expect_punct(")", "to close a parenthesised term")
            return inner
        tok = self.expect_ident("a term")
        if self.at_punct("("):
            return self.parse_application(tok)
        return self.resolve_name(tok)

    def parse_braced(self) -> Term:
        """Parse ``{a,b}``, ``{m}k``, ``{m}pk(A)``, ``{m}sk(A)`` or ``{m}h(x)``.

        A brace group followed by an identifier is an encryption; followed by a
        comma, a closing parenthesis or a semicolon it is a plain tuple.
        """
        self.expect_punct("{", "to start a group")
        parts = [self.parse_unary()]
        while self.at_punct(","):
            self.advance()
            parts.append(self.parse_unary())
        self.expect_punct("}", "to close a group opened at '{'")
        payload: Term = parts[0] if len(parts) == 1 else Tuple(tuple(parts))
        if self.current.kind is not Kind.IDENT:
            return payload
        key = self.parse_key_operand()
        if isinstance(key, Pk):
            return AsymEnc(payload, key)
        if isinstance(key, Sk):
            return Sign(payload, key)
        if isinstance(key, Hash):
            return Hash(payload, key.name)
        return SymEnc(payload, key)

    def parse_application(self, head: Token) -> Term:
        """Parse ``pk(A)``, ``sk(A)``, ``h(x)`` or ``k(A,B)``."""
        name = head.text
        self.expect_punct("(", f"after '{name}'")
        if name == "k":
            left = self.parse_unary()
            self.expect_punct(",", "between the two agents of a shared key")
            right = self.parse_unary()
            self.expect_punct(")", "after the agents of k(...)")
            return SharedKey(left, right)
        if name not in ("pk", "sk", "h") and name not in self.hash_functions:
            raise self.error(
                f"unknown term constructor {name!r}; expected pk, sk, k or a declared hashfunction",
                head,
            )
        arg = self.parse_unary()
        self.expect_punct(")", f"after the argument of {name}(...)")
        if name == "pk":
            return Pk(arg)
        if name == "sk":
            return Sk(arg)
        return Hash(arg, name)

    def parse_key_operand(self) -> Term:
        """Parse the operand that follows ``}`` in ``{m}<key>``."""
        tok = self.expect_ident("a key after '}' (k, pk(A), sk(A) or h(x))")
        is_constructor = tok.text in ("pk", "sk", "k", "h") or tok.text in self.hash_functions
        if is_constructor and self.at_punct("("):
            return self.parse_application(tok)
        return self.resolve_name(tok)

    def resolve_name(self, tok: Token) -> Term:
        """Turn a bare identifier into a constant, a role parameter, or a variable.

        Names that are not declared yet become ``Var(name, "Any")``; the static
        checker then reports use-before-declaration or a missing declaration,
        which lets it accumulate every name error in one pass.
        """
        name = tok.text
        if name in self.constants or name in self.params:
            return Atom(name)
        declared = self.var_types.get(name)
        return Var(name, declared or "Any")


def parse(source: str) -> Protocol:
    """Parse ``source`` and return the resulting :class:`Protocol`."""
    return Parser(source).parse_program()


def parse_file(path: str) -> Protocol:
    """Read and parse the SPDL file at ``path``."""
    return parse(pathlib.Path(path).read_text(encoding="utf-8"))
