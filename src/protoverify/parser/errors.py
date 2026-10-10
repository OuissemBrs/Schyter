"""Error types carrying source positions."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["EngineError", "Pos", "ProtoVerifyError", "SPDLError", "StaticCheckError"]


@dataclass(frozen=True, slots=True)
class Pos:
    """A 1-based source position."""

    line: int
    col: int

    def __str__(self) -> str:
        return f"line {self.line}, col {self.col}"


class ProtoVerifyError(Exception):
    """Base class of every ProtoVerify error."""


class SPDLError(ProtoVerifyError):
    """A lexical or syntactic error, rendered with the offending source line."""

    def __init__(self, message: str, pos: Pos, source_line: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.pos = pos
        self.source_line = source_line

    def __str__(self) -> str:
        head = f"{self.pos}: {self.message}"
        if not self.source_line.strip():
            return head
        caret = " " * max(0, self.pos.col - 1) + "^"
        return f"{head}\n  {self.source_line.rstrip()}\n  {caret}"


@dataclass(frozen=True, slots=True)
class StaticCheckError:
    """A rejected program; ``error`` renders the human-readable diagnostic."""

    error: str


class EngineError(ProtoVerifyError):
    """Raised when the engine reaches an unexpected internal state."""
