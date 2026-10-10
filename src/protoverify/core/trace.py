"""The trace JSON contract.

This module is the **only** interface between the engine and the ``viz``
package.  Renderers read a :class:`Trace` produced by :meth:`Trace.from_json`
and never touch the engine.

The on-disk shape is documented in ``docs/trace-schema.md``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

__all__ = ["AgentInfo", "Edge", "RunInfo", "Status", "Step", "Trace", "TraceError"]


class TraceError(ValueError):
    """Raised when a trace document does not satisfy the schema."""


class Status(StrEnum):
    """The three outcomes ProtoVerify may report for a claim."""

    VERIFIED = "VERIFIED"
    FALSIFIED = "FALSIFIED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class AgentInfo:
    """An agent appearing in the trace."""

    id: str
    kind: str = "honest"

    def to_json(self) -> dict[str, str]:
        """Return the JSON object for this agent."""
        return {"id": self.id, "kind": self.kind}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> AgentInfo:
        """Rebuild an agent from a JSON object."""
        return cls(id=_req_str(data, "id"), kind=data.get("kind", "honest"))


@dataclass(frozen=True, slots=True)
class RunInfo:
    """A role instance in the trace."""

    id: int
    role: str
    agent: str
    peer: str

    def to_json(self) -> dict[str, Any]:
        """Return the JSON object for this run."""
        return {"id": self.id, "role": self.role, "agent": self.agent, "peer": self.peer}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RunInfo:
        """Rebuild a run from a JSON object."""
        return cls(
            id=_req_int(data, "id"),
            role=_req_str(data, "role"),
            agent=_req_str(data, "agent"),
            peer=_req_str(data, "peer"),
        )


@dataclass(frozen=True, slots=True)
class Step:
    """One event of the attack trace."""

    i: int
    type: str
    run: int | None
    frm: str
    to: str
    label: str
    msg: str
    attacker_new: tuple[str, ...] = ()
    note: str = ""

    @property
    def is_attacker(self) -> bool:
        """True when the step is performed by the attacker."""
        return self.type.startswith("attacker")

    def to_json(self) -> dict[str, Any]:
        """Return the JSON object for this step."""
        return {
            "i": self.i,
            "type": self.type,
            "run": self.run,
            "from": self.frm,
            "to": self.to,
            "label": self.label,
            "msg": self.msg,
            "attacker_new": list(self.attacker_new),
            "note": self.note,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Step:
        """Rebuild a step from a JSON object."""
        return cls(
            i=_req_int(data, "i"),
            type=_req_str(data, "type"),
            run=_opt_int(data, "run"),
            frm=_req_str(data, "from"),
            to=_req_str(data, "to"),
            label=str(data.get("label", "")),
            msg=_req_str(data, "msg"),
            attacker_new=tuple(str(x) for x in data.get("attacker_new", ())),
            note=str(data.get("note", "")),
        )


@dataclass(frozen=True, slots=True)
class Edge:
    """A causal relation between two steps (1-based step numbers)."""

    src: int
    dst: int
    kind: str = "message"

    def to_json(self) -> dict[str, Any]:
        """Return the JSON object for this edge."""
        return {"from": self.src, "to": self.dst, "kind": self.kind}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Edge:
        """Rebuild an edge from a JSON object."""
        return cls(
            src=_req_int(data, "from"),
            dst=_req_int(data, "to"),
            kind=str(data.get("kind", "message")),
        )


@dataclass(frozen=True, slots=True)
class Trace:
    """A complete, renderer-ready description of one attack."""

    protocol: str
    claim: str
    status: str = Status.UNKNOWN.value
    bounds: dict[str, Any] = field(default_factory=dict)
    agents: tuple[AgentInfo, ...] = ()
    runs: tuple[RunInfo, ...] = ()
    steps: tuple[Step, ...] = ()
    edges: tuple[Edge, ...] = ()
    violation: str = ""
    claim_kind: str = ""

    # -- serialisation ---------------------------------------------------
    def to_json(self) -> dict[str, Any]:
        """Return the trace as a plain JSON-compatible dictionary."""
        return {
            "protocol": self.protocol,
            "claim": self.claim,
            "status": self.status,
            "claim_kind": self.claim_kind,
            "bounds": dict(self.bounds),
            "agents": [a.to_json() for a in self.agents],
            "runs": [r.to_json() for r in self.runs],
            "steps": [s.to_json() for s in self.steps],
            "edges": [e.to_json() for e in self.edges],
            "violation": self.violation,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Trace:
        """Rebuild and validate a trace from a JSON dictionary."""
        if not isinstance(data, dict):
            raise TraceError("trace document must be a JSON object")
        trace = cls(
            protocol=_req_str(data, "protocol"),
            claim=_req_str(data, "claim"),
            status=_req_status(data),
            claim_kind=str(data.get("claim_kind", "")),
            bounds=dict(data.get("bounds", {})),
            agents=tuple(AgentInfo.from_json(x) for x in data.get("agents", ())),
            runs=tuple(RunInfo.from_json(x) for x in data.get("runs", ())),
            steps=tuple(Step.from_json(x) for x in data.get("steps", ())),
            edges=tuple(Edge.from_json(x) for x in data.get("edges", ())),
            violation=str(data.get("violation", "")),
        )
        validate(trace)
        return trace

    def to_file(self, path: str | Path) -> Path:
        """Write the trace to ``path`` as pretty-printed JSON."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_json(), indent=2) + "\n", encoding="utf-8")
        return target

    @classmethod
    def from_file(cls, path: str | Path) -> Trace:
        """Read a trace from ``path``."""
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    # -- convenience ------------------------------------------------------
    @property
    def falsified(self) -> bool:
        """True when this trace disproves its claim."""
        return self.status == Status.FALSIFIED.value

    def knowledge_after(self, step_index: int) -> tuple[str, ...]:
        """Return every attacker-learned term up to and including ``step_index``."""
        out: list[str] = []
        for step in self.steps:
            if step.i > step_index:
                break
            out.extend(step.attacker_new)
        return tuple(out)

    def run_of(self, run_id: int) -> RunInfo | None:
        """Return the run with id ``run_id``, if any."""
        return next((r for r in self.runs if r.id == run_id), None)


# ---------------------------------------------------------------------------
# Hand-written JSON-schema validator
# ---------------------------------------------------------------------------

_STEP_TYPES = frozenset({"send", "recv", "attacker_forward", "attacker_inject"})
_CLAIM_KINDS = frozenset({"Secret", "Alive", "Weakagree", "Niagree", "Nisynch"})
_KINDS = frozenset({"honest", "attacker"})


def validate(trace: Trace) -> None:
    """Raise :class:`TraceError` when ``trace`` violates the documented schema."""
    if not trace.protocol:
        raise TraceError("trace.protocol must be a non-empty string")
    if not trace.claim:
        raise TraceError("trace.claim must be a non-empty string")
    if trace.claim_kind and trace.claim_kind not in _CLAIM_KINDS:
        raise TraceError(f"trace.claim_kind must be one of {sorted(_CLAIM_KINDS)}")
    agents = {a.id for a in trace.agents}
    if len(agents) != len(trace.agents):
        raise TraceError("trace.agents contains duplicate ids")
    run_ids = {r.id for r in trace.runs}
    if len(run_ids) != len(trace.runs):
        raise TraceError("trace.runs contains duplicate ids")
    expected = list(range(1, len(trace.steps) + 1))
    if [s.i for s in trace.steps] != expected:
        raise TraceError("trace.steps must be numbered 1..n without gaps")
    for step in trace.steps:
        if step.type not in _STEP_TYPES:
            raise TraceError(f"step {step.i}: unknown type {step.type!r}")
        if step.run is not None and step.run not in run_ids:
            raise TraceError(f"step {step.i}: references unknown run {step.run}")
        if not step.msg:
            raise TraceError(f"step {step.i}: msg must be a non-empty string")
    for edge in trace.edges:
        if not 1 <= edge.src <= len(trace.steps) or not 1 <= edge.dst <= len(trace.steps):
            raise TraceError(f"edge {edge.src}->{edge.dst} refers to a missing step")
        if edge.src >= edge.dst:
            raise TraceError(f"edge {edge.src}->{edge.dst} is not a forward causal edge")


def _req_str(data: dict[str, Any], key: str) -> str:
    if key not in data:
        raise TraceError(f"missing required field {key!r}")
    value = data[key]
    if not isinstance(value, str) or not value:
        raise TraceError(f"field {key!r} must be a non-empty string")
    return value


def _req_int(data: dict[str, Any], key: str) -> int:
    if key not in data:
        raise TraceError(f"missing required field {key!r}")
    value = data[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise TraceError(f"field {key!r} must be an integer")
    return value


def _opt_int(data: dict[str, Any], key: str) -> int | None:
    if key not in data or data[key] is None:
        return None
    return _req_int(data, key)


def _req_status(data: dict[str, Any]) -> str:
    status = _req_str(data, "status")
    if status not in {s.value for s in Status}:
        raise TraceError(f"status must be one of {[s.value for s in Status]}, got {status!r}")
    return status
