"""Trace JSON contract tests: round-tripping and schema validation."""

from __future__ import annotations

import json

import pytest

from conftest import SRC  # noqa: F401  (path bootstrap)
from protoverify.core.trace import AgentInfo, Edge, RunInfo, Status, Step, Trace, TraceError


def sample() -> Trace:
    return Trace(
        protocol="ns",
        claim="R3",
        status=Status.FALSIFIED.value,
        claim_kind="Niagree",
        bounds={"max_runs": 4, "max_len": 20},
        agents=(AgentInfo("A", "honest"), AgentInfo("M", "attacker")),
        runs=(RunInfo(1, "I", "A", "M"), RunInfo(2, "R", "B", "A")),
        steps=(
            Step(1, "send", 1, "A", "M", "1", "{A,ni#1}pk(M)", ("ni#1",), "A sends"),
            Step(2, "attacker_inject", None, "M", "B", "1", "{A,ni#1}pk(B)", (), "M forges"),
        ),
        edges=(Edge(1, 2, "message"),),
        violation="Bob believes he talked to Alice, but Alice talked to Mallory.",
    )


def test_round_trip_through_json() -> None:
    assert Trace.from_json(sample().to_json()) == sample()


def test_round_trip_through_a_file(tmp_path: object) -> None:
    path = tmp_path / "sub" / "trace.json"  # type: ignore[operator]
    written = sample().to_file(path)
    assert written.exists()
    assert Trace.from_file(written) == sample()
    assert json.loads(written.read_text(encoding="utf-8"))["protocol"] == "ns"


def test_step_is_attacker() -> None:
    assert sample().steps[1].is_attacker
    assert not sample().steps[0].is_attacker


def test_falsified_property() -> None:
    assert sample().falsified
    assert not Trace(protocol="p", claim="c").falsified


def test_knowledge_after() -> None:
    assert sample().knowledge_after(1) == ("ni#1",)
    assert sample().knowledge_after(2) == ("ni#1",)


def test_run_of() -> None:
    assert sample().run_of(2) == RunInfo(2, "R", "B", "A")
    assert sample().run_of(9) is None


@pytest.mark.parametrize(
    "mutate,message",
    [
        (lambda d: d.update(protocol=""), "protocol"),
        (lambda d: d.update(claim=""), "claim"),
        (lambda d: d.update(status="MAYBE"), "status"),
        (lambda d: d.update(claim_kind="Nope"), "claim_kind"),
        (lambda d: d.update(agents=[{"id": "A"}, {"id": "A"}]), "duplicate"),
        (lambda d: d.update(runs=[{"id": 1, "role": "I", "agent": "A", "peer": "B"},
                                  {"id": 1, "role": "R", "agent": "B", "peer": "A"}]),
         "duplicate"),
        (lambda d: d.update(steps=[{"i": 2, "type": "send", "run": 1, "from": "A",
                                    "to": "B", "msg": "m"}]), "numbered"),
        (lambda d: d["steps"].__setitem__(0, dict(d["steps"][0], type="teleport")), "unknown type"),
        (lambda d: d["steps"].__setitem__(0, dict(d["steps"][0], run=99)), "unknown run"),
        (lambda d: d["steps"].__setitem__(0, dict(d["steps"][0], msg="")), "non-empty"),
        (lambda d: d.update(edges=[{"from": 2, "to": 1}]), "forward"),
        (lambda d: d.update(edges=[{"from": 1, "to": 9}]), "missing step"),
    ],
)
def test_validator_rejects_broken_documents(mutate: object, message: str) -> None:
    data = sample().to_json()
    mutate(data)  # type: ignore[operator]
    with pytest.raises(TraceError, match=message):
        Trace.from_json(data)


@pytest.mark.parametrize("field", ["protocol", "claim", "status"])
def test_missing_required_fields(field: str) -> None:
    data = sample().to_json()
    del data[field]
    with pytest.raises(TraceError, match="missing required field"):
        Trace.from_json(data)


def test_from_json_rejects_non_objects() -> None:
    with pytest.raises(TraceError, match="must be a JSON object"):
        Trace.from_json([])  # type: ignore[arg-type]


def test_bad_types_are_reported() -> None:
    with pytest.raises(TraceError, match="must be an integer"):
        Trace.from_json({**sample().to_json(), "runs": [{"id": "one", "role": "I",
                                                         "agent": "A", "peer": "B"}]})


def test_step_numbers_must_be_contiguous() -> None:
    trace = sample()
    broken = Trace.from_json(trace.to_json())
    assert [s.i for s in broken.steps] == [1, 2]
