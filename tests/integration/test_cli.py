"""CLI tests: exit codes, output files and error handling."""

from __future__ import annotations

import json

import pytest

from conftest import SRC, example_path  # noqa: F401  (path bootstrap)
from protoverify.cli import EXIT_FALSIFIED, EXIT_INTERNAL, EXIT_OK, EXIT_PARSE, main

BROKEN = "const c: Key;\nprotocol p(A){role A{send_1(A,A,c)}}"


def test_check_accepts_a_valid_protocol(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-color", "check", str(example_path("ns"))]) == EXIT_OK
    assert "static checks passed" in capsys.readouterr().out


def test_check_rejects_a_broken_program(
    tmp_path: object, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "broken.spdl"  # type: ignore[operator]
    path.write_text(BROKEN, encoding="utf-8")
    assert main(["--no-color", "check", str(path)]) == EXIT_PARSE
    assert "protoverify:" in capsys.readouterr().err


def test_verify_reports_falsified_claims(
    tmp_path: object, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--no-color", "verify", str(example_path("ns")), "--trace-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == EXIT_FALSIFIED
    assert "FALSIFIED" in out and "VERIFIED" in out
    assert "role  claim" in out
    assert (tmp_path / "ns_R3.json").exists()  # type: ignore[operator]


def test_verify_of_a_secure_protocol_exits_zero(
    tmp_path: object, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["--no-color", "verify", str(example_path("nsl")), "--trace-dir", str(tmp_path)])
    assert code == EXIT_OK
    assert "FALSIFIED" not in capsys.readouterr().out


def test_verify_writes_json(
    tmp_path: object, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "result.json"  # type: ignore[operator]
    main(["--no-color", "verify", str(example_path("ns")), "--trace-dir", str(tmp_path),
          "--json", str(target)])
    payload = json.loads(target.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    assert payload["protocol"] == "ns"
    assert {c["claim"]: c["status"] for c in payload["claims"]}["R3"] == "FALSIFIED"
    assert payload["claims"][0]["kind"]
    assert payload["bounds"] == {"max_runs": 4, "max_len": 20}


def test_verbose_prints_the_attack(
    tmp_path: object, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--no-color", "-v", "verify", str(example_path("ns")), "--trace-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert "attack trace" in out
    assert "violation:" in out


def test_quiet_prints_only_the_summary(
    tmp_path: object, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["--no-color", "-q", "verify", str(example_path("ns")), "--trace-dir", str(tmp_path)])
    out = capsys.readouterr().out
    assert "role  claim" not in out
    assert "wrote trace" in out


def test_list_examples(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-color", "list-examples"]) == EXIT_OK
    assert "ns" in capsys.readouterr().out


def test_run_example_verifies(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--no-color", "run-example", "ns", "--quiet"]) == EXIT_FALSIFIED
    assert main(["--no-color", "run-example", "nsl", "--quiet"]) == EXIT_OK
    capsys.readouterr()


def test_run_example_rejects_an_unknown_name(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--no-color", "run-example", "nope"]) == EXIT_PARSE
    assert "unknown example" in capsys.readouterr().err


def test_claim_filter(tmp_path: object, capsys: pytest.CaptureFixture[str]) -> None:
    main(["--no-color", "verify", str(example_path("ns")), "--trace-dir", str(tmp_path),
          "--claim", "I1"])
    out = capsys.readouterr().out
    assert "I1" in out and "R3" not in out


def test_compromise_option_is_accepted(tmp_path: object) -> None:
    assert main(["--no-color", "verify", str(example_path("ns")), "--trace-dir", str(tmp_path),
                 "--compromise", "B"]) in (EXIT_OK, EXIT_FALSIFIED)


def test_trace_bounds_are_reported_in_the_document(tmp_path: object) -> None:
    main(["--no-color", "verify", str(example_path("ns")), "--trace-dir", str(tmp_path),
          "--max-runs", "2", "--max-len", "8"])
    document = json.loads((tmp_path / "ns_R3.json").read_text(encoding="utf-8"))  # type: ignore[operator]
    assert document["bounds"] == {"max_runs": 2, "max_len": 8}


def test_internal_error_is_reported_as_exit_three(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_args: object) -> int:
        raise ZeroDivisionError("engine exploded")

    monkeypatch.setattr("protoverify.cli._dispatch", boom)
    assert main(["--no-color", "check", str(example_path("ns"))]) == EXIT_INTERNAL
    assert "internal error" in capsys.readouterr().err


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "protoverify" in capsys.readouterr().out


def test_missing_subcommand_is_an_error(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main([])
    assert "required" in capsys.readouterr().err
