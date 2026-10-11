"""Regenerate ``examples/regression_snapshot.json`` from a real verification run.

The snapshot records what the engine *actually* produced. It is a **change
detector, never an oracle**: ``tests/integration/test_reference.py`` compares the
engine against the hand-written ``examples/expected_reference.json``, which is the
only oracle.

Keeping the two apart is deliberate. A file generated from the engine's own output
can only ever confirm the engine; the reference file is what makes a wrong answer
visible.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, "src")

from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file

EXAMPLES = pathlib.Path("examples")
SNAPSHOT = EXAMPLES / "regression_snapshot.json"
BOUNDS = {"ns": Bounds(), "nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}


def main() -> None:
    snapshot: dict[str, dict[str, object]] = {}
    for path in sorted(EXAMPLES.glob("*.spdl")):
        protocol = parse_file(str(path))
        bounds = BOUNDS.get(path.stem, Bounds())
        results = Verifier(protocol, bounds).verify()
        snapshot[path.stem] = {
            "description": _describe(path),
            "bounds": bounds.to_json(),
            "claims": {r.claim: r.status for r in results},
        }
        print(path.stem, {r.claim: r.status for r in results})
    SNAPSHOT.write_text(
        json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {SNAPSHOT} (snapshot only - the oracle is expected_reference.json)")


def _describe(path: pathlib.Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            return stripped.lstrip("/ ").strip()
    return ""


if __name__ == "__main__":
    main()
