"""Regenerate ``examples/expected.json`` from a real verification run.

The file records what the engine *actually* produced; nothing in the engine
reads it, so deleting it cannot change any result.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, "src")

from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file

EXAMPLES = pathlib.Path("examples")
BOUNDS = {"ns": Bounds(), "nsl": Bounds(max_runs=3), "yahalom": Bounds(timeout=60.0)}


def main() -> None:
    expected: dict[str, dict[str, object]] = {}
    for path in sorted(EXAMPLES.glob("*.spdl")):
        protocol = parse_file(str(path))
        bounds = BOUNDS.get(path.stem, Bounds())
        results = Verifier(protocol, bounds).verify()
        expected[path.stem] = {
            "description": _describe(path),
            "bounds": bounds.to_json(),
            "claims": {r.claim: r.status for r in results},
        }
        print(path.stem, {r.claim: r.status for r in results})
    (EXAMPLES / "expected.json").write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _describe(path: pathlib.Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            return stripped.lstrip("/ ").strip()
    return ""


if __name__ == "__main__":
    main()
