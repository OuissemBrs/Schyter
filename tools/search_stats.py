"""Search statistics for the bundled examples (diagnostic tool, not a test).

Wraps :class:`Searcher` to count branch points, dead ends and the receive labels
that could not be resolved, so the "why is this VERIFIED" question can be
answered with numbers instead of adjectives.

Usage::

    python tools/search_stats.py nsl
    python tools/search_stats.py ns R2
"""

from __future__ import annotations

import collections
import pathlib
import sys

sys.path.insert(0, "src")

from protoverify.core import search as S
from protoverify.parser import parse_file

EXAMPLES = pathlib.Path("examples")


def instrument(search: S.Searcher) -> collections.Counter[str]:
    """Patch ``search`` in place so every transition updates ``stats``."""
    stats: collections.Counter[str] = collections.Counter()

    def resolve_recv(state: object, key: tuple[int, int]) -> list[object]:
        stats["recv_branch_points"] += 1
        children = original(state, key)  # type: ignore[arg-type]
        run = state.runs[key[0]]  # type: ignore[attr-defined]
        stats[f"recv_label_{run.event(key[1]).label}"] += 1
        if not children:
            stats["dead_ends"] += 1
            stats[f"dead_recv_label_{run.event(key[1]).label}"] += 1
        return children

    def attacker_branches(*args: object, **kwargs: object) -> list[object]:
        out = original_attacker(*args, **kwargs)  # type: ignore[arg-type]
        stats["attacker_options"] += len(out)  # type: ignore[arg-type]
        return out

    def new_run_branches(*args: object, **kwargs: object) -> list[object]:
        out = original_new_run(*args, **kwargs)  # type: ignore[arg-type]
        stats["new_run_options"] += len(out)  # type: ignore[arg-type]
        return out

    original = search._resolve_recv
    original_attacker = search._attacker_branches
    original_new_run = search._new_run_branches
    search._resolve_recv = resolve_recv  # type: ignore[method-assign]
    search._attacker_branches = attacker_branches  # type: ignore[method-assign]
    search._new_run_branches = new_run_branches  # type: ignore[method-assign]
    return stats


def main(argv: list[str]) -> int:
    name = argv[0] if argv else "nsl"
    only = argv[1] if len(argv) > 1 else None
    protocol = parse_file(str(EXAMPLES / f"{name}.spdl"))
    verifier = S.Verifier(protocol, S.Bounds(max_runs=4, timeout=120.0))
    stats = instrument(verifier.searcher)
    results = verifier.verify([only] if only else None)
    for result in results:
        print(f"{name}/{result.claim:<3} {result.kind:<9} {result.status:<9} "
              f"states={result.states:<6} {result.seconds:.2f}s")
    print()
    for key in sorted(stats):
        print(f"  {key:<26} {stats[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
