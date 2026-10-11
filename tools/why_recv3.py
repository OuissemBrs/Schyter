"""Why can Bob's ``recv_3`` not be satisfied in NSL?

Replays the reachable search states of the responder role and, for every state in
which ``recv_3`` is the next event, reports which of the four ways of obtaining
the message ``{nr}pk(R)`` are still open:

* **attacker**  -- can the Dolev-Yao attacker build it from its knowledge?
* **match**     -- does it unify with a ``send`` of an existing run?
* **new run**   -- would a fresh role instance produce it?
* **spontaneous**-- could an unrelated session have sent it?

Usage::

    python tools/why_recv3.py examples/nsl.spdl 3
    python tools/why_recv3.py examples/ns.spdl  3
"""

from __future__ import annotations

import pathlib
import sys
from collections import Counter

sys.path.insert(0, "src")

from protoverify.core.search import Bounds, Verifier
from protoverify.parser import parse_file
from protoverify.parser.ast import RecvEvent

MAX_STATES = 4000


def main(argv: list[str]) -> int:
    path = pathlib.Path(argv[0])
    label = argv[1] if len(argv) > 1 else "3"
    protocol = parse_file(str(path))
    verifier = Verifier(protocol, Bounds(max_runs=4, timeout=120.0))
    search = verifier.searcher
    tally: Counter[str] = Counter()
    visited: set[tuple] = set()

    def walk(state: object, depth: int = 0) -> None:
        if len(visited) >= MAX_STATES or depth > 14:
            return
        key = search._canonical(state)  # type: ignore[arg-type]
        if key in visited:
            return
        visited.add(key)
        ready = search._ready(state)  # type: ignore[arg-type]
        if not ready:
            return
        for event_key in ready:
            event = state.runs[event_key[0]].event(event_key[1])  # type: ignore[attr-defined]
            if isinstance(event, RecvEvent) and str(event.label) == label:
                tally.update(_probe(search, state, event_key))  # type: ignore[arg-type]
                continue
            for child in search._advance(state, event_key):  # type: ignore[arg-type]
                walk(child, depth + 1)

    for role_name in ("R",):
        agent = search._default_agent(role_name)
        for peer in search.peer_pool(agent):
            walk(search._initial_state(role_name, agent, peer))
    print(f"{path.name}: recv_{label} reached in {sum(tally.values())} states "
          f"(states explored: {len(visited)})")
    for key in sorted(tally):
        print(f"  {key:<34} {tally[key]}")
    return 0


def _probe(search: object, state: object, key: tuple[int, int]) -> Counter[str]:
    """Count which ways of satisfying ``key`` are open in ``state``."""
    run = state.runs[key[0]]  # type: ignore[attr-defined]
    event = run.event(key[1])
    out: Counter[str] = Counter()
    out["states"] += 1
    forged = search._attacker_branches(state, key, run, event)  # type: ignore[attr-defined]
    out["attacker_option_open"] += 1 if forged else 0
    for run_id, slot in search._sends_in(state, event.label):  # type: ignore[attr-defined]
        if search._match_send(state, key, run_id, slot) is not None:  # type: ignore[attr-defined]
            out["match_option_open"] += 1
    if search._new_run_branches(state, key, run, event):  # type: ignore[attr-defined]
        out["new_run_option_open"] += 1
    if search._spontaneous_runs(state, key):  # type: ignore[attr-defined]
        out["spontaneous_option_open"] += 1
    message = run.instantiate(event.msg).substitute(state.sigma)  # type: ignore[attr-defined]
    knows = search.attacker.can_synthesize(  # type: ignore[attr-defined]
        message, state.knowledge  # type: ignore[attr-defined]
    )
    out[f"attacker_can_build_{message.text()}"] += 1 if knows else 0
    if knows:
        for name, value in sorted(state.sigma.items()):  # type: ignore[attr-defined]
            out[f"   sigma {name} = {value.text()}"] += 1
        out["   runs"] += 1
        out["   " + ", ".join(
            f"{r.role.name}:{r.agent}->{r.peer}" for r in state.runs.values()  # type: ignore[attr-defined]
        )] += 1
        out["   attacker_learned=" + ",".join(sorted(
            {t.text() for t in state.knowledge  # type: ignore[attr-defined]
             if t.text().endswith(tuple("123456789")) or "#" in t.text()}
        ))] += 1
    return out


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
