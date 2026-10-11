Architecture
============

How a verification run is put together, and why sharing one search between
several claims is sound.

The layers, from the bottom up
-----------------------------

```
parser/      lexer -> recursive-descent parser -> frozen AST -> static checks
core/terms   the term algebra (Atom, Tuple, SymEnc, AsymEnc, Sign, Hash, Pk, Sk, SharedKey)
core/unify   MGU with occurs check, plus post-hoc type checking of the result
core/attacker  Dolev-Yao closure (`analyze`) and term synthesis (`can_synthesize`)
core/run     one instantiated role: agent, peer, scoped variables, fresh atoms
core/ordering the message-event poset, kept acyclic
core/replay  an independent forward re-execution of a search state
core/claims  the claim predicates (`Secret`, `Alive`, `Weakagree`, `Niagree`, `Nisynch`)
core/search  the claim-driven search, the bounds and the `Verifier`
core/trace   the trace document: the *only* interface to `viz/`
```

Dependencies point strictly downwards. `viz/` never imports `core/`; it reads
trace JSON and nothing else. `tools/independent_replay.py` goes one step further
and rebuilds a trace from `core/terms`, `core/unify` and `core/attacker` alone,
with no `replay`, `search` or `claims` code in sight.

One search serves a `(role, partner)` group
------------------------------------------

### What is grouped

`Searcher.verify_role` splits a role's claims by their **resolved partner role**
(`search._group`, using `claims.resolve_partner`). Claims with no partner
(`Secret(t)`, `Alive`) get the key `None`, so they form one group of their own;
claims naming the same partner role share a group. For `ns.spdl` that is:

| group | claims |
| --- | --- |
| partner `None` | `I1` (`Secret ni`), `I2` (`Secret nr`) |
| partner `I` | `I3` (`Niagree`), `I4` (`Nisynch`) |
| partner `None` | `R1` (`Secret ni`), `R2` (`Secret nr`) |
| partner `I` | `R3` (`Niagree`), `R4` (`Nisynch`) |

### What is shared

For one group the following are computed **once**:

* **the start state** — claimant role, its default agent, and each peer in
  `Searcher.peer_pool(agent)`, i.e. the honest agents other than the claimant;
* **the state space** — `_initial_state`, then `_ready` / `_advance` /
  `_resolve_recv`. None of these look at a claim, so the reachable states are
  literally the same objects a per-claim search would visit;
* **the memo of visited states** (`_canonical`), so no state is explored twice;
* **the substitution, the poset and the attacker's knowledge** carried along each
  branch;
* **the deadline and the `max_states` budget**, which is why the reported
  `states` count is identical for every claim of a group.

### What is *not* shared

The violation condition. Each claim has its own predicate, and
`Searcher._collect` evaluates **every** claim of the group against **every**
terminal trace:

```python
for claim in claims:
    if claim.label in found:
        continue
    verdict = claim_semantics.evaluate(
        claim, claimant, state.runs, state.sigma, partner,
        lambda term: replayed.knows(self.attacker, term),
    )
    if not verdict.satisfied:
        found[claim.label] = self._build_trace(claim, state, replayed, verdict.violation)
```

`claims` is the group's goal set; `partner` is the group's partner role;
`claimant`, `state.runs`, `state.sigma` and `replayed.knows` are the shared
search state. The loop variable `claim` is the only thing that differs, so two
claims cannot influence each other's verdict, and the trace recorded for each is
built from that claim alone (`_build_trace(claim, ...)` sets `trace.claim`,
`trace.claim_kind` and the violation text from `claim`).

### Why one search is enough

Sharing is sound because the goal predicate is *not part of the search*. The
search enumerates terminal traces; it never asks "is this a counterexample?" until
the trace is complete and has been re-verified by `core/replay`. Whether a
terminal trace is interesting is decided afterwards, by a pure function of
`(claim, claimant run, all runs, substitution, partner, attacker knowledge)`.
Nothing in that tuple depends on which other claims are being checked.

The one place sharing *could* go wrong is the early exit in `_search_group`:

```python
if reason or len(found) == len(claims):
    return states, found, reason
```

It fires only when (a) a budget stopped the search — in which case every claim in
the group is reported `UNKNOWN` with the same `reason`, which is the correct
answer for all of them — or (b) **every** claim in the group already has a
counterexample, so nothing is left to find. It never fires when a *subset* of the
claims is falsified; a claim that survives keeps the search running until the
space is exhausted, and only then becomes `VERIFIED`.

### The invariant that proves it

> For any claim `c` in a group `G`: running the search for `G` and reading off
> `c`'s verdict gives the same answer as running a search for `{c}` alone.

`tests/integration/test_shared_search.py` checks this for every bundled example
in three ways: full shared run vs. `share=False`, each claim alone vs. its entry
in the shared run (status *and* trace steps), and the state count being constant
across a group. `protoverify verify --no-share` exposes the per-claim mode from
the command line:

```
$ protoverify verify examples/ns.spdl            # shared
R     R1     Secret   FALSIFIED  1995    0.95
R     R2     Secret   FALSIFIED  1995    0.95
$ protoverify verify examples/ns.spdl --no-share # one search per claim
R     R1     Secret   FALSIFIED  1995    0.95
R     R2     Secret   FALSIFIED  1995    0.97
```

Identical verdicts, identical state counts, and the only visible difference is
the wall-clock time.

The performance argument
------------------------

Sharing is not just tidiness: it is the difference between a search that is
practical and one that is not. A group of four claims verified separately walks
the same state space four times; sharing walks it once and evaluates four cheap
predicates per terminal trace. The reported `states` column is therefore a
property of the *group*, not of the individual claim, and is shown once per
claim so the table stays rectangular.

Bounds
------

`Bounds` (`max_runs`, `max_trace_len`, `timeout`, `max_states`,
`max_runs_per_role`) bounds the shared search. Exhausting the space within them
is what `VERIFIED` means; hitting a budget yields `UNKNOWN` with the reason. The
known incompletenesses are listed in [`limitations.md`](limitations.md).