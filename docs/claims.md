Claim semantics
================

Throughout, a **trace** is a consistent execution of a set of role instances in
which

* every `send` of a run produced exactly one message term (the substitution makes
  it ground);
* every `recv` of a run received exactly one message term;
* the messages respect the causal order (a message used by a `recv` was sent
  before it by *someone*: another honest run, or the attacker);
* the attacker never learns `t` from anything but the Dolev-Yao rules.

Write `r` for the **claimant run** — the single run of the role that wrote the
claim — with agent `r.agent` and peer `r.peer`. Write `p` for a *partner run*: a
run of the claim's partner role `P`.

The honest-run condition
------------------------

Every claim is evaluated only over traces in which the claimant run is entirely
honest: `r.agent` and `r.peer` are both non-compromised. A session that
deliberately talks to the attacker is a different question, and is answered by
the attacker's own role runs rather than by the partner's agreement claims.

The condition applies to the **claimant's** run only. Other runs in the same
trace may involve the attacker; see
[Secrecy of `ni` for the responder](#secrecy-of-ni-for-the-responder) for a
worked example where exactly that distinction decides a verdict.

Secret(t)
----------

> In no consistent trace in which the claimant run is entirely honest does the
> attacker know `t` at the point where that run finishes.

`t` is the claim's term after substituting the trace's assignment. The attacker
"knows" a term when the term can be built from the decomposition closure of its
knowledge at that point (`can_synthesize` over an `analyze`-closed set).

`Secret` is falsified as soon as **one** trace exists in which the attacker can
build `t`. The returned trace shows exactly when the leak happened.

Alive(P)
--------

> If `r` completes, some run of role `P` executed.

`r` completes when all of its events have fired. `Alive` is falsified by any
trace in which `r` completes and no run of `P` exists at all.

Weakagree(P)
------------

> A run `p` of role `P` exists with `p.agent = r.peer` and `p.peer = r.agent`:
> the two runs really are partners, in both directions.

No message is compared. `Weakagree` is falsified when the runs that do exist are
not mutually paired — for example when the partner run was played by the
attacker, or by an agent nobody expected.

Niagree(P)
----------

> `Weakagree(P)` holds and every message of `r` matches the message of `p` at the
> same point of the protocol, **up to the choice of keys**.

The comparison is non-injective in the key material only: `data_view` erases
`pk`, `sk` and `k(...)` before comparing. So `{I,na}pk(R)` and `{I,na}pk(M)` are
*the same data* — Bob cannot tell from the payload that Mallory re-encrypted it,
and `Niagree` does not complain about the re-encryption. It does complain about
a payload that differs.

Each role's message events are compared pairwise by position: labels must
match, directions must be complementary (`send` against `recv`) and the data
views must be equal.

Nisynch(P)
----------

> `Niagree(P)` holds and the concrete messages are **identical** term by term,
> with an injective correspondence.

This is `Niagree` plus `injectivity = True` in the comparison: no key erasure.
Lowe's man-in-the-middle breaks `Nisynch` precisely because
`{I,na}pk(R)` ≠ `{I,na}pk(M)` even though the data agrees.

The hierarchy
-------------

```
        Nisynch
           |
        Niagree
           |
       Weakagree
           |
         Alive
```

Each step is a strengthening of the one above it:

* `Nisynch ⇒ Niagree` — identical messages have identical data views;
* `Niagree ⇒ Weakagree` — the mutual peer/agent pairing is required by both;
* `Weakagree ⇒ Alive` — a partner run of role `P` existing *is* `Alive`.

`tests/integration/test_hierarchy.py` evaluates the four predicates on **every**
concrete trace the search visits for every bundled example and asserts the chain
empirically, not just by construction.

What is reported
----------------

| outcome | meaning |
| --- | --- |
| `FALSIFIED` | a trace exists that breaks the claim; it is written to JSON |
| `VERIFIED` | the whole bounded search space was exhausted with no counterexample |
| `UNKNOWN` | a budget (timeout, state count) stopped the search first; `reason` says which |

`VERIFIED` is always relative to the bounds: `max_runs`, `max_len`, `timeout`,
`max_states` and one run per role. See [`limitations.md`](limitations.md).

Secrecy of `ni` for the responder
---------------------------------

*Why does `claim_R1(R, Secret, ni)` have different verdicts in `ns.spdl` and
`nsl.spdl`, when both are about the "initiator's nonce" and the responder never
sends it?*

Short answer: `R1` is about **Alice's nonce**, and Alice is free to start a
session *with the attacker*. The honest-run condition constrains the **claimant's**
run (Bob's), not every run in the trace. Mallory only has to get hold of `na` in
a *different* run to break Bob's claim.

### The NS counterexample (Lowe's man in the middle)

`protoverify verify examples/ns.spdl --claim R1` — **FALSIFIED**, 831 states, 0.3 s.
The trace, with the rule used at each step:

| # | type | message | rule | what the attacker does |
| --- | --- | --- | --- | --- |
| 1 | `send` | `{I,ni#2}pk(M)` | **send** | Alice's initiator run has peer `M`, so message 1 is encrypted **for Mallory**. She holds `sk(M)`, the **decrypt** rule fires and she learns `ni#2`. |
| 2 | `attacker_inject` | `{I,ni#2}pk(R)` | **forge** | Mallory holds `Atom I`, `Atom ni#2` and `pk(R)`, so the **encrypt** (composition) rule builds `{I,ni#2}pk(R)`. Bob's `recv_1` takes it and binds `ni := ni#2`. |
| 3 | `send` | `{ni#2,nr#1}pk(I)` | **send** | Bob's message 2 is addressed to Alice, so Mallory can only relay it: the **decrypt** rule does not fire and she learns nothing here. |
| 4 | `attacker_forward` | `{ni#2,nr#1}pk(I)` | **forward** | Alice's `recv_2` accepts the relayed ciphertext and Alice's run completes. |
| 5 | `send` | `{nr#1}pk(M)` | **send** | Alice's message 3 is encrypted for Mallory; the **decrypt** rule fires and she learns `nr#1`. |
| 6 | `attacker_inject` | `{nr#1}pk(R)` | **forge** | With `nr#1` and `pk(R)` she forges Bob's `{nr}pk(R)`. Bob's `recv_3` takes it and Bob's run completes. |

The violated claim is *"the attacker learns ni#2, which R claimed to be secret"* —
`ni#2` is exactly the value Bob bound to his `ni` at step 2.

Every step is re-checked by `tools/independent_replay.py`, which rebuilds the
trace using only `core/terms`, `core/unify` and `core/attacker` — no search, no
claims, no `core/replay`:

```
$ python tools/independent_replay.py out/golden/ns_R1.json examples/ns.spdl
trace ns_R1.json: ns/R1
  step  1 send              I->M {I,ni#2}pk(M)      learned=['ni#2']
  step  2 attacker_inject   M->R {I,ni#2}pk(R)     learned=[]
  step  3 send              R->I {ni#2,nr#1}pk(I)  learned=[]
  step  4 attacker_forward  M->I {ni#2,nr#1}pk(I)  learned=[]
  step  5 send              I->M {nr#1}pk(M)       learned=['nr#1']
  step  6 attacker_inject   M->R {nr#1}pk(R)      learned=[]
  verdict: attacker can build ni#2 = True
OK: every step is justified by terms/unify/attacker alone
```

`tests/integration/test_independent_replay.py` runs this tool over *every*
falsifying trace of *every* example, so the check is permanent, not a one-off.

### Why NSL does not have this trace

`nsl.spdl` is identical except for message 2, `{R,ni,nr}pk(I)`. The decisive
question is: **in which states can Mallory forge `{nr#1}pk(R)` for Bob's
`recv_3`?** `tools/why_recv3.py` enumerates every reachable state in which Bob's
`recv_3` is the next event and reports which delivery options are open:

```
$ python tools/why_recv3.py examples/nsl.spdl 3
nsl.spdl: recv_3 reached in 352 states (states explored: 536)
     R:R->I, I:I->R                  2
     attacker_learned={I,ni#2}pk(R),{R,ni#2,nr#1}pk(I),{nr#1}pk(R) 2
     sigma r1::ni = ni#2             2
     sigma r1::nr = nr#1             2
     sigma r2::ni = ni#2             2
     sigma r2::nr = nr#1             2
  attacker_can_build_{nr#1}pk(R)     2
  attacker_option_open               2
  match_option_open                  13
  spontaneous_option_open            3
  states                             318

$ python tools/why_recv3.py examples/ns.spdl 3
ns.spdl: recv_3 reached in 1580 states (states explored: 2468)
     R:R->I, I:I->M                   1        <-- Alice talked to Mallory
     R:R->I, I:I->R                   2
     ...
     attacker_learned=(I,ni#2),ni#2,nr#1,{I,ni#2}pk(M),... 1
  attacker_can_build_{nr#1}pk(R)     6
```

In NS there are 6 such states, one of which has Alice's run with peer `M`; its
knowledge contains the bare values `ni#2` and `nr#1`. In NSL there are only 2,
**both** with `I:I->R` — Alice's run is with Bob, not with Mallory — and Mallory's
knowledge contains only ciphertexts: `{I,ni#2}pk(R)`, `{R,ni#2,nr#1}pk(I)`,
`{nr#1}pk(R)`. She can *relay* the last one, but she cannot read `ni#2` out of any
of them, so she never learns Alice's nonce.

That is exactly the property NSL restores: binding the responder's identity into
message 2 means the relay Bob needs can no longer be delivered to an
Alice-with-Mallory run, so her message 3 — the only place `nr` could leak — is
never sent to Mallory.

Search statistics for the whole protocol:

```
$ python tools/search_stats.py nsl
nsl/R1  Secret    VERIFIED  states=654     0.25s
nsl/R2  Secret    VERIFIED  states=654     0.25s
nsl/R3  Niagree   VERIFIED  states=654     0.25s
nsl/R4  Nisynch   VERIFIED  states=654     0.25s

  attacker_options           213
  dead_ends                  470
  dead_recv_label_2          99
  dead_recv_label_3          371
  new_run_options            0
  recv_branch_points         568
  recv_label_1               30
  recv_label_2               132
  recv_label_3               406
```

* `recv_3` (`{nr}pk(R)`) is reached 406 times and dies 371 times: the attacker
  option is open in only 6 of them, and the two states that survive have Alice
  talking to Bob, so `ni` stays secret.
* `recv_2` (`{R,ni,nr}pk(I)`) is reached 132 times and dies 99 times. The
  `R`/`I` identity inside the tuple rejects every Alice-with-Mallory run:
  `new_run_options = 0` means **no** role instance, agent or peer assignment can
  produce a `send_2` that satisfies a receive of an Alice-with-Mallory run.
* Because `nr` never leaks there is no `Secret(nr)` counterexample, and because no
  relay reaches Alice there is no `Niagree`/`Nisynch` counterexample either. The
  space is exhausted at 654 states, well inside `max_runs=4` and `max_len=20`.

### Does the asymmetry also apply to `I1`/`I2`?

Yes — and that is the point. `claim_I1(I, Secret, ni)` and
`claim_I2(I, Secret, nr)` are evaluated over traces where **Alice's** run is
entirely honest (agent *and* peer honest). A trace where Alice deliberately starts
a session with Mallory is excluded from *her own* claims, which is exactly why
`I1`/`I2` are `VERIFIED` in NS while `R1` is `FALSIFIED` in the same file. The two
conditions are mirror images:

| claim | claimant run must be honest | Mallory may talk to the other party in a *different* run |
| --- | --- | --- |
| `I1`/`I2` (Alice) | yes — Alice's peer must be honest | irrelevant |
| `R1` (Bob) | yes — Bob's peer must be honest | **yes** — Alice may run with Mallory, which leaks `na` |

Worked example: Lowe's attack on NS
-----------------------------------

```
 1 send      I -> M   {I,ni#2}pk(M)        Alice believes Mallory is her peer
 2 attacker  M -> R   {I,ni#2}pk(R)        Mallory re-encrypts for Bob
 3 send      R -> I   {ni#2,nr#1}pk(I)     Bob answers, believing Alice asked
 4 attacker  M -> I   {ni#2,nr#1}pk(I)     Mallory relays it unchanged
 5 send      I -> M   {nr#1}pk(M)          Mallory learns Bob's nonce
 6 attacker  M -> R   {nr#1}pk(R)          Mallory replays it to Bob
```

Bob's run has `peer = I`, the Alice run has `peer = M`:

* `Weakagree(I)`: `p.peer` must be Bob's agent, but the Alice run talks to `M`
  → **falsified**.
* `Niagree(I)`: the payloads agree, but the pairing does not → **falsified**.
* `Nisynch(I)`: `{I,na}pk(R)` ≠ `{I,na}pk(M)` → **falsified**.
* `Secret(ni)`: the attacker decrypted `ni#2` in step 1 → **falsified**.
* `Secret(nr)`: the attacker decrypted `nr#1` in step 5 → **falsified**.

Alice's own claims survive because her run never completes in this trace, and
because her peer is the attacker, which the honest-run condition excludes.

In NSL the only change is `{R,ni,nr}pk(I)` in message 2: the relay no longer
matches, so Bob's run can no longer be completed by the attacker and every claim
holds.