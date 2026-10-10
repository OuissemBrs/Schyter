# Claim semantics

Throughout, a **trace** is a consistent execution of a set of role instances in
which

* every `send` of a run produced exactly one message term (the substitution makes
  it ground);
* every `recv` of a run received exactly one message term;
* the messages respect the causal order (a message used by a `recv` was sent
  before it by *someone*: another honest run, or the attacker);
* the attacker never learns `t` from anything but the Dolev–Yao rules.

Write `r` for the **claimant run** — the single run of the role that wrote the
claim — with agent `r.agent` and peer `r.peer`. Write `p` for a *partner run*: a
run of the claim's partner role `P`.

## The honest-run condition

Every claim is evaluated only over traces in which the claimant run is entirely
honest: `r.agent` and `r.peer` are both non-compromised. A session that
deliberately talks to the attacker is a different question, and is answered by
the attacker's own role runs rather than by the partner's agreement claims.

## `Secret(t)`

> In no consistent trace in which the claimant run is entirely honest does the
> attacker know `t` at the point where that run finishes.

`t` is the claim's term after substituting the trace's assignment. The attacker
"knows" a term when the term can be built from the decomposition closure of its
knowledge at that point (`can_synthesize` over an `analyze`-closed set).

`Secret` is falsified as soon as **one** trace exists in which the attacker can
build `t`. The returned trace shows exactly when the leak happened.

## `Alive(P)`

> If `r` completes, some run of role `P` executed.

`r` completes when all of its events have fired. `Alive` is falsified by any
trace in which `r` completes and no run of `P` exists at all.

## `Weakagree(P)`

> A run `p` of role `P` exists with `p.agent = r.peer` and `p.peer = r.agent`:
> the two runs really are partners, in both directions.

No message is compared. `Weakagree` is falsified when the runs that do exist are
not mutually paired — for example when the partner run was played by the
attacker, or by an agent nobody expected.

## `Niagree(P)`

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

## `Nisynch(P)`

> `Niagree(P)` holds and the concrete messages are **identical** term by term,
> with an injective correspondence.

This is `Niagree` plus `injectivity = True` in the comparison: no key erasure.
Lowe's man-in-the-middle breaks `Nisynch` precisely because
`{I,na}pk(R)` ≠ `{I,na}pk(M)` even though the data agrees.

## The hierarchy

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

## What is reported

| outcome | meaning |
| --- | --- |
| `FALSIFIED` | a trace exists that breaks the claim; it is written to JSON |
| `VERIFIED` | the whole bounded search space was exhausted with no counterexample |
| `UNKNOWN` | a budget (timeout, state count) stopped the search first; `reason` says which |

`VERIFIED` is always relative to the bounds: `max_runs`, `max_len`, `timeout`,
`max_states` and one run per role. See [`limitations.md`](limitations.md).

## Worked example: Lowe's attack on NS

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

Alice's own claims survive because her run never completes in this trace, and
because her peer is the attacker, which the honest-run condition excludes.

In NSL the only change is `{R,ni,nr}pk(I)` in message 2: the relay no longer
matches, so Bob's run can no longer be completed by the attacker and every claim
holds.