# PROGRESS

Review round 2 log. Round 1 is below under "Review round 1".
Evidence is command output, not assertion.

---

# Review round 2

## BLOCKER: the specification document is not in the workspace

Tasks 1, 2 and 5 of round 2 cannot be done. The brief refers to "the spec
(section 10 and 10.7)", "the spec's exact files" and "spec 5.1", but:

```
$ Get-ChildItem -Recurse -Include *.spdl    # whole workspace
protoverify\examples\challenge_response.spdl   <- ours
protoverify\examples\challenge_response_no_id.spdl
protoverify\examples\ns.spdl
protoverify\examples\nsl.spdl
protoverify\examples\replay.spdl
protoverify\examples\yahalom.spdl
(no spec files, no .pdf, no .tex, no specification document)

$ git log --all --oneline
bb4bafd first commit                       # the only commit; never contained a spec

$ Get-ChildItem D:\ -Recurse -Include *.spdl -Depth 6   # nothing outside protoverify
```

The engine has only ever seen *references* to the spec (in the original brief),
never the document. Guessing the contents of `cr`, `cr_noid`, `replay` and
`yahalom` would produce verdicts about protocols that may not be the ones in
section 10, so I have not touched the example files or
`expected_reference.json`.

What I have done instead is answer, from evidence, every part of the round that
does not need the document.

## Issue 6 (round 2, task 6) — "no verdict changed", and the NSL R1 question

### The NSL R1 claim

**NSL R1 was `VERIFIED` in the engine's output at every point in its history.
It was never `FALSIFIED` by the engine.** It was `FALSIFIED` only in my earlier
prose report, which was simply wrong.

Proof, by running the *original* committed code (commit `bb4bafd`, extracted to a
git worktree) with the original `expected.json` still in place:

```
$ git worktree add --detach out\orig HEAD
$ PYTHONPATH=out\orig\src python -m protoverify.cli --no-color \
      verify out\orig\examples\nsl.spdl
protocol nsl

role  claim  kind     status    states  seconds
----  -----  -------  --------  ------  -------
I     I1     Secret   VERIFIED  76      0.06
I     I2     Secret   VERIFIED  76      0.06
I     I3     Niagree  VERIFIED  76      0.06
I     I4     Nisynch  VERIFIED  76      0.06
R     R1     Secret   VERIFIED  654     0.33
R     R2     Secret   VERIFIED  654     0.33
R     R3     Niagree  VERIFIED  654     0.33
R     R4     Nisynch  VERIFIED  654     0.33

8 claim(s): 8 verified
```

And the `expected.json` committed in that same commit already said
`"nsl": {"R1": "VERIFIED", ...}`. The mistake was in my report text, never in
the engine or its recorded output.

### The diff

```
$ git show HEAD:examples/expected.json > out/diff/old_expected.json
$ git diff --no-index --unified=0 out/diff/old_expected.json \
                            examples/regression_snapshot.json
-﻿{
+{
```

That is the *entire* diff: a UTF-8 BOM that PowerShell's redirect added to the
extracted copy. Every verdict in the original `expected.json` is byte-identical
to today's snapshot, across both rounds and including this round's two bug fixes.

Running the whole original example set through the original engine reproduces the
same 38 verdicts as today. Only the **state counts** moved (e.g. `ns` role I
308 → 488, role R 831 → 1995), because the attacker-constant change of round 1
widened the candidate set. More states explored, same verdicts — which is the
expected shape for a strictly larger search space.

## Issue 7 (round 2, task 3) — `k(A,B)` did not unify with `k(B,A)`

**Engine bug, found and fixed.** See DECISIONS.md D12.

```
before: solve({na}k(k(A,B)), {nb}k(k(B,A))) -> None
after:  solve({na}k(k(A,B)), {nb}k(k(B,A))) -> {'r1::na': Var('r2::nb')}
```

This is the template pair a `send` and its partner `recv` have in any protocol
written symmetrically, so the search could not match an honest send with its
partner's receive — losing traces, and a lost trace can turn a real attack into a
`VERIFIED`. The first attempt (canonicalising in `SharedKey.__post_init__`) was
wrong and was caught by its own test; the fix puts symmetry in
`unify._match_shared`.

`test_key_terms_unify_positionally` asserted the assumption being removed and was
replaced by three tests of the real contract.

## Issue 8 (round 2, task 3) — the claim hierarchy in the falsified direction

**Invariant added and checked.** `Niagree` is defined to include `Weakagree`,
and `Weakagree` to include `Alive`, so a falsified `Alive` (the claimant
completed with no partner run at all) forces all three stronger claims to be
falsified as well. Reporting `Alive FALSIFIED` next to `Nisynch VERIFIED` would
be self-contradictory.

`tests/integration/test_hierarchy.py` now checks this:

* per trace, in `hierarchy_holds`: if there is no partner run, then `Weakagree`,
  `Niagree` and `Nisynch` must all be unsatisfied;
* per role, in `test_reported_verdicts_never_contradict_the_hierarchy`: no
  bundled example produces an incoherent verdict set;
* `test_the_coherence_check_can_actually_fail` asserts the check raises on
  `{"Alive": "FALSIFIED", "Nisynch": "VERIFIED"}`, so it cannot rot into a no-op.

The hierarchy check does **not** fire on the current examples: `cr_noid` reports
`A2 Alive VERIFIED` next to `A3 Niagree VERIFIED` and `A4 Nisynch VERIFIED`,
which is coherent. The disagreement there is about whether `Alive` *should* be
`VERIFIED`, not about a contradiction — and that needs the spec's `cr_noid` to
settle.

## Issue 9 — `analyze` did not saturate (pre-existing soundness bug)

**Found by the property suite, proven pre-existing, fixed.** See DECISIONS.md D13.

```
term = Tuple((Sign(Sk(A), Sk(A)), AsymEnc(A, Pk(A))))   # A compromised

before:  analyze([term]) -> 4 terms, Atom(A) absent
         analyze(once)   -> 5 terms, Atom(A) present     # IDEMPOTENT: False
after:   analyze([term]) -> 5 terms, Atom(A) present
         analyze(once)   -> 5 terms, Atom(A) present     # IDEMPOTENT: True
```

The same probe against commit `bb4bafd` gives `IDEMPOTENT: False`, so this is not
caused by any round-1 or round-2 change. It violates the documented contract
that `can_synthesize` is called on an `analyze`-closed set, which could yield a
false `VERIFIED`. Fixed by iterating to a fixed point.

The lesson is recorded: a green property run backed by a *cold* hypothesis
database is not evidence. The direct probe is.

## Round 2 status

```
pytest -q              -> 340 passed, 2 skipped (manim; ffmpeg/mp4)
mypy --strict src      -> Success: no issues found in 28 source files
ruff check .           -> All checks passed!
verdicts changed       -> none, on all 38 claims of the 6 bundled examples
```

---

# Review round 1

## Issue 1 — is NSL `R1` really falsified?

**Verdict: the premise is wrong. NSL `R1` is `VERIFIED`.**

Evidence:

```
$ protoverify --no-color verify examples/nsl.spdl --claim R1 --max-runs 4
protocol nsl

role  claim  kind    status    states  seconds
----  -----  ------  --------  ------  -------
R     R1     Secret  VERIFIED  654     0.27
```

```
$ protoverify --no-color verify examples/nsl.spdl        # whole protocol
R     R1     Secret   VERIFIED  654     0.38
... 8 claim(s): 8 verified
```

The claim that NSL `R1` was falsified came from my own previous final report,
which was simply wrong. The correct asymmetry is:

| file | R1 `Secret(ni)` | why |
| --- | --- | --- |
| `ns.spdl` | FALSIFIED | Alice runs with Mallory, message 1 is `{I,ni}pk(M)`, Mallory decrypts it |
| `nsl.spdl` | VERIFIED | Alice can only run with Bob or a partner that binds her in message 2, so Mallory never sees a plaintext |

NS `R1` *is* falsified, and the trace is legitimate — confirmed with an
independent replayer (below). See `docs/claims.md`, section
"Secrecy of `ni` for the responder".

### Bug found and fixed: `attacker_new` reported sealed nonces

`tools/independent_replay.py` (new, uses only `terms.py`/`unify.py`/`attacker.py`)
failed on the very first NS trace:

```
FAIL out\golden\ns_R1.json: step 3: recorded attacker_new=[] but recomputation gives ['nr#1']
```

Step 3 is Bob's message `{ni#2,nr#1}pk(I)`, addressed to Alice. Mallory must not
learn `nr#1` from it. The cause: `core/replay.py` computed `attacker_new` from
`terms.leaves()`, which descends into the plaintext of a ciphertext. The fix
computes it as the **difference of the Dolev-Yao closures** before and after the
message (`replay._newly_learned`), which is what the attacker actually derives.

After the fix:

```
  step  1 send              I->M {I,ni#2}pk(M)      learned=['ni#2']
  step  2 attacker_inject   M->R {I,ni#2}pk(R)     learned=[]
  step  3 send              R->I {ni#2,nr#1}pk(I)  learned=[]
  step  4 attacker_forward  M->I {ni#2,nr#1}pk(I)  learned=[]
  step  5 send              I->M {nr#1}pk(M)       learned=['nr#1']
  step  6 attacker_inject   M->R {nr#1}pk(R)      learned=[]
OK: every step is justified by terms/unify/attacker alone
```

This changed **no verdict**: `attacker_new` feeds only the trace document, never
claim evaluation. All examples were re-run; verdicts are byte-identical to the
pre-fix snapshot.

Regression tests: `tests/unit/test_attacker_new.py` (6 tests) and
`tests/integration/test_independent_replay.py` (5 tests), the latter running the
independent replayer over every falsifying trace of every example.

### New tooling

| file | purpose |
| --- | --- |
| `tools/independent_replay.py` | re-derives a trace from `terms`/`unify`/`attacker` only |
| `tools/search_stats.py` | branch points, dead ends, options per label |
| `tools/why_recv3.py` | which delivery options are open at a given receive event |

---

## Issue 2 — `expected.json` is circular

**Fixed.** Two files with two jobs:

| file | origin | role |
| --- | --- | --- |
| `examples/expected_reference.json` | hand written from spec §10, Lowe 1996 and first-principles key-sealing arguments | **the oracle** |
| `examples/regression_snapshot.json` | `tools/make_snapshot.py`, from the engine's own output | change detector only |

`tools/make_expected.py` was renamed to `tools/make_snapshot.py` and now writes
`regression_snapshot.json`; `examples/expected.json` was deleted.
`tests/integration/test_reference.py` compares against the oracle,
`tests/integration/test_regression.py` against the snapshot, and
`test_examples.py` no longer holds a verdict table at all.

The reference-vs-engine-vs-snapshot table (`pytest -s tests/integration/test_reference.py`):

```
protocol                 claim  reference  engine     snapshot   ok
-------------------------------------------------------------------
challenge_response       A1     VERIFIED   VERIFIED   VERIFIED
challenge_response       A2     VERIFIED   VERIFIED   VERIFIED
challenge_response       A3     VERIFIED   VERIFIED   VERIFIED
challenge_response       A4     VERIFIED   VERIFIED   VERIFIED
challenge_response       B1     VERIFIED   VERIFIED   VERIFIED
challenge_response       B2     VERIFIED   VERIFIED   VERIFIED
challenge_response_no_id A1     FALSIFIED  FALSIFIED  FALSIFIED
challenge_response_no_id A2     VERIFIED   VERIFIED   VERIFIED
challenge_response_no_id A3     VERIFIED   VERIFIED   VERIFIED
challenge_response_no_id A4     VERIFIED   VERIFIED   VERIFIED
challenge_response_no_id B1     VERIFIED   VERIFIED   VERIFIED
challenge_response_no_id B2     VERIFIED   VERIFIED   VERIFIED
ns                       I1     VERIFIED   VERIFIED   VERIFIED
ns                       I2     VERIFIED   VERIFIED   VERIFIED
ns                       I3     VERIFIED   VERIFIED   VERIFIED
ns                       I4     VERIFIED   VERIFIED   VERIFIED
ns                       R1     FALSIFIED  FALSIFIED  FALSIFIED
ns                       R2     FALSIFIED  FALSIFIED  FALSIFIED
ns                       R3     FALSIFIED  FALSIFIED  FALSIFIED
ns                       R4     FALSIFIED  FALSIFIED  FALSIFIED
nsl                      I1..I4 VERIFIED   VERIFIED   VERIFIED
nsl                      R1..R4 VERIFIED   VERIFIED   VERIFIED
replay                   A1     FALSIFIED  FALSIFIED  FALSIFIED
replay                   A2     FALSIFIED  FALSIFIED  FALSIFIED
replay                   B1     FALSIFIED  FALSIFIED  FALSIFIED
replay                   B2     FALSIFIED  FALSIFIED  FALSIFIED
yahalom                  A1..A3 VERIFIED   VERIFIED   VERIFIED
yahalom                  B1..B2 VERIFIED   VERIFIED   VERIFIED
```

**Zero disagreements between reference and engine.** Three disagreements between
the reference and the *review brief's* skeleton are analysed paragraph by
paragraph in DECISIONS.md D6 (`cr` responder claims), D7 (`cr_noid` initiator
agreement claims) and D8 (`replay` all four claims). Each says why the engine
and reference agree with each other and disagree with the brief, and each is
raised as a question in the final report rather than resolved by editing the
reference file.

---

## Issue 3 — the attacker has no constants of its own

**Fixed.** `attacker.ATTACKER_CONSTANTS = {"Nonce": "nM", "Key": "kM", "Data": "dM"}`
is part of `initial()`, and `Searcher._candidates` offers the matching constant
for a `Nonce`/`Key`/`Data` receive variable *before* the replayable atoms. A
`Nonce` variable is not offered the attacker's key (atoms are polymorphic, so the
type filter in `search._accepts` is stricter on purpose).

**Verdicts that changed: none.** Re-ran every example after the change:

```
challenge_response         {'A1': 'VERIFIED', ... 'B2': 'VERIFIED'}   (unchanged)
challenge_response_no_id  {'A1': 'FALSIFIED', ... 'B2': 'VERIFIED'}  (unchanged)
ns                         {'I1': 'VERIFIED', ... 'R4': 'FALSIFIED'}  (unchanged)
nsl                        all eight 'VERIFIED'                       (unchanged)
replay                     all four 'FALSIFIED'                       (unchanged)
yahalom                    all five 'VERIFIED'                        (unchanged)
```

Scanning every trace the engine produces for `nM`/`kM`/`dM` finds **0 hits**. The
reason is structural and is argued in DECISIONS.md D6: in every bundled protocol
the receive an honest run must satisfy is sealed under `k(A,B)`, a key between
two honest agents that the attacker's own values cannot help produce.

The capability itself is real and tested — `test_a_nonce_receive_can_be_answered_
with_the_attacker_nonce` shows the attacker delivering `nM` into a bare-nonce
receive, a path that did not exist before. Soundness guards are also tested: an
attacker constant can never unify with a run's fresh atom, and the attacker
cannot build `ni#1` before a run sends it.

---

## Issue 4 — "one search serves all claims of a role"

**Verified sound, documented, and now checked.**

* `docs/architecture.md` (new) states exactly what is grouped, what is shared, what
  is *not* shared, why one search is enough, and the invariant that proves it.
* `tests/integration/test_shared_search.py` (new, 14 tests) compares, for all six
  examples: shared vs. `share=False`; each claim alone vs. its entry in the shared
  run, including the trace step list; and the constancy of the state count within
  a group. All pass — no verdict, trace or state count differs.
* `protoverify verify --no-share` added to the CLI:

```
$ protoverify verify examples/ns.spdl
R     R1     Secret   FALSIFIED  1995    0.95
$ protoverify verify examples/ns.spdl --no-share
R     R1     Secret   FALSIFIED  1995    0.95
```

---

## Issue 5 — Manim was never actually rendered

**Added.** `tools/check_manim.sh` and `tools/check_manim.ps1` check
`import manim`, `ffmpeg -version`, and a real `-ql` render of `SequenceScene`
from `examples/golden/ns_R2.trace.json`, and report which of the three failed.
The README section "Rendering with Manim (optional)" now gives the exact install
steps and system packages for Linux, macOS and Windows.

`viz/export.py` now distinguishes `_manim_missing()` from `_ffmpeg_missing()` —
they have different fixes — and each names the install command per platform.
The matplotlib fallback is untouched and tested.

Running the script here:

```
$ powershell -ExecutionPolicy Bypass -File tools\check_manim.ps1
1/3  python -c 'import manim'
  [FAIL] manim is not importable
2/3  ffmpeg -version
  [FAIL] ffmpeg is not on PATH
3/3  render SequenceScene at -ql
  [FAIL] manim produced no MP4 under out
RESULT: the Manim back-end could not be exercised here.
```

Manim still cannot be installed on this machine, so `manim_scenes.py` remains
compile-checked and `mypy --strict`-clean but never rendered. Its test is marked
`@pytest.mark.manim` and skips.

---

## Standing status after every issue

```
pytest -q              -> 330 passed, 2 skipped (manim; ffmpeg/mp4)
mypy --strict src      -> Success: no issues found in 28 source files
ruff check .           -> All checks passed!
```
```