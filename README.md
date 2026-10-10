# ProtoVerify

A **bounded, Scyther-style symbolic security protocol verifier** written in pure
Python, with two animation back-ends for the attacks it finds.

```
   ns.spdl  ──parse──▶  AST  ──check──▶  run/search  ──▶  VERIFIED | FALSIFIED | UNKNOWN
                                                               │
                                                               ▼
                                                         trace.json
                                                       ╱          ╲
                                            matplotlib            Manim CE
                                       sequence / event graph     3 scenes
```

* **Never guesses.** If the engine cannot decide, it answers `UNKNOWN` and says
  why (timeout, state budget, …). A `VERIFIED` always means *no counterexample
  was found within the stated bounds*, never "proved secure".
* **Renderers never call the engine.** They read a trace JSON document that is
  validated on load (see [`docs/trace-schema.md`](docs/trace-schema.md)).

---

## Installation

```bash
python -m pip install -e .            # engine only (standard library)
python -m pip install -e ".[viz]"     # + matplotlib / networkx / Pillow
python -m pip install -e ".[manim]"   # + Manim Community Edition
python -m pip install -e ".[dev]"     # + pytest / hypothesis / mypy / ruff
```

Requires **Python 3.11+**. The engine itself has no third-party dependencies.

### System dependencies for Manim and MP4

| Platform | ffmpeg | Manim |
| --- | --- | --- |
| Debian/Ubuntu | `sudo apt install ffmpeg` | `sudo apt install libcairo2-dev libpango1.0-dev pkg-config python3-dev` |
| macOS | `brew install ffmpeg` | `brew install pango` then `pip install manim` (a Homebrew Python is required) |
| Windows | `winget install Gyan.FFmpeg` | `pip install manim` works out of the box (wheels bundle pango); install `ffmpeg` for MP4 output |

Both are **optional**. When Manim is missing, `protoverify animate --engine manim`
prints a clear message and falls back to the matplotlib GIF renderer. When
ffmpeg is missing, the matplotlib back-end writes GIF instead of MP4.

---

## Five-minute tutorial

### 1. Write Needham–Schroeder

```bash
protoverify check examples/ns.spdl
protoverify verify examples/ns.spdl
```

```
protocol ns

role  claim  kind     status     states  seconds
----  -----  -------  ---------  ------  -------
I     I1     Secret   VERIFIED   308     0.30
I     I2     Secret   VERIFIED   308     0.30
I     I3     Niagree  VERIFIED   308     0.30
I     I4     Nisynch  VERIFIED   308     0.30
R     R1     Secret   FALSIFIED  831     0.42
R     R2     Secret   FALSIFIED  831     0.42
R     R3     Niagree  FALSIFIED  831     0.42
R     R4     Nisynch  FALSIFIED  831     0.42
```

Every responder claim is broken: Lowe’s man-in-the-middle. A trace was written
to `traces/ns_R3.json`.

### 2. Watch the attack

```bash
protoverify animate-trace traces/ns_R3.json --engine mpl --style seq --out attack.gif
protoverify animate-trace traces/ns_R3.json --engine mpl --style graph --out graph.gif
protoverify animate-trace traces/ns_R3.json --engine mpl --style seq --show   # interactive
protoverify animate-trace traces/ns_R3.json --engine manim --style seq --quality l -q
```

The last frame always carries the violated claim and the English explanation:

```
violation: B believes its I partner is I, but the I run(s) of this trace are
I talking to M; claim R3 (Niagree) does not hold.
```

### 3. Fix it

`examples/nsl.spdl` differs from `examples/ns.spdl` in exactly one place — the
responder’s identity is added to message 2:

```
recv_2(R,I, {ni,nr}pk(I));        // ns.spdl
recv_2(R,I, {R,ni,nr}pk(I));      // nsl.spdl
```

```bash
protoverify run-example nsl
```

All eight claims are `VERIFIED` within the bounds.

---

## CLI reference

```
protoverify [--quiet] [--verbose] [--color|--no-color] COMMAND ...

protoverify verify FILE [--max-runs 4] [--max-len 20] [--timeout 30]
                        [--max-states N] [--compromise A,B] [--json out.json]
                        [--trace-dir DIR] [--claim LABEL]
protoverify check FILE
protoverify animate FILE --claim ID [--engine mpl|manim] [--style seq|graph]
                        [--out FILE] [--speed 1.0] [--fps 20] [--quality l|m|h] [--show]
protoverify animate-trace TRACE.json [same options as animate]
protoverify list-examples
protoverify run-example NAME [--animate] [--engine mpl|manim] [--style seq|graph]
                             [-q l|m|h] [--claim ID] [--out FILE] [--show]
```

| exit code | meaning |
| --- | --- |
| `0` | nothing was falsified |
| `1` | at least one claim was falsified |
| `2` | parse error, failed static check or unknown example |
| `3` | internal error (a bug — please report it) |

Colours are plain ANSI and are disabled automatically when stdout is not a TTY
or when `NO_COLOR` is set.

### GUI (optional)

```bash
python -m protoverify.gui
```

A small Tkinter window lists the bundled examples, shows the claim table and
draws the attack trace of any falsified claim in an embedded matplotlib canvas.

---

## Architecture

```
                protoverify/
  cli.py  gui.py  report.py          user interface (argparse, ANSI, Tk)
      │
      ├── parser/   lexer.py -> parser.py -> ast.py, checks.py
      │             hand-written lexer with (line, col); recursive-descent parser;
      │             frozen slotted AST; static checks accumulate *all* errors
      │
      └── core/
            terms.py     free term algebra: Atom Var Tuple SymEnc AsymEnc
                         Sign Hash Pk Sk SharedKey (immutable, hash-consed)
            types.py     typing discipline: Agent / Nonce / Key / Data / Ticket
            unify.py     MGU with occurs check + end-to-end type requirements
            attacker.py  Dolev-Yao: analyze() closure and can_synthesize()
            run.py       role instances: agent, peer, fresh values, agent env
            ordering.py  causal DAG with incremental cycle rejection
            search.py    claim-driven bounded search + Verifier facade
            claims.py    Secret / Alive / Weakagree / Niagree / Nisynch
            replay.py    independent forward replay checker
            trace.py     the trace JSON contract (dataclasses + validator)
                     │
                     └── viz/  common.py, mpl_sequence.py, mpl_graph.py,
                              controls.py, manim_scenes.py, export.py
                              ── reads trace.json only, never the engine ──
```

### How the search works

For each role the verifier creates one **run** of the claimant role and then
repeatedly branches over *which ready event fires next*:

* a **`send`** fires immediately and enlarges the attacker's knowledge;
* a **`recv`** branches four ways:
  * **attacker** — the message can be built from the knowledge available at that
    point (the missing components are added as new attacker knowledge),
  * **existing run** — it unifies with a `send` of a run that already exists; an
    ordering edge `send → recv` is added,
  * **new run** — a fresh run of some role is instantiated to produce it,
  * **spontaneous run** — a session nobody is waiting for starts; this is what
    makes man-in-the-middle relaying expressible.

After every branch the substitution is applied, the causal graph is checked for
cycles, fresh values are checked for leaks and a canonicalising memo table
(renaming runs and variables) prunes isomorphic states. When every message event
has fired, the concrete trace is **replayed from scratch** by `replay.py`; a
trace that does not replay consistently is thrown away, which guards the engine
against its own bookkeeping bugs.

Bounds: `--max-runs` (total role instances), `--max-len` (total events),
`--timeout` (seconds), `--max-states` (explored search nodes) and
`max_runs_per_role` (1 by default). Exhausting them without finding a
counterexample is what `VERIFIED` means.

---

## Adding a new example

1. Drop `myproto.spdl` into `examples/`.
2. `protoverify check examples/myproto.spdl` — fix whatever the static checker
   reports.
3. `protoverify verify examples/myproto.spdl` and look at the table.
4. `protoverify animate examples/myproto.spdl --claim R3 --out myproto.gif`.
5. Regenerate the expected results so the test suite covers it:

   ```bash
   python tools/make_expected.py
   ```

`examples/expected.json` is *data*. Nothing in the engine reads it — deleting it
cannot change a single verification result, which `tests/integration/
test_examples.py::test_results_do_not_depend_on_expected_json` asserts.

---

## Testing

```bash
pytest -q                  # 270 tests
mypy --strict src          # clean
ruff check .               # clean
```

* `tests/unit/` — lexer positions and comments, every parser construct and error
  message, unification (occurs check, type mismatch, aliasing), attacker
  decomposition/synthesis/compromise, ordering cycle rejection, claim semantics,
  trace schema, replay checker.
* `tests/property/` — hypothesis: `analyze` is monotone and idempotent,
  `synthesizable ⟹ derivable`, unification makes both sides equal and is
  symmetric, substitution is idempotent, the occurs check never admits a cycle.
* `tests/integration/` — every example against `expected.json`, the claim
  implication hierarchy `Nisynch ⇒ Niagree ⇒ Weakagree ⇒ Alive` checked on real
  traces, CLI exit codes, GUI smoke test, performance guards.
* `tests/viz/` — headless GIF generation, frame count `= steps × subframes`,
  PNG/MP4 export and the Manim fallback. The Manim test is marked `manim` and
  skips itself when Manim or ffmpeg is absent.

---

## Documentation

* [`docs/spdl.md`](docs/spdl.md) — the accepted language, typing rules, run model
* [`docs/claims.md`](docs/claims.md) — formal claim semantics
* [`docs/trace-schema.md`](docs/trace-schema.md) — the renderer contract
* [`docs/limitations.md`](docs/limitations.md) — what this tool does **not** prove,
  and how it differs from Scyther, Tamarin and ProVerif

## License

MIT.