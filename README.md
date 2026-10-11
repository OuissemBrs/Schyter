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

### Rendering with Manim (optional)

The matplotlib back-end is the default and needs nothing beyond `[viz]`. The
Manim back-end is optional and has **two** dependencies, not one: the `manim`
Python package *and* a working `ffmpeg`. Manim itself also links against the
system libraries **Cairo** and **Pango**; those are not optional on Linux and
macOS, which is why `pip install manim` fails there without them.

#### Linux (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y ffmpeg libcairo2-dev libpango1.0-dev pkg-config python3-dev
python -m pip install -e ".[manim]"
```

#### macOS

```bash
brew install ffmpeg pango pkg-config
python -m pip install -e ".[manim]"
```

Use the Homebrew Python; a python.org or pyenv build usually cannot find the
Homebrew Pango and fails to build Manim.

#### Windows

```powershell
winget install Gyan.FFmpeg
python -m pip install -e ".[manim]"
```

Manim ships Windows wheels that bundle Cairo and Pango, so no system packages are
needed; only ffmpeg is missing out of the box. Add it to `PATH` if
`winget` does not do it for you, then reopen the shell.

#### Checking the installation

`tools/check_manim.sh` (macOS/Linux) and `tools/check_manim.ps1` (Windows) check
all three things — `import manim`, `ffmpeg -version`, and a real `-ql` render of
`SequenceScene` from a golden trace — and print which one is missing:

```bash
bash tools/check_manim.sh                       # Linux / macOS
powershell -ExecutionPolicy Bypass -File tools\check_manim.ps1   # Windows
```

A healthy machine ends with:

```
RESULT: the Manim back-end renders correctly.
```

A machine without Manim ends with a precise diagnosis instead:

```
1/3  python -c 'import manim'
  [FAIL] manim is not importable
       install:  pip install 'protoverify[manim]'
2/3  ffmpeg -version
  [FAIL] ffmpeg is not on PATH
       install:  winget install Gyan.FFmpeg
...
RESULT: the Manim back-end could not be exercised here.
        The matplotlib back-end is unaffected and remains the default:
          protoverify run-example ns --animate --engine mpl
```

#### Fallback behaviour

Both tools are optional and the fallback is automatic. `protoverify animate
--engine manim` names the missing tool and the command that installs it, then
renders with matplotlib instead:

```
protoverify: the 'manim' back-end was requested but manim is not installed.
            install the Python package with:  pip install 'protoverify[manim]'
            manim also needs the system libraries Cairo and Pango; see the
            README section 'Rendering with Manim' for Linux, macOS and Windows.
            falling back to the matplotlib back-end (GIF/PNG only).
```

If manim is present but ffmpeg is not, the message says so instead — the two
failures have different fixes and are never reported the same way. A `.mp4`
target is rewritten to `.gif` on the fallback path, because Pillow cannot write
MP4.

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
5. Work out the right answers **by hand first** and add them to
   `examples/expected_reference.json` — the reference oracle, with a `source`
   field saying where each verdict comes from ("spec", "literature: Lowe 1996",
   "reasoned: ..."). Only then run:

   ```bash
   python tools/make_snapshot.py
   ```

Two data files, two jobs, and the distinction matters:

| file | origin | role |
| --- | --- | --- |
| `examples/expected_reference.json` | hand written | **the oracle** — `test_reference.py` fails if the engine disagrees |
| `examples/regression_snapshot.json` | `tools/make_snapshot.py` | change detector — `test_regression.py` fails if anything moved |

Neither is read by the engine — deleting both cannot change a single
verification result, which `tests/integration/test_examples.py::
test_results_do_not_depend_on_the_data_files` asserts. If the engine and the
reference disagree, **do not edit the reference to match**: decide which one is
wrong, record the evidence in `DECISIONS.md`, and fix the engine if it is the
engine.

---

## Testing

```bash
pytest -q                  # 332 tests (2 skipped: manim, ffmpeg)
mypy --strict src          # clean
ruff check .               # clean
```

* `tests/unit/` — lexer positions and comments, every parser construct and error
  message, unification (occurs check, type mismatch, aliasing), attacker
  decomposition/synthesis/compromise/own constants, ordering cycle rejection,
  claim semantics, trace schema, replay checker.
* `tests/property/` — hypothesis: `analyze` is monotone and idempotent,
  `synthesizable ⟹ derivable`, unification makes both sides equal and is
  symmetric, substitution is idempotent, the occurs check never admits a cycle.
* `tests/integration/` — every example against the hand-written
  `expected_reference.json` oracle and, separately, against the generated
  `regression_snapshot.json`; the claim implication hierarchy
  `Nisynch ⇒ Niagree ⇒ Weakagree ⇒ Alive` checked on real traces; every falsifying
  trace re-checked by an **independent replayer** that imports only
  `core/terms`, `core/unify` and `core/attacker`; the shared-search optimisation
  compared against one-search-per-claim; CLI exit codes, GUI smoke test,
  performance guards.
* `tests/viz/` — headless GIF generation, frame count `= steps × subframes`,
  PNG/MP4 export and the Manim fallback. The Manim test is marked `manim` and
  skips itself when Manim or ffmpeg is absent.

Three diagnostic tools sit outside the test suite, under `tools/`:

| tool | what it answers |
| --- | --- |
| `independent_replay.py` | "is this trace justified, using no search or claims code?" |
| `search_stats.py` | "why is this VERIFIED — how many states, how many dead ends?" |
| `why_recv3.py` | "at this receive event, which delivery options are still open?" |
| `make_snapshot.py` | regenerate the change-detector file (never the oracle) |
| `check_manim.sh` / `.ps1` | "does the Manim back-end really render here?" |

---

## Documentation

* [`docs/spdl.md`](docs/spdl.md) — the accepted language, typing rules, run model
* [`docs/architecture.md`](docs/architecture.md) — the layers, the search, and why
  one search may serve several claims
* [`docs/claims.md`](docs/claims.md) — formal claim semantics, plus a worked
  analysis of NS vs. NSL
* [`docs/trace-schema.md`](docs/trace-schema.md) — the renderer contract
* [`docs/limitations.md`](docs/limitations.md) — what this tool does **not** prove,
  and how it differs from Scyther, Tamarin and ProVerif
* [`PROGRESS.md`](PROGRESS.md) and [`DECISIONS.md`](DECISIONS.md) — the review log
  and the reasoning behind each design decision

## License

MIT.