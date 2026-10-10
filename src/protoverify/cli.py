"""The ``protoverify`` command line interface.

Exit codes:

``0``
    nothing was falsified (or no expectations were given)
``1``
    at least one claim was falsified
``2``
    the protocol could not be parsed or failed a static check
``3``
    an unexpected internal error
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import traceback
from collections.abc import Sequence

from . import __version__
from .core.search import Bounds, ClaimResult, Verifier
from .core.trace import Status, Trace, TraceError
from .parser import check, parse_file
from .parser.errors import ProtoVerifyError
from .report import Palette, render_table, render_trace, write_trace

__all__ = ["build_parser", "main"]

EXIT_OK = 0
EXIT_FALSIFIED = 1
EXIT_PARSE = 2
EXIT_INTERNAL = 3

EXAMPLES_DIRNAME = "examples"


def examples_dir() -> pathlib.Path | None:
    """Locate the bundled example protocols.

    A source checkout or an editable install keeps them next to the package; a
    wheel install may ship them inside the package instead.
    """
    here = pathlib.Path(__file__).resolve()
    for candidate in (here.parents[2] / EXAMPLES_DIRNAME, here.parent / EXAMPLES_DIRNAME):
        if candidate.is_dir():
            return candidate
    return None


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser of the ``protoverify`` command."""
    parser = _root_parser()
    sub = parser.add_subparsers(dest="command", required=True)
    _add_verify(sub)
    sub.add_parser("check", help="parse and run the static checks only").add_argument("file")
    _add_animate(sub)
    sub.add_parser("list-examples", help="list the bundled example protocols")
    _add_run_example(sub)
    return parser


def _root_parser() -> argparse.ArgumentParser:
    """The parser holding the flags that apply to every sub-command."""
    parser = argparse.ArgumentParser(
        prog="protoverify",
        description="Bounded, Scyther-style symbolic security verification with "
                    "attack animations.",
    )
    parser.add_argument("--version", action="version", version=f"protoverify {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="only print the summary line")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every attack trace")
    colour = parser.add_mutually_exclusive_group()
    colour.add_argument("--color", dest="color", action="store_true", default=None,
                        help="force coloured output")
    colour.add_argument("--no-color", dest="color", action="store_false",
                        help="disable coloured output")
    return parser


def _add_verify(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``protoverify verify``."""
    verify = sub.add_parser("verify", help="verify every claim of a protocol")
    _add_output_flags(verify)
    verify.add_argument("file")
    verify.add_argument("--max-runs", type=int, default=4)
    verify.add_argument("--max-len", type=int, default=20)
    verify.add_argument("--timeout", type=float, default=30.0)
    verify.add_argument("--max-states", type=int, default=200_000)
    verify.add_argument("--compromise", default="", help="comma separated extra compromised agents")
    verify.add_argument("--json", dest="json_out", help="write the full result as JSON")
    verify.add_argument("--trace-dir", default="traces", help="directory for attack traces")
    verify.add_argument("--claim", action="append", default=None, help="only these claims")


def _add_animate(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``protoverify animate`` and ``protoverify animate-trace``."""
    animate = sub.add_parser("animate", help="verify a protocol and animate a falsified claim")
    _add_output_flags(animate)
    _add_animate_options(animate)
    animate.add_argument("file")
    animate.add_argument("--claim", required=True)
    animate.add_argument("--max-runs", type=int, default=4)
    animate.add_argument("--max-len", type=int, default=20)
    animate.add_argument("--timeout", type=float, default=30.0)

    from_trace = sub.add_parser("animate-trace", help="animate an existing trace JSON file")
    _add_output_flags(from_trace)
    _add_animate_options(from_trace)
    from_trace.add_argument("trace")


def _add_run_example(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register ``protoverify run-example``."""
    run_example = sub.add_parser("run-example", help="verify (and animate) a bundled example")
    _add_output_flags(run_example, short=False)
    run_example.add_argument("name")
    run_example.add_argument("--animate", action="store_true")
    run_example.add_argument("--claim", default=None)
    _add_animate_options(run_example, quality_short="-q")
    run_example.add_argument("--max-runs", type=int, default=4)
    run_example.add_argument("--timeout", type=float, default=30.0)


def _add_output_flags(parser: argparse.ArgumentParser, short: bool = True) -> None:
    """Add ``--quiet``/``--verbose`` without clobbering the global values.

    ``SUPPRESS`` keeps the sub-parser from overwriting a flag the user already
    gave before the sub-command, so ``protoverify -q verify x`` and
    ``protoverify verify x -q`` mean the same thing.
    """
    quiet = ["-q", "--quiet"] if short else ["--quiet"]
    parser.add_argument(*quiet, action="store_true", dest="quiet", default=argparse.SUPPRESS)
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose",
                        default=argparse.SUPPRESS)


def _add_animate_options(parser: argparse.ArgumentParser, *, quality_short: str = "") -> None:
    """Add the renderer options shared by every animation command.

    ``animate`` and ``animate-trace`` use ``-q`` for ``--quiet``, so their
    quality flag has no short form; ``run-example`` follows the documented
    ``-q l`` spelling and only offers ``--quiet`` in long form.
    """
    parser.add_argument("--engine", choices=("mpl", "manim"), default="mpl")
    parser.add_argument("--style", choices=("seq", "graph"), default="seq")
    parser.add_argument("--out", default=None, help="output file (.gif/.mp4/.png)")
    parser.add_argument("--fps", type=int, default=20)
    parser.add_argument("--speed", type=float, default=1.0)
    if quality_short:
        parser.add_argument(quality_short, "--quality", choices=("l", "m", "h"), default="l")
    else:
        parser.add_argument("--quality", choices=("l", "m", "h"), default="l")
    parser.add_argument("--show", action="store_true", help="interactive player (matplotlib only)")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``protoverify`` executable."""
    parser = build_parser()
    args = parser.parse_args(argv)
    args.quiet = getattr(args, "quiet", False)
    args.verbose = getattr(args, "verbose", False)
    palette = Palette.detect(force=args.color)
    try:
        return _dispatch(args, palette)
    except (ProtoVerifyError, TraceError) as exc:
        print(f"protoverify: {exc}", file=sys.stderr)
        return EXIT_PARSE
    except Exception:  # pragma: no cover - the internal-error path
        traceback.print_exc()
        print("protoverify: internal error", file=sys.stderr)
        return EXIT_INTERNAL


def _dispatch(args: argparse.Namespace, palette: Palette) -> int:
    handlers = {
        "verify": _cmd_verify,
        "check": _cmd_check,
        "animate": _cmd_animate,
        "animate-trace": _cmd_animate_trace,
        "list-examples": _cmd_list_examples,
        "run-example": _cmd_run_example,
    }
    return handlers[args.command](args, palette)


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def _cmd_check(args: argparse.Namespace, palette: Palette) -> int:
    protocol = parse_file(args.file)
    errors = check(protocol)
    if errors:
        for err in errors:
            print(f"protoverify: {err.error}", file=sys.stderr)
        return EXIT_PARSE
    print(palette.status(Status.VERIFIED.value, "OK"), f"{protocol.name}: "
          f"{len(protocol.roles)} role(s), {len(protocol.all_claims())} claim(s), "
          f"static checks passed")
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace, palette: Palette) -> int:
    protocol = parse_file(args.file)
    _require_clean(protocol)
    bounds = Bounds(
        max_runs=args.max_runs,
        max_trace_len=args.max_len,
        timeout=args.timeout,
        max_states=args.max_states,
    )
    verifier = Verifier(protocol, bounds, _split(args.compromise))
    results = verifier.verify(args.claim)
    if not args.quiet:
        print(render_table(protocol.name, results, palette))
    trace_dir = pathlib.Path(args.trace_dir)
    written: list[Trace] = []
    for result in results:
        if result.trace is not None:
            trace = result.trace
            written.append(trace)
            trace.to_file(trace_dir / f"{protocol.name}_{result.claim}.json")
    if args.verbose:
        for trace in written:
            print()
            print(render_trace(trace, palette))
    if written and not args.verbose:
        print()
        for trace in written:
            print(write_trace(trace, str(trace_dir / f"{protocol.name}_{trace.claim}.json")))
    if args.json_out:
        _write_json(args.json_out, protocol.name, results, bounds)
    return EXIT_FALSIFIED if any(r.falsified for r in results) else EXIT_OK


def _cmd_animate(args: argparse.Namespace, palette: Palette) -> int:
    protocol = parse_file(args.file)
    _require_clean(protocol)
    bounds = Bounds(max_runs=args.max_runs, max_trace_len=args.max_len, timeout=args.timeout)
    verifier = Verifier(protocol, bounds)
    results = verifier.verify([args.claim])
    falsified = [r for r in results if r.falsified and r.trace is not None]
    if not falsified:
        print(palette.status(Status.VERIFIED.value, args.claim),
              "is not falsified: there is no attack trace to animate")
        return EXIT_OK
    trace = falsified[0].trace
    assert trace is not None
    print(render_trace(trace, palette))
    out = args.out or f"{protocol.name}_{trace.claim}.gif"
    written = _animate(trace, args, out)
    print(f"wrote {written}")
    return EXIT_FALSIFIED


def _cmd_animate_trace(args: argparse.Namespace, palette: Palette) -> int:
    trace = Trace.from_file(args.trace)
    if not args.quiet:
        print(render_trace(trace, palette))
    out = args.out or f"{trace.protocol}_{trace.claim}.gif"
    written = _animate(trace, args, out)
    print(f"wrote {written}")
    return EXIT_FALSIFIED if trace.falsified else EXIT_OK


def _cmd_list_examples(args: argparse.Namespace, palette: Palette) -> int:
    del args
    names = list_examples()
    if not names:
        print(
            "no bundled examples found: run protoverify from a source checkout, "
            "or pass a path to 'protoverify verify FILE'"
        )
        return EXIT_OK
    print(palette.bold("bundled examples:"))
    for name in names:
        print(f"  {name}")
    return EXIT_OK


def _cmd_run_example(args: argparse.Namespace, palette: Palette) -> int:
    path = _example_path(args.name)
    protocol = parse_file(str(path))
    _require_clean(protocol)
    bounds = Bounds(max_runs=args.max_runs, timeout=args.timeout)
    verifier = Verifier(protocol, bounds)
    results = verifier.verify([args.claim] if args.claim else None)
    if not args.quiet:
        print(render_table(protocol.name, results, palette))
    code = EXIT_FALSIFIED if any(r.falsified for r in results) else EXIT_OK
    if args.animate:
        traces = [r.trace for r in results if r.trace is not None]
        if not traces:
            print("nothing to animate: no claim was falsified")
            return code
        trace = traces[0]
        out = args.out or f"{protocol.name}_{trace.claim}.gif"
        anim = argparse.Namespace(
            engine=args.engine, style=args.style, out=out, fps=args.fps,
            speed=args.speed, quality=args.quality, show=args.show,
        )
        written = _animate(trace, anim, out)
        print(f"wrote {written}")
    return code


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _animate(trace: Trace, args: argparse.Namespace, out: str) -> str:
    from .viz.export import render_trace as render

    return render(
        trace,
        out=out,
        engine=args.engine,
        style=args.style,
        fps=args.fps,
        speed=args.speed,
        quality=args.quality,
        show=args.show,
    )


def _require_clean(protocol: object) -> None:
    from .parser.checks import check_or_raise

    check_or_raise(protocol)  # type: ignore[arg-type]


def _split(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _write_json(path: str, protocol: str, results: Sequence[ClaimResult], bounds: Bounds) -> None:
    payload = {
        "protocol": protocol,
        "bounds": bounds.to_json(),
        "claims": [
            {
                "role": r.role,
                "claim": r.claim,
                "kind": r.kind,
                "status": r.status,
                "states": r.states,
                "seconds": round(r.seconds, 4),
                "reason": r.reason,
                "trace": r.trace.to_json() if r.trace else None,
            }
            for r in results
        ],
    }
    target = pathlib.Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def list_examples() -> list[str]:
    """Return the names of the bundled example protocols."""
    directory = examples_dir()
    if directory is None:
        return []
    return sorted(p.stem for p in directory.glob("*.spdl"))


def _example_path(name: str) -> pathlib.Path:
    directory = examples_dir()
    if directory is None:
        raise ProtoVerifyError(
            "no bundled examples found; pass a file to 'protoverify verify FILE' instead"
        )
    candidate = name if name.endswith(".spdl") else f"{name}.spdl"
    path = directory / candidate
    if not path.exists():
        raise ProtoVerifyError(
            f"unknown example {name!r}; available: {', '.join(list_examples())}"
        )
    return path


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
