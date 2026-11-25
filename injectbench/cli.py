"""Command line interface: `injectbench list` and `injectbench run`."""

from __future__ import annotations

import argparse
import importlib
import os
import sys

from .attacks import categories, get_attacks
from .defenses import ALL_LAYERS, GuardedAgent
from .models import Outcome, Severity
from .report import fmt_rate, summarize, write_reports
from .runner import Runner, make_environment


FORMATS = ("json", "md", "html")


class AgentLoadError(Exception):
    """The requested agent could not be created (missing module, SDK, ...)."""


def positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid int value: {text!r}") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {value}")
    return value


def parse_layers(spec: str) -> tuple[str, ...]:
    """'all' or a comma list of layer names. Empty items are dropped. Raises ValueError."""
    if spec.strip() == "all":
        return ALL_LAYERS
    layers = tuple(x.strip() for x in spec.split(",") if x.strip())
    if not layers:
        raise ValueError(f"no defense layers given; use 'all' or a comma list of: {', '.join(ALL_LAYERS)}")
    unknown = [x for x in layers if x not in ALL_LAYERS]
    if unknown:
        raise ValueError(f"unknown defense layer(s): {', '.join(unknown)}; choose from: all, {', '.join(ALL_LAYERS)}")
    return tuple(dict.fromkeys(layers))


def parse_formats(spec: str) -> list[str]:
    """Comma list of report formats. Empty items are dropped. Raises ValueError."""
    formats = list(dict.fromkeys(x.strip().lower() for x in spec.split(",") if x.strip()))
    if not formats:
        raise ValueError(f"no report format given; choose from: {', '.join(FORMATS)}")
    unknown = [x for x in formats if x not in FORMATS]
    if unknown:
        raise ValueError(f"unknown report format(s): {', '.join(unknown)}; choose from: {', '.join(FORMATS)}")
    return formats


def _load_custom(spec: str):
    """Load `package.module:factory` and call it to get an agent."""
    module, _, attr = spec.partition(":")
    obj = getattr(importlib.import_module(module), attr or "agent")
    return obj() if callable(obj) and not hasattr(obj, "run") else obj


def build_agent(args, env):
    try:
        agent = _make_agent(args)
    except AgentLoadError:
        raise
    except (ImportError, AttributeError, RuntimeError) as exc:
        raise AgentLoadError(f"cannot load agent '{args.agent}': {exc}") from exc

    if args.defenses:
        layers = args.defenses if isinstance(args.defenses, tuple) else parse_layers(args.defenses)
        agent = GuardedAgent(agent, env, layers=layers)
    return agent


def _make_agent(args):
    if args.agent == "naive":
        from .agents import NaiveAgent

        agent = NaiveAgent()
    elif args.agent == "claude":
        from .agents.claude import ClaudeAgent

        agent = ClaudeAgent(model=args.model, effort=args.effort, use_fallbacks=not args.no_fallbacks)
    elif args.agent == "http":
        if not args.url:
            sys.exit("--url is required for --agent http")
        from .agents import HttpAgent

        agent = HttpAgent(args.url)
    else:
        agent = _load_custom(args.agent)
    return agent


def cmd_list(args) -> int:
    attacks = get_attacks(args.category)
    if not attacks:
        print(f"No attacks match the filters. Categories: {', '.join(categories())}", file=sys.stderr)
        return 2
    for a in attacks:
        print(f"{a.id:7} {a.severity.value:8} {a.vector:12} {a.category:24} {a.name}")
    print(f"\n{len(attacks)} attacks. Categories: {', '.join(categories())}")
    return 0


def cmd_run(args) -> int:
    env = make_environment(args.seed)
    try:
        agent = build_agent(args, env)
    except AgentLoadError as exc:
        print(f"injectbench: error: {exc}", file=sys.stderr)
        return 2
    attacks = get_attacks(args.category, args.id, Severity(args.min_severity) if args.min_severity else None)
    if not attacks:
        print("No attacks match the filters.", file=sys.stderr)
        return 2

    def progress(r):
        mark = {"missed": "MISSED ", "blocked": "blocked", "error": "ERROR  "}[r.outcome.value]
        print(f"  [{mark}] {r.attack_id:7} {r.severity.value:8} {r.name}", flush=True)

    print(f"Running {len(attacks)} attacks x {args.trials} trial(s) against {agent.name}\n")
    runner = Runner(agent, env, trials=args.trials, workers=args.workers, progress=progress, seed=args.seed)
    report = runner.run(attacks)
    formats = args.format if isinstance(args.format, list) else parse_formats(args.format)
    paths = write_reports(report, args.out, formats)
    s = summarize(report)
    score = "n/a" if s["security_score"] is None else f"{s['security_score']}/100"
    print(
        f"\nSecurity score: {score} | missed {s['missed']} of {s['total']} "
        f"| success rate {fmt_rate(s['attack_success_rate'])} | errors {s['errors']}"
    )
    for p in paths:
        print(f"Report: {p}")

    if s["errors"]:
        print(f"WARNING: {s['errors']} attack(s) ended with an error; the result is incomplete.", file=sys.stderr)
    if args.fail_on:
        if s["errors"]:
            print("FAIL: errors make the security gate unreliable", file=sys.stderr)
            return 1
        limit = Severity(args.fail_on).rank
        bad = [r for r in report.results if r.outcome == Outcome.MISSED and r.severity.rank >= limit]
        if bad:
            print(f"FAIL: {len(bad)} missed attack(s) at severity >= {args.fail_on}", file=sys.stderr)
            return 1
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="injectbench", description="Prompt injection test suite for AI agents")
    sub = p.add_subparsers(dest="cmd", required=True)

    pl = sub.add_parser("list", help="list attacks in the library")
    pl.add_argument("--category", action="append")
    pl.set_defaults(func=cmd_list)

    pr = sub.add_parser("run", help="run attacks against an agent")
    pr.add_argument("--agent", default="naive", help="naive | claude | http | module:factory")
    pr.add_argument("--model", default="claude-opus-5-5", help="model for --agent claude")
    pr.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"])
    pr.add_argument("--no-fallbacks", action="store_true", help="disable server-side refusal fallbacks")
    pr.add_argument("--url", help="endpoint for --agent http")
    pr.add_argument("--defenses", help=f"'all' or a comma list of: {','.join(ALL_LAYERS)}")
    pr.add_argument("--category", action="append", help="filter by category (repeatable)")
    pr.add_argument("--id", action="append", help="run one attack id (repeatable)")
    pr.add_argument("--min-severity", choices=[s.value for s in Severity])
    pr.add_argument("--trials", type=positive_int, default=1, help="runs per attack (LLMs are not deterministic)")
    pr.add_argument("--workers", type=positive_int, default=1, help="parallel attacks")
    pr.add_argument("--seed", help="fixed secret token (reproducible reports)")
    pr.add_argument("--out", default="reports", help="output directory")
    pr.add_argument("--format", default="json,md,html", help=f"comma list of: {','.join(FORMATS)}")
    pr.add_argument("--fail-on", choices=[s.value for s in Severity], help="exit 1 if a missed attack is at this severity or above")
    pr.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    if args.cmd == "run":
        try:
            if args.defenses is not None:
                args.defenses = parse_layers(args.defenses)
        except ValueError as exc:
            pr.error(f"--defenses: {exc}")
        try:
            args.format = parse_formats(args.format)
        except ValueError as exc:
            pr.error(f"--format: {exc}")
    try:
        return args.func(args)
    except BrokenPipeError:
        # Output piped into e.g. `head`: stop quietly. Point stdout at devnull so
        # the interpreter's final flush does not raise again.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError, AttributeError):
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
