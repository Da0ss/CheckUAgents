"""Command line interface: `injectbench list` and `injectbench run`."""

from __future__ import annotations

import argparse
import importlib
import sys

from .attacks import categories, get_attacks
from .defenses import ALL_LAYERS, GuardedAgent
from .models import Outcome, Severity
from .report import summarize, write_reports
from .runner import Runner, make_environment


def _load_custom(spec: str):
    """Load `package.module:factory` and call it to get an agent."""
    module, _, attr = spec.partition(":")
    obj = getattr(importlib.import_module(module), attr or "agent")
    return obj() if callable(obj) and not hasattr(obj, "run") else obj


def build_agent(args, env):
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

    if args.defenses:
        layers = ALL_LAYERS if args.defenses == "all" else tuple(x.strip() for x in args.defenses.split(","))
        agent = GuardedAgent(agent, env, layers=layers)
    return agent


def cmd_list(args) -> int:
    attacks = get_attacks(args.category)
    for a in attacks:
        print(f"{a.id:7} {a.severity.value:8} {a.vector:12} {a.category:24} {a.name}")
    print(f"\n{len(attacks)} attacks. Categories: {', '.join(categories())}")
    return 0


def cmd_run(args) -> int:
    env = make_environment(args.seed)
    agent = build_agent(args, env)
    attacks = get_attacks(args.category, args.id, Severity(args.min_severity) if args.min_severity else None)
    if not attacks:
        print("No attacks match the filters.", file=sys.stderr)
        return 2

    def progress(r):
        mark = {"missed": "MISSED ", "blocked": "blocked", "error": "ERROR  "}[r.outcome.value]
        print(f"  [{mark}] {r.attack_id:7} {r.severity.value:8} {r.name}", flush=True)

    print(f"Running {len(attacks)} attacks x {args.trials} trial(s) against {agent.name}\n")
    report = Runner(agent, env, trials=args.trials, workers=args.workers, progress=progress).run(attacks)
    paths = write_reports(report, args.out, args.format.split(","))
    s = summarize(report)
    print(
        f"\nSecurity score: {'n/a' if s['security_score'] is None else s['security_score']}/100 | missed {s['missed']} of {s['total']} "
        f"| errors {s['errors']}"
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
    pr.add_argument("--trials", type=int, default=1, help="runs per attack (LLMs are not deterministic)")
    pr.add_argument("--workers", type=int, default=1, help="parallel attacks")
    pr.add_argument("--seed", help="fixed secret token (reproducible reports)")
    pr.add_argument("--out", default="reports", help="output directory")
    pr.add_argument("--format", default="json,md,html")
    pr.add_argument("--fail-on", choices=[s.value for s in Severity], help="exit 1 if a missed attack is at this severity or above")
    pr.set_defaults(func=cmd_run)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
