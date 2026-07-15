"""Command line entry point for LogSentry."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, engine
from .digest import render_html, render_text
from .models import Event
from .parsers import parse_syslog, parse_windows_csv

DEMO_DIR = Path(__file__).resolve().parent.parent / "demo"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsentry",
        description="Turn Windows and Linux security logs into a daily digest.",
    )
    p.add_argument("--windows-csv", metavar="PATH", help="Windows Security event CSV export.")
    p.add_argument("--syslog", metavar="PATH", help="Linux auth log in syslog format.")
    p.add_argument("--demo", action="store_true", help="Run against the bundled synthetic corpus.")
    p.add_argument("--out", metavar="PATH", help="Write the HTML digest to this path.")
    p.add_argument("--format", choices=["text", "html"], default="text",
                   help="Console output format. Default text.")
    p.add_argument("--version", action="version", version=f"logsentry {__version__}")
    return p


def load_events(args: argparse.Namespace) -> list[Event]:
    events: list[Event] = []
    if args.demo:
        events += parse_windows_csv(DEMO_DIR / "demo_security.csv")
        events += parse_syslog(DEMO_DIR / "demo_auth.log")
        return events
    if args.windows_csv:
        events += parse_windows_csv(args.windows_csv)
    if args.syslog:
        events += parse_syslog(args.syslog)
    return events


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.demo and not args.windows_csv and not args.syslog:
        print("Nothing to do. Pass --demo, --windows-csv, or --syslog.", file=sys.stderr)
        return 2

    events = load_events(args)
    digest = engine.run(events)

    if args.out:
        Path(args.out).write_text(render_html(digest), encoding="utf-8")

    if args.format == "html" and not args.out:
        print(render_html(digest))
    else:
        print(render_text(digest))
        if args.out:
            print(f"\nHTML digest written to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
