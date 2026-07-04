"""Command-line interface for iil-codeguard.

Subcommands:
  audit       — Audit a repo or directory
  check-file  — Check a single file
  list-rules  — List all registered rules
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from iil_codeguard import __version__, api
from iil_codeguard.domain import RULE_REGISTRY, Severity
from iil_codeguard.reporters import json_reporter, sarif, text


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "audit":
        return _cmd_audit(args)
    if args.command == "check-file":
        return _cmd_check_file(args)
    if args.command == "list-rules":
        return _cmd_list_rules(args)
    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codeguard",
        description="iil-codeguard — Library-first code compliance for the IIL Platform",
    )
    p.add_argument("--version", action="version", version=f"iil-codeguard {__version__}")
    sub = p.add_subparsers(dest="command", required=False)

    # audit
    pa = sub.add_parser("audit", help="Audit a repo or directory")
    pa.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    pa.add_argument(
        "--format",
        choices=["text", "sarif", "json"],
        default="text",
        help="Output format (default: text)",
    )
    pa.add_argument(
        "--severity-threshold",
        choices=[s.value for s in Severity],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    pa.add_argument(
        "--summary-only",
        action="store_true",
        help="Only print summary counts (works with --format json)",
    )
    pa.add_argument("-o", "--output", help="Write to file instead of stdout")
    pa.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with non-zero status if findings >= threshold are present",
    )

    # check-file
    pc = sub.add_parser("check-file", help="Check a single file")
    pc.add_argument("file", help="Path to a .py or .html file")
    pc.add_argument(
        "--format",
        choices=["text", "sarif", "json"],
        default="text",
    )

    # list-rules
    pr = sub.add_parser("list-rules", help="List all registered rules")
    pr.add_argument("--category", help="Filter by category (SL, HX, DC, DF, NX)")

    return p


def _cmd_audit(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2
    result = api.audit_repo(root)

    threshold = Severity(args.severity_threshold)
    result.findings = result.filter_by_severity(threshold)

    output = _format(result, args.format, summary_only=args.summary_only)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)

    if args.exit_code and result.findings:
        return 1
    return 0


def _cmd_check_file(args: argparse.Namespace) -> int:
    f = Path(args.file).resolve()
    if not f.exists():
        print(f"error: file not found: {f}", file=sys.stderr)
        return 2
    result = api.check_file(f)
    sys.stdout.write(_format(result, args.format))
    return 0


def _cmd_list_rules(args: argparse.Namespace) -> int:
    rules = sorted(RULE_REGISTRY.values(), key=lambda r: r.rule_id)
    if args.category:
        rules = [r for r in rules if r.category == args.category.upper()]
    for r in rules:
        adrs = ", ".join(r.adr_refs)
        print(f"{r.rule_id}  [{r.severity.value:<8}]  {r.description}  ({adrs})")
    return 0


def _format(result, fmt: str, summary_only: bool = False) -> str:
    if fmt == "sarif":
        return sarif.render(result)
    if fmt == "json":
        return json_reporter.render(result, summary_only=summary_only)
    return text.render(result)


if __name__ == "__main__":
    sys.exit(main())
