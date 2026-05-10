"""Human-readable text reporter for terminal output."""

from __future__ import annotations

import sys
from io import StringIO

from iil_codeguard.domain import AuditResult, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.ERROR: "\033[31m",       # red
    Severity.WARNING: "\033[33m",     # yellow
    Severity.INFO: "\033[36m",        # cyan
}
_RESET = "\033[0m"


def render(result: AuditResult, use_color: bool | None = None) -> str:
    """Render an audit result as a human-readable string."""
    if use_color is None:
        use_color = sys.stdout.isatty()

    out = StringIO()

    if not result.findings:
        out.write(_color(
            f"No findings ({result.files_scanned} files scanned in {result.duration_ms} ms)\n",
            "\033[32m", use_color,
        ))
        return out.getvalue()

    # Group by file
    by_file: dict[str, list] = {}
    for f in sorted(
        result.findings,
        key=lambda x: (x.location.file_path, x.location.start_line),
    ):
        by_file.setdefault(f.location.file_path, []).append(f)

    for file_path, findings in by_file.items():
        out.write(f"\n{_color(file_path, '\033[1m', use_color)}\n")
        for f in findings:
            color = _SEVERITY_COLORS[f.severity]
            severity_str = f.severity.value.upper().ljust(8)
            location = f"{f.location.start_line}:{f.location.start_column}"
            out.write(
                f"  {_color(severity_str, color, use_color)} "
                f"{f.rule_id}  {location}  {f.message}\n"
            )
            if f.fix_hint:
                out.write(f"           {_color('hint:', '\033[2m', use_color)} {f.fix_hint}\n")

    # Summary
    counts = result.counts_by_severity()
    parts = []
    for sev in (Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO):
        n = counts[sev.value]
        if n:
            color = _SEVERITY_COLORS[sev]
            parts.append(_color(f"{n} {sev.value}", color, use_color))
    summary = ", ".join(parts) or "0 findings"
    out.write(
        f"\nSummary: {summary} "
        f"({result.files_scanned} files, {result.duration_ms} ms)\n"
    )
    return out.getvalue()


def _color(text: str, code: str, use_color: bool) -> str:
    return f"{code}{text}{_RESET}" if use_color else text
