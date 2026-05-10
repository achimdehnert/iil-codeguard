"""SL-001..006: Detect ORM access in Django views.

Per ADR-192 v1.1 §1: Inversion approach — detect *presence* of ORM access
rather than *absence* of service-layer delegation. Inversion is robust because
absence of ORM is structurally provable; presence of service-calls is not
(aliases, mixins, dynamic dispatch).

Supports FBV, CBV (form_valid, dispatch, get_queryset, ...), and async views.
"""

from __future__ import annotations

import ast
from pathlib import Path

from iil_codeguard.domain import (
    Finding,
    Location,
    RuleMeta,
    Severity,
    register_rule,
)

# Rule registration ----------------------------------------------------------

register_rule(RuleMeta(
    rule_id="SL-001",
    name="orm-in-view",
    description="View contains direct ORM access (Model.objects.*). Move to services.py.",
    severity=Severity.ERROR,
    category="SL",
    adr_refs=("ADR-009", "ADR-192"),
))
register_rule(RuleMeta(
    rule_id="SL-002",
    name="transaction-in-view",
    description="View contains transaction.atomic(). Transaction handling belongs in services.",
    severity=Severity.ERROR,
    category="SL",
    adr_refs=("ADR-009", "ADR-192"),
))
register_rule(RuleMeta(
    rule_id="SL-003",
    name="queryset-chains-in-view",
    description="View contains queryset chain (select_related/prefetch_related). Move to services.",
    severity=Severity.WARNING,
    category="SL",
    adr_refs=("ADR-009", "ADR-192"),
))
register_rule(RuleMeta(
    rule_id="SL-004",
    name="model-import-in-view",
    description="View imports Django model directly. Use services to wrap data access.",
    severity=Severity.WARNING,
    category="SL",
    adr_refs=("ADR-009", "ADR-192"),
))
register_rule(RuleMeta(
    rule_id="SL-005",
    name="raw-sql-in-view",
    description="View contains raw SQL (connection.cursor / .raw()). Move to services.",
    severity=Severity.ERROR,
    category="SL",
    adr_refs=("ADR-009", "ADR-192"),
))
register_rule(RuleMeta(
    rule_id="SL-006",
    name="missing-services-py",
    description="App has views.py but no services.py — service-layer not initialized.",
    severity=Severity.INFO,
    category="SL",
    adr_refs=("ADR-009", "ADR-192"),
))


# AST helpers ----------------------------------------------------------------

# Method names exposed on managers / querysets that indicate ORM data access.
_ORM_METHODS = frozenset({
    "filter", "exclude", "get", "get_or_create", "create", "update_or_create",
    "delete", "save", "bulk_create", "bulk_update", "update", "all", "first",
    "last", "count", "exists", "values", "values_list", "annotate", "aggregate",
    "in_bulk", "earliest", "latest",
    # async variants (Django 4.1+)
    "aget", "aget_or_create", "acreate", "aupdate_or_create", "adelete",
    "asave", "aupdate", "afirst", "alast", "acount", "aexists",
})

_QUERYSET_OPTIMIZATION = frozenset({"select_related", "prefetch_related"})

_RAW_SQL_NAMES = frozenset({"raw", "extra"})


class ViewVisitor(ast.NodeVisitor):
    """Walk a Django views.py module and collect SL-* findings."""

    def __init__(self, file_path: Path):
        self.file_path = str(file_path)
        self.findings: list[Finding] = []
        self._scope: list[str] = []  # function/class context stack

    # Context tracking -------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope.append(f"async {node.name}")
        self.generic_visit(node)
        self._scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope.append(f"class {node.name}")
        self.generic_visit(node)
        self._scope.pop()

    # Detection rules --------------------------------------------------------
    def visit_Attribute(self, node: ast.Attribute) -> None:
        # SL-001: SomeModel.objects (manager access)
        if isinstance(node.value, ast.Name) and node.attr == "objects":
            self._add(
                rule_id="SL-001",
                severity=Severity.ERROR,
                line=node.lineno,
                col=node.col_offset + 1,
                message=(
                    f"Direct ORM access via {node.value.id}.objects in "
                    f"{self._scope_str() or '<module>'}"
                ),
                fix_hint=(
                    f"Move query to services.py and call it from the view "
                    f"(e.g. {node.value.id.lower()}_service.list_active())"
                ),
                context={"model": node.value.id},
            )
        # SL-003: queryset chain (select_related / prefetch_related)
        elif node.attr in _QUERYSET_OPTIMIZATION:
            self._add(
                rule_id="SL-003",
                severity=Severity.WARNING,
                line=node.lineno,
                col=node.col_offset + 1,
                message=(
                    f"Queryset optimization '{node.attr}' in "
                    f"{self._scope_str() or '<module>'} — belongs in services"
                ),
                context={"method": node.attr},
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # SL-002: transaction.atomic(...)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "atomic"
            and isinstance(func.value, ast.Name)
            and func.value.id == "transaction"
        ):
            self._add(
                rule_id="SL-002",
                severity=Severity.ERROR,
                line=node.lineno,
                col=node.col_offset + 1,
                message=(
                    f"transaction.atomic() in {self._scope_str() or '<module>'} "
                    f"— transaction handling belongs in services"
                ),
                fix_hint="Wrap the service call in transaction.atomic, not the view",
            )
        # SL-005: raw SQL — connection.cursor() or .raw(...)
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in _RAW_SQL_NAMES
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "objects"
        ):
            self._add(
                rule_id="SL-005",
                severity=Severity.ERROR,
                line=node.lineno,
                col=node.col_offset + 1,
                message=(
                    f"Raw SQL via .{func.attr}() in "
                    f"{self._scope_str() or '<module>'} — move to services"
                ),
            )
        elif (
            isinstance(func, ast.Attribute)
            and func.attr == "cursor"
            and isinstance(func.value, ast.Name)
            and func.value.id == "connection"
        ):
            self._add(
                rule_id="SL-005",
                severity=Severity.ERROR,
                line=node.lineno,
                col=node.col_offset + 1,
                message=(
                    f"connection.cursor() in {self._scope_str() or '<module>'} "
                    f"— move raw SQL to services"
                ),
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # SL-004: importing from .models or models.X in views.py
        if node.module and (
            node.module == "models"
            or node.module.endswith(".models")
            or ".models." in node.module
        ):
            for alias in node.names:
                self._add(
                    rule_id="SL-004",
                    severity=Severity.WARNING,
                    line=node.lineno,
                    col=node.col_offset + 1,
                    message=f"View imports model '{alias.name}' directly from {node.module}",
                    fix_hint=(
                        "Replace direct model imports with service-layer calls "
                        f"(e.g. from .services import get_{alias.name.lower()})"
                    ),
                    context={"module": node.module, "name": alias.name},
                )
        self.generic_visit(node)

    # Helpers ----------------------------------------------------------------
    def _scope_str(self) -> str:
        return " > ".join(self._scope)

    def _add(
        self,
        rule_id: str,
        severity: Severity,
        line: int,
        col: int,
        message: str,
        fix_hint: str | None = None,
        context: dict[str, str] | None = None,
    ) -> None:
        self.findings.append(Finding(
            rule_id=rule_id,
            severity=severity,
            message=message,
            location=Location(file_path=self.file_path, start_line=line, start_column=col),
            fix_hint=fix_hint,
            context=context or {},
        ))


# Public API -----------------------------------------------------------------

def check_file(file_path: Path) -> list[Finding]:
    """Check a single Python file for ORM-in-view violations.

    The file should be a Django views.py (or a *.py file in a views/ package).
    Other files return [] silently.
    """
    if not _is_view_file(file_path):
        return []
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []
    visitor = ViewVisitor(file_path)
    visitor.visit(tree)
    return visitor.findings


def check_app(app_dir: Path) -> list[Finding]:
    """Scan all view files in an app directory.

    Also reports SL-006 (missing services.py) if applicable.
    """
    findings: list[Finding] = []
    view_files = _find_view_files(app_dir)
    if not view_files:
        return findings
    has_services = any(
        (app_dir / "services.py").exists()
        or (app_dir / "services").is_dir()
        for _ in [0]
    )
    for vf in view_files:
        findings.extend(check_file(vf))
    if not has_services:
        # SL-006 is a once-per-app finding pinned to the views file
        findings.append(Finding(
            rule_id="SL-006",
            severity=Severity.INFO,
            message=f"App '{app_dir.name}' has views but no services.py — service-layer missing",
            location=Location(file_path=str(view_files[0]), start_line=1, start_column=1),
        ))
    return findings


def check_repo(repo_root: Path) -> list[Finding]:
    """Scan an entire repo for ORM-in-view violations across all apps."""
    findings: list[Finding] = []
    for view_file in _find_view_files_recursive(repo_root):
        findings.extend(check_file(view_file))
    return findings


# File discovery -------------------------------------------------------------

def _is_view_file(file_path: Path) -> bool:
    """Heuristic: a Python file is a view file if its name is views.py
    or it lives inside a views/ package."""
    if file_path.name == "views.py":
        return True
    parts = file_path.parts
    return "views" in parts and file_path.suffix == ".py"


def _find_view_files(directory: Path) -> list[Path]:
    """Find views.py files directly in this directory (1 level)."""
    candidates: list[Path] = []
    if not directory.is_dir():
        return candidates
    if (directory / "views.py").exists():
        candidates.append(directory / "views.py")
    views_pkg = directory / "views"
    if views_pkg.is_dir():
        candidates.extend(p for p in views_pkg.rglob("*.py") if p.name != "__init__.py")
    return candidates


_EXCLUDE_DIRS = frozenset({
    ".venv", "venv", "env", "__pycache__", ".git", ".tox", "node_modules",
    "site-packages", "dist", "build", ".pytest_cache", ".ruff_cache",
})


def _find_view_files_recursive(root: Path) -> list[Path]:
    """Recursively find views.py and views/*.py, excluding common non-source dirs."""
    found: list[Path] = []
    for path in root.rglob("views.py"):
        if not _is_excluded(path):
            found.append(path)
    for path in root.rglob("views/*.py"):
        if not _is_excluded(path) and path.name != "__init__.py":
            found.append(path)
    return sorted(set(found))


def _is_excluded(path: Path) -> bool:
    return any(part in _EXCLUDE_DIRS for part in path.parts)
