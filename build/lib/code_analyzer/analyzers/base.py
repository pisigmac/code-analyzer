"""Base analyzer classes and data models."""

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Fix:
    """Represents a suggested fix for an issue."""

    description: str
    replacement_code: str
    confidence: float = 0.8
    auto_applicable: bool = False


@dataclass
class Issue:
    """Represents a detected code issue."""

    rule_id: str
    message: str
    severity: Severity
    line: int
    column: int
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    file_path: Optional[str] = None
    fix: Optional[Fix] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        location = f"{self.file_path or 'unknown'}:{self.line}:{self.column}"
        return f"[{self.severity.value.upper()}] {self.rule_id}: {self.message} ({location})"


@dataclass
class AnalysisContext:
    """Context for code analysis."""

    file_path: Optional[str] = None
    source_code: Optional[str] = None
    config: Optional[Any] = None


class BaseAnalyzer(ast.NodeVisitor):
    """Base class for all code analyzers."""

    def __init__(self, config: Optional[Any] = None):
        self.config = config
        self.issues: List[Issue] = []
        self.context: Optional[AnalysisContext] = None

    def analyze(
        self, source_code: str, file_path: Optional[str] = None
    ) -> List[Issue]:
        """Analyze source code and return detected issues."""
        self.issues = []
        self.context = AnalysisContext(
            file_path=file_path,
            source_code=source_code,
            config=self.config,
        )

        try:
            tree = ast.parse(source_code)
            self.visit(tree)
        except SyntaxError as e:
            self.issues.append(
                Issue(
                    rule_id="syntax_error",
                    message=f"Syntax error: {e.msg}",
                    severity=Severity.CRITICAL,
                    line=e.lineno or 1,
                    column=e.offset or 1,
                    file_path=file_path,
                )
            )

        return self.issues

    def add_issue(
        self,
        rule_id: str,
        message: str,
        severity: Severity,
        node: ast.AST,
        fix: Optional[Fix] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Issue:
        """Add a detected issue."""
        issue = Issue(
            rule_id=rule_id,
            message=message,
            severity=severity,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 1),
            end_line=getattr(node, "end_lineno", None),
            end_column=getattr(node, "end_col_offset", None),
            file_path=self.context.file_path if self.context else None,
            fix=fix,
            metadata=metadata or {},
        )
        self.issues.append(issue)
        return issue

    def is_rule_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled in configuration."""
        if not self.config:
            return True
        # Check if rule is explicitly disabled
        if hasattr(self.config, "rule_overrides"):
            if rule_id in self.config.rule_overrides:
                return self.config.rule_overrides[rule_id]
        return True

    def get_rule_severity(self, rule_id: str, default: Severity) -> Severity:
        """Get severity for a rule, considering profile overrides."""
        if not self.config:
            return default
        if hasattr(self.config, "severity_overrides"):
            if rule_id in self.config.severity_overrides:
                return self.config.severity_overrides[rule_id]
        return default
