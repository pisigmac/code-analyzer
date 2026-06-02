"""Console reporter using Rich for beautiful terminal output."""

from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..analyzers.base import Issue, Severity


class ConsoleReporter:
    """Reporter that outputs analysis results to the console."""

    SEVERITY_COLORS = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "bright_red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "green",
    }

    SEVERITY_ICONS = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
        Severity.INFO: "🟢",
    }

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def report(
        self,
        issues: List[Issue],
        file_path: Optional[str] = None,
        show_fixes: bool = True,
        show_stats: bool = True,
    ) -> None:
        """Report analysis results to the console."""
        if not issues:
            self.console.print(Panel("✅ No issues found!", style="green"))
            return

        # Header
        header = f"Analysis Results{' - ' + file_path if file_path else ''}"
        self.console.print(Panel(header, style="bold blue"))

        # Issues table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Rule", width=20)
        table.add_column("Location", width=15)
        table.add_column("Message", width=50)

        for issue in issues:
            severity_color = self.SEVERITY_COLORS.get(issue.severity, "white")
            severity_icon = self.SEVERITY_ICONS.get(issue.severity, "⚪")
            location = f"{issue.line}:{issue.column}"

            table.add_row(
                f"{severity_icon} [{severity_color}]{issue.severity.value.upper()}[/{severity_color}]",
                issue.rule_id,
                location,
                issue.message,
            )

        self.console.print(table)

        # Fixes
        if show_fixes:
            self._report_fixes(issues)

        # Statistics
        if show_stats:
            self._report_stats(issues)

    def _report_fixes(self, issues: List[Issue]) -> None:
        """Report available fixes."""
        fixable_issues = [i for i in issues if i.fix]
        if not fixable_issues:
            return

        self.console.print("\n[bold cyan]Suggested Fixes:[/bold cyan]")
        for issue in fixable_issues:
            severity_color = self.SEVERITY_COLORS.get(issue.severity, "white")
            fix_text = Text()
            fix_text.append(f"  {issue.rule_id}: ", style="bold")
            fix_text.append(issue.fix.description, style=severity_color)
            if issue.fix.auto_applicable:
                fix_text.append(" [auto-fixable]", style="green")
            self.console.print(fix_text)

            if issue.fix.replacement_code:
                self.console.print(
                    f"    [dim]→ {issue.fix.replacement_code[:100]}...[/dim]"
                )

    def _report_stats(self, issues: List[Issue]) -> None:
        """Report summary statistics."""
        severity_counts = {}
        for issue in issues:
            severity_counts[issue.severity] = severity_counts.get(issue.severity, 0) + 1

        stats_table = Table(show_header=False, title="Summary")
        stats_table.add_column("Metric", style="bold")
        stats_table.add_column("Count", style="bold")

        total = len(issues)
        fixable = len([i for i in issues if i.fix])

        stats_table.add_row("Total Issues", str(total))
        stats_table.add_row("Fixable Issues", str(fixable))

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                color = self.SEVERITY_COLORS.get(severity, "white")
                stats_table.add_row(
                    f"[{color}]{severity.value.upper()}[/{color}]",
                    str(count),
                )

        self.console.print(stats_table)
