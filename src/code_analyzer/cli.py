"""Command-line interface for code analyzer."""

from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .analyzers.performance import PerformanceAnalyzer
from .analyzers.security import SecurityAnalyzer
from .analyzers.ai_security import AISecurityAnalyzer
from .config.loader import ConfigLoader
from .config.models import OutputFormat
from .fixers.ast_fixer import ASTFixer
from .reporters.console import ConsoleReporter
from .reporters.html import HTMLReporter
from .reporters.json_reporter import JSONReporter

app = typer.Typer(
    name="code-analyzer",
    help="AI-powered code performance, security, and fix generator",
    no_args_is_help=True,
)
console = Console()


@app.command()
def analyze(
    paths: List[Path] = typer.Argument(
        ...,
        help="Files or directories to analyze",
        exists=True,
        readable=True,
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
        exists=True,
        readable=True,
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="Configuration profile to use",
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.RICH,
        "--output",
        "-o",
        help="Output format",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-f",
        help="Write output to file",
    ),
    severity_threshold: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Minimum severity to report (critical, high, medium, low, info)",
    ),
    apply_fixes: bool = typer.Option(
        False,
        "--apply-fixes",
        "-a",
        help="Automatically apply safe fixes",
    ),
    show_fixes: bool = typer.Option(
        True,
        "--show-fixes/--hide-fixes",
        help="Show suggested fixes",
    ),
    show_stats: bool = typer.Option(
        True,
        "--show-stats/--hide-stats",
        help="Show summary statistics",
    ),
) -> None:
    """Analyze Python code for performance and security issues."""
    # Load configuration
    config_loader = ConfigLoader(config)
    analyzer_config = config_loader.load()

    # Override with CLI options
    if severity_threshold:
        analyzer_config.severity_threshold = severity_threshold
    if profile:
        analyzer_config.profile = profile
    if output:
        analyzer_config.output.format = output

    # Collect files to analyze
    files_to_analyze = []
    for path in paths:
        if path.is_file() and path.suffix == ".py":
            files_to_analyze.append(path)
        elif path.is_dir():
            files_to_analyze.extend(path.rglob("*.py"))

    if not files_to_analyze:
        console.print("[yellow]No Python files found to analyze.[/yellow]")
        raise typer.Exit(0)

    # Run analysis
    all_issues = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            f"Analyzing {len(files_to_analyze)} files...", total=len(files_to_analyze)
        )

        for file_path in files_to_analyze:
            progress.update(task, description=f"Analyzing {file_path.name}...")

            try:
                source_code = file_path.read_text()
                issues = _analyze_file(source_code, str(file_path), analyzer_config)
                all_issues.extend(issues)
            except (OSError, ValueError, RecursionError) as e:
                console.print(f"[red]Error analyzing {file_path}: {e}[/red]")

            progress.advance(task)

    # Filter by severity threshold
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    threshold_level = severity_order.get(analyzer_config.severity_threshold.value, 4)
    filtered_issues = [
        i
        for i in all_issues
        if severity_order.get(i.severity.value, 4) <= threshold_level
    ]

    # Apply fixes if requested
    if apply_fixes:
        fixer = ASTFixer(analyzer_config.fix_generation)
        for file_path in files_to_analyze:
            file_issues = [i for i in filtered_issues if i.file_path == str(file_path)]
            if file_issues:
                try:
                    source_code = file_path.read_text()
                    fixed_code = fixer.apply_all_fixes(source_code, file_issues)
                    if fixed_code != source_code:
                        file_path.write_text(fixed_code)
                        console.print(
                            f"[green]Applied fixes to {file_path.name}[/green]"
                        )
                except (OSError, ValueError) as e:
                    console.print(f"[red]Error fixing {file_path}: {e}[/red]")

    # Report results
    _report_results(
        filtered_issues,
        output=analyzer_config.output.format,
        output_file=output_file,
        show_fixes=show_fixes and analyzer_config.output.show_fixes,
        show_stats=show_stats and analyzer_config.output.show_stats,
    )

    # Exit with error code if critical/high issues found
    critical_high = [i for i in filtered_issues if i.severity.value in {"critical", "high"}]
    if critical_high:
        raise typer.Exit(1)


def _analyzer_enabled(config, name: str) -> bool:
    """Check if an analyzer is enabled, handling both dict and object configs."""
    analyzer = config.analyzers.get(name, {})
    if hasattr(analyzer, "enabled"):
        return analyzer.enabled
    if isinstance(analyzer, dict):
        return analyzer.get("enabled", True)
    return True


def _analyze_file(source_code: str, file_path: str, config) -> list:
    """Analyze a single file."""
    issues = []

    if _analyzer_enabled(config, "performance"):
        issues.extend(PerformanceAnalyzer(config).analyze(source_code, file_path))

    if _analyzer_enabled(config, "security"):
        issues.extend(SecurityAnalyzer(config).analyze(source_code, file_path))

    if _analyzer_enabled(config, "ai_security"):
        issues.extend(AISecurityAnalyzer(config).analyze(source_code, file_path))

    return issues


def _report_results(
    issues,
    output: OutputFormat,
    output_file: Optional[Path],
    show_fixes: bool,
    show_stats: bool,
) -> None:
    """Report analysis results."""
    if output == OutputFormat.RICH:
        reporter = ConsoleReporter(console)
        reporter.report(issues, show_fixes=show_fixes, show_stats=show_stats)
    elif output == OutputFormat.JSON:
        reporter = JSONReporter()
        json_str = reporter.report(
            issues, output_file=str(output_file) if output_file else None
        )
        if not output_file:
            console.print(json_str)
    elif output == OutputFormat.HTML:
        reporter = HTMLReporter()
        html = reporter.report(
            issues, output_file=str(output_file) if output_file else None
        )
        if not output_file:
            console.print(html)
    else:
        console.print(f"[red]Unsupported output format: {output}[/red]")


@app.command()
def profiles() -> None:
    """List available configuration profiles."""
    loader = ConfigLoader()
    available_profiles = loader.list_profiles()

    console.print("[bold cyan]Available Profiles:[/bold cyan]")
    for profile in available_profiles:
        console.print(f"  • {profile}")


@app.command()
def init(
    path: Path = typer.Argument(
        ".",
        help="Directory to initialize configuration in",
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="Default profile to use",
    ),
) -> None:
    """Initialize a new code-analyzer configuration file."""
    config_path = path / "code-analyzer.yaml"

    if config_path.exists():
        overwrite = typer.confirm(
            f"Configuration file already exists at {config_path}. Overwrite?"
        )
        if not overwrite:
            raise typer.Abort()

    config_content = f"""# Code Analyzer Configuration
profile: {profile}

severity_threshold: low

analyzers:
  performance:
    enabled: true
  security:
    enabled: true

fix_generation:
  enabled: true
  confidence_threshold: 0.8
  auto_apply_safe_fixes: false

output:
  format: rich
  show_fixes: true
  show_explanations: true
  show_stats: true
"""

    config_path.write_text(config_content)
    console.print(f"[green]Created configuration file: {config_path}[/green]")


def main() -> None:
    """Entry point for the CLI."""
    app()
