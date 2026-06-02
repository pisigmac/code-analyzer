# Code Analyzer

AI-powered code performance, security, and fix generator for Python.

## Features

- **Performance Analysis**: Detects inefficient patterns like loops that could be list comprehensions, string concatenation in loops, unnecessary `list()` calls, imports inside functions, and repeated dict/attribute lookups
- **Security Analysis**: Detects SQL injection, hardcoded secrets, eval/exec usage, unsafe pickle, weak hashing, debug mode, weak crypto, and insecure temp files
- **Configuration-Driven**: Uses YAML configuration with profiles (default, fintech, performance)
- **Fix Generation**: Suggests and can auto-apply fixes for detected issues
- **Multiple Output Formats**: Rich terminal output, JSON, and HTML reports

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

### Analyze files or directories

```bash
# Analyze a single file
code-analyzer analyze myfile.py

# Analyze a directory
code-analyzer analyze src/

# Use a specific profile
code-analyzer analyze src/ --profile fintech

# Output as JSON
code-analyzer analyze src/ --output json

# Generate HTML report
code-analyzer analyze src/ --output html --output-file report.html

# Auto-apply safe fixes
code-analyzer analyze src/ --apply-fixes
```

### Initialize configuration

```bash
code-analyzer init
code-analyzer init --profile fintech
```

### List profiles

```bash
code-analyzer profiles
```

## Configuration

Create a `code-analyzer.yaml` file:

```yaml
profile: fintech

severity_threshold: high

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
```

## Architecture

The analyzer uses Python's AST module for static analysis with a visitor pattern:

- **BaseAnalyzer**: Abstract base with issue tracking and fix generation
- **PerformanceAnalyzer**: Detects performance anti-patterns
- **SecurityAnalyzer**: Detects security vulnerabilities
- **ASTFixer**: Applies AST transformations for auto-fixable issues
- **Reporters**: Console (Rich), JSON, and HTML output

## Testing

```bash
pytest tests/ -v
```

## License

MIT
