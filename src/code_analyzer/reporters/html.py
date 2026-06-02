"""HTML reporter for generating HTML reports."""

from typing import List, Optional

from jinja2 import Template

from ..analyzers.base import Issue, Severity


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Code Analyzer Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { font-size: 2em; margin-bottom: 10px; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .stat-card h3 { font-size: 0.9em; color: #666; margin-bottom: 10px; }
        .stat-card .number { font-size: 2em; font-weight: bold; }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #17a2b8; }
        .severity-info { color: #28a745; }
        .issues-table {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f8f9fa;
            padding: 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }
        td {
            padding: 15px;
            border-bottom: 1px solid #dee2e6;
        }
        tr:hover { background: #f8f9fa; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-critical { background: #f8d7da; color: #721c24; }
        .badge-high { background: #fff3cd; color: #856404; }
        .badge-medium { background: #d1ecf1; color: #0c5460; }
        .badge-low { background: #d4edda; color: #155724; }
        .badge-info { background: #e2e3e5; color: #383d41; }
        .fix-box {
            background: #f8f9fa;
            border-left: 4px solid #28a745;
            padding: 10px;
            margin-top: 10px;
            border-radius: 4px;
        }
        .fix-box code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .location {
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            word-break: break-all;
        }
        .location small { color: #888; }
            text-align: center;
            padding: 60px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .no-issues h2 { color: #28a745; margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Code Analyzer Report</h1>
            <p>{{ file_path or 'Analysis Results' }}</p>
        </div>

        {% if issues %}
        <div class="stats">
            <div class="stat-card">
                <h3>Total Issues</h3>
                <div class="number">{{ total_issues }}</div>
            </div>
            <div class="stat-card">
                <h3>Fixable Issues</h3>
                <div class="number">{{ fixable_issues }}</div>
            </div>
            {% for severity, count in severity_counts.items() %}
            <div class="stat-card">
                <h3>{{ severity.upper() }}</h3>
                <div class="number severity-{{ severity }}">{{ count }}</div>
            </div>
            {% endfor %}
        </div>

        <div class="issues-table">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>Location</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    {% for issue in issues %}
                    <tr>
                        <td>
                            <span class="badge badge-{{ issue.severity.value }}">
                                {{ issue.severity.value.upper() }}
                            </span>
                        </td>
                        <td>{{ issue.rule_id }}</td>
                        <td class="location">{{ issue.file_path or '' }}<br><small>{{ issue.line }}:{{ issue.column }}</small></td>
                        <td>
                            {{ issue.message }}
                            {% if issue.fix %}
                            <div class="fix-box">
                                <strong>💡 Fix:</strong> {{ issue.fix.description }}
                                {% if issue.fix.auto_applicable %}
                                <span style="color: #28a745;">[auto-fixable]</span>
                                {% endif %}
                                <br>
                                <code>{{ issue.fix.replacement_code[:100] }}{% if issue.fix.replacement_code|length > 100 %}...{% endif %}</code>
                            </div>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <div class="no-issues">
            <h2>✅ No Issues Found</h2>
            <p>Your code looks great! No performance or security issues were detected.</p>
        </div>
        {% endif %}
    </div>
</body>
</html>
"""


class HTMLReporter:
    """Reporter that generates HTML reports."""

    def report(
        self,
        issues: List[Issue],
        file_path: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> str:
        """Generate an HTML report."""
        template = Template(HTML_TEMPLATE)

        severity_counts = {}
        for issue in issues:
            severity_counts[issue.severity.value] = severity_counts.get(
                issue.severity.value, 0
            ) + 1

        html = template.render(
            issues=issues,
            file_path=file_path,
            total_issues=len(issues),
            fixable_issues=len([i for i in issues if i.fix]),
            severity_counts=severity_counts,
        )

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html)

        return html
