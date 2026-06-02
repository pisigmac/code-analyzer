"""JSON reporter for machine-readable output."""

import json
from typing import List, Optional

from ..analyzers.base import Issue


class JSONReporter:
    """Reporter that outputs analysis results as JSON."""

    def report(
        self,
        issues: List[Issue],
        file_path: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> str:
        """Report analysis results as JSON string."""
        result = {
            "file": file_path,
            "summary": {
                "total_issues": len(issues),
                "fixable_issues": len([i for i in issues if i.fix]),
                "severity_counts": self._count_by_severity(issues),
            },
            "issues": [self._issue_to_dict(issue) for issue in issues],
        }

        json_str = json.dumps(result, indent=2)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(json_str)

        return json_str

    def _issue_to_dict(self, issue: Issue) -> dict:
        """Convert an Issue to a dictionary."""
        result = {
            "rule_id": issue.rule_id,
            "message": issue.message,
            "severity": issue.severity.value,
            "location": {
                "line": issue.line,
                "column": issue.column,
                "end_line": issue.end_line,
                "end_column": issue.end_column,
            },
            "file": issue.file_path,
        }

        if issue.fix:
            result["fix"] = {
                "description": issue.fix.description,
                "replacement_code": issue.fix.replacement_code,
                "confidence": issue.fix.confidence,
                "auto_applicable": issue.fix.auto_applicable,
            }

        if issue.metadata:
            result["metadata"] = issue.metadata

        return result

    def _count_by_severity(self, issues: List[Issue]) -> dict:
        """Count issues by severity."""
        counts = {}
        for issue in issues:
            counts[issue.severity.value] = counts.get(issue.severity.value, 0) + 1
        return counts
