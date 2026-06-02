"""Base fixer class for code transformations."""

from abc import ABC, abstractmethod
from typing import List, Optional

from ..analyzers.base import Issue


class BaseFixer(ABC):
    """Base class for code fixers."""

    def __init__(self, config=None):
        self.config = config

    @abstractmethod
    def apply_fix(self, source_code: str, issue: Issue) -> Optional[str]:
        """Apply a fix to source code and return modified code."""
        pass

    def can_auto_apply(self, issue: Issue) -> bool:
        """Check if a fix can be automatically applied."""
        if not issue.fix:
            return False
        if not issue.fix.auto_applicable:
            return False
        if self.config and hasattr(self.config, "confidence_threshold"):
            if issue.fix.confidence < self.config.confidence_threshold:
                return False
        return True

    def apply_all_fixes(self, source_code: str, issues: List[Issue]) -> str:
        """Apply all auto-applicable fixes to source code."""
        modified_code = source_code
        applied_count = 0

        for issue in issues:
            if self.can_auto_apply(issue):
                fixed = self.apply_fix(modified_code, issue)
                if fixed:
                    modified_code = fixed
                    applied_count += 1

        return modified_code
