"""Pydantic models for configuration."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OutputFormat(str, Enum):
    """Output format options."""

    RICH = "rich"
    JSON = "json"
    HTML = "html"
    SARIF = "sarif"


class RuleConfig(BaseModel):
    """Configuration for a single rule."""

    name: str = Field(..., description="Rule identifier")
    enabled: bool = Field(default=True, description="Whether rule is active")
    severity: Optional[Severity] = Field(
        default=None, description="Override default severity"
    )
    options: Dict[str, Any] = Field(
        default_factory=dict, description="Rule-specific options"
    )


class AnalyzerConfig(BaseModel):
    """Configuration for an analyzer module."""

    enabled: bool = Field(default=True, description="Whether analyzer is active")
    rules: List[RuleConfig] = Field(
        default_factory=list, description="List of rule configurations"
    )
    options: Dict[str, Any] = Field(
        default_factory=dict, description="Analyzer-specific options"
    )


class FixConfig(BaseModel):
    """Configuration for fix generation."""

    enabled: bool = Field(default=True, description="Whether fix generation is active")
    confidence_threshold: float = Field(
        default=0.8, ge=0.0, le=1.0, description="Minimum confidence for auto-fixes"
    )
    auto_apply_safe_fixes: bool = Field(
        default=False, description="Auto-apply fixes above confidence threshold"
    )
    max_fixes_per_file: int = Field(
        default=10, ge=1, description="Maximum fixes to apply per file"
    )


class OutputConfig(BaseModel):
    """Configuration for output formatting."""

    format: OutputFormat = Field(default=OutputFormat.RICH, description="Output format")
    show_fixes: bool = Field(default=True, description="Show suggested fixes")
    show_explanations: bool = Field(
        default=True, description="Show detailed explanations"
    )
    show_stats: bool = Field(default=True, description="Show summary statistics")
    output_file: Optional[str] = Field(
        default=None, description="Write output to file"
    )


class ProfileConfig(BaseModel):
    """Configuration profile (e.g., fintech, performance-focused)."""

    name: str = Field(..., description="Profile name")
    description: str = Field(default="", description="Profile description")
    severity_overrides: Dict[str, Severity] = Field(
        default_factory=dict, description="Rule severity overrides"
    )
    rule_overrides: Dict[str, bool] = Field(
        default_factory=dict, description="Rule enable/disable overrides"
    )


class CodeAnalyzerConfig(BaseModel):
    """Main configuration for the code analyzer."""

    profile: str = Field(default="default", description="Active configuration profile")
    severity_threshold: Severity = Field(
        default=Severity.LOW, description="Minimum severity to report"
    )

    analyzers: Dict[str, AnalyzerConfig] = Field(
        default_factory=lambda: {
            "performance": AnalyzerConfig(),
            "security": AnalyzerConfig(),
        },
        description="Analyzer configurations",
    )

    fix_generation: FixConfig = Field(
        default_factory=FixConfig, description="Fix generation settings"
    )

    output: OutputConfig = Field(
        default_factory=OutputConfig, description="Output settings"
    )

    profiles: Dict[str, ProfileConfig] = Field(
        default_factory=dict, description="Custom profile definitions"
    )

    @field_validator("analyzers")
    @classmethod
    def validate_analyzers(cls, v: Dict[str, AnalyzerConfig]) -> Dict[str, AnalyzerConfig]:
        """Ensure at least one analyzer is enabled."""
        if not any(a.enabled for a in v.values()):
            raise ValueError("At least one analyzer must be enabled")
        return v

    class Config:
        validate_assignment = True
