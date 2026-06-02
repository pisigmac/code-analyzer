"""Configuration loader for YAML/TOML/JSON config files."""

import os
from pathlib import Path
from typing import Optional, Union

import yaml

from .models import CodeAnalyzerConfig, ProfileConfig


class ConfigLoader:
    """Loads configuration from files with profile support."""

    DEFAULT_CONFIG_NAMES = [
        "code-analyzer.yaml",
        "code-analyzer.yml",
        ".code-analyzer.yaml",
        ".code-analyzer.yml",
    ]

    def __init__(self, config_path: Optional[Union[str, Path]] = None):
        self.config_path = self._resolve_config_path(config_path)
        self._default_profiles = self._load_builtin_profiles()

    def _resolve_config_path(
        self, config_path: Optional[Union[str, Path]]
    ) -> Optional[Path]:
        """Resolve config file path."""
        if config_path:
            path = Path(config_path)
            if path.exists():
                return path
            raise FileNotFoundError(f"Config file not found: {config_path}")

        # Search in current directory and parent directories
        current = Path.cwd()
        for _ in range(10):  # Search up to 10 levels
            for name in self.DEFAULT_CONFIG_NAMES:
                candidate = current / name
                if candidate.exists():
                    return candidate
            parent = current.parent
            if parent == current:
                break
            current = parent

        return None

    def _load_builtin_profiles(self) -> dict:
        """Load built-in configuration profiles."""
        profiles_dir = Path(__file__).parent / "profiles"
        profiles = {}

        if profiles_dir.exists():
            for profile_file in profiles_dir.glob("*.yaml"):
                name = profile_file.stem
                with open(profile_file, "r") as f:
                    data = yaml.safe_load(f)
                    profiles[name] = ProfileConfig(**data)

        return profiles

    def load(self) -> CodeAnalyzerConfig:
        """Load configuration from file or return defaults."""
        if not self.config_path:
            return CodeAnalyzerConfig()

        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)

        config = CodeAnalyzerConfig(**data)

        # Apply profile overrides
        if config.profile in self._default_profiles:
            profile = self._default_profiles[config.profile]
            config = self._apply_profile(config, profile)

        if config.profile in config.profiles:
            profile = config.profiles[config.profile]
            config = self._apply_profile(config, profile)

        return config

    def _apply_profile(
        self, config: CodeAnalyzerConfig, profile: ProfileConfig
    ) -> CodeAnalyzerConfig:
        """Apply profile overrides to configuration."""
        for analyzer in config.analyzers.values():
            for rule in analyzer.rules:
                if rule.name in profile.severity_overrides:
                    rule.severity = profile.severity_overrides[rule.name]
                if rule.name in profile.rule_overrides:
                    rule.enabled = profile.rule_overrides[rule.name]
        return config

    def list_profiles(self) -> list:
        """List available configuration profiles."""
        builtin = list(self._default_profiles.keys())
        return builtin
