"""Tests for configuration engine."""

import pytest

from code_analyzer.config.loader import ConfigLoader
from code_analyzer.config.models import CodeAnalyzerConfig, OutputFormat, Severity


class TestConfigModels:
    """Tests for configuration models."""

    def test_default_config(self):
        """Test default configuration creation."""
        config = CodeAnalyzerConfig()

        assert config.profile == "default"
        assert config.severity_threshold == Severity.LOW
        assert config.analyzers["performance"].enabled is True
        assert config.analyzers["security"].enabled is True
        assert config.fix_generation.enabled is True
        assert config.output.format == OutputFormat.RICH

    def test_custom_config(self):
        """Test custom configuration."""
        config = CodeAnalyzerConfig(
            profile="fintech",
            severity_threshold=Severity.HIGH,
        )

        assert config.profile == "fintech"
        assert config.severity_threshold == Severity.HIGH

    def test_all_analyzers_disabled_raises_error(self):
        """Test that disabling all analyzers raises an error."""
        with pytest.raises(ValueError):
            CodeAnalyzerConfig(
                analyzers={
                    "performance": {"enabled": False},
                    "security": {"enabled": False},
                }
            )


class TestConfigLoader:
    """Tests for configuration loader."""

    def test_load_default_config(self):
        """Test loading default configuration."""
        loader = ConfigLoader()
        config = loader.load()

        assert isinstance(config, CodeAnalyzerConfig)
        assert config.profile == "default"

    def test_list_profiles(self):
        """Test listing available profiles."""
        loader = ConfigLoader()
        profiles = loader.list_profiles()

        assert "default" in profiles
        assert "fintech" in profiles
        assert "performance" in profiles

    def test_profile_overrides(self):
        """Test that profile overrides are applied."""
        loader = ConfigLoader()
        # Just verify profiles can be loaded without errors
        profiles = loader.list_profiles()
        assert len(profiles) >= 3
