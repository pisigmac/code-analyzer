"""AI security analyzer - detects AI/ML-specific security and safety issues."""

import ast
import re

from .base import BaseAnalyzer, Fix, Severity


class AISecurityAnalyzer(BaseAnalyzer):
    """Analyzer for AI/ML-specific security and safety issues."""

    RULES = {
        "detect_prompt_injection": {
            "message": "User input concatenated directly into LLM prompt - potential prompt injection",
            "severity": Severity.CRITICAL,
            "fixable": False,
        },
        "detect_ai_hardcoded_key": {
            "message": "Hardcoded AI provider API key - use environment variables",
            "severity": Severity.CRITICAL,
            "fixable": True,
        },
        "detect_torch_load_unsafe": {
            "message": "torch.load() without weights_only=True - allows arbitrary code execution via pickle",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_joblib_load_unsafe": {
            "message": "joblib.load() on potentially untrusted path - arbitrary code execution risk",
            "severity": Severity.HIGH,
            "fixable": False,
        },
        "detect_keras_load_unsafe": {
            "message": "Keras/TF model loaded from potentially untrusted source",
            "severity": Severity.HIGH,
            "fixable": False,
        },
        "detect_pii_logging": {
            "message": "Model input/output logged - may expose PII in logs",
            "severity": Severity.MEDIUM,
            "fixable": False,
        },
        "detect_missing_seed": {
            "message": "No random seed set - results are non-reproducible",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_api_call_in_loop": {
            "message": "LLM API call inside loop without visible limit - unbounded cost risk",
            "severity": Severity.HIGH,
            "fixable": False,
        },
        "detect_api_call_no_timeout": {
            "message": "LLM API call without timeout or max_tokens - may hang or incur large cost",
            "severity": Severity.MEDIUM,
            "fixable": True,
        },
        "detect_model_from_url": {
            "message": "Model loaded from URL without hash verification - supply chain risk",
            "severity": Severity.HIGH,
            "fixable": False,
        },
    }

    AI_KEY_PATTERNS = [
        (r'openai_api_key\s*=\s*["\'][^"\']+["\']', "OPENAI_API_KEY"),
        (r'anthropic_api_key\s*=\s*["\'][^"\']+["\']', "ANTHROPIC_API_KEY"),
        (r'huggingface_token\s*=\s*["\'][^"\']+["\']', "HUGGINGFACE_TOKEN"),
        (r'cohere_api_key\s*=\s*["\'][^"\']+["\']', "COHERE_API_KEY"),
        (r'gemini_api_key\s*=\s*["\'][^"\']+["\']', "GEMINI_API_KEY"),
        (r'hf_token\s*=\s*["\'][^"\']+["\']', "HF_TOKEN"),
        (r'replicate_api_token\s*=\s*["\'][^"\']+["\']', "REPLICATE_API_TOKEN"),
    ]

    LLM_API_METHODS = {
        "create", "complete", "chat", "generate", "invoke", "predict", "run",
        "completion", "acreate", "agenerate",
    }

    LLM_CLIENT_NAMES = {
        "openai", "client", "llm", "model", "anthropic", "cohere", "gemini",
        "chat", "completions",
    }

    def __init__(self, config=None):
        super().__init__(config)
        self._loop_depth = 0
        self._has_seed = False
        self._has_training_call = False

    def visit_Module(self, node: ast.Module) -> None:
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and self._is_seed_call(child):
                self._has_seed = True
                break
        self.generic_visit(node)
        if self._has_training_call and not self._has_seed:
            if self.is_rule_enabled("detect_missing_seed"):
                fix = Fix(
                    description="Set a random seed for reproducibility",
                    replacement_code=(
                        "import random, numpy as np\n"
                        "random.seed(42)\nnp.random.seed(42)\n"
                        "# torch.manual_seed(42)  # if using PyTorch"
                    ),
                    confidence=0.8,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_missing_seed",
                    self.RULES["detect_missing_seed"]["message"],
                    self.get_rule_severity("detect_missing_seed", self.RULES["detect_missing_seed"]["severity"]),
                    node,
                    fix=fix,
                )

    def visit_For(self, node: ast.For) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        self._loop_depth += 1
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_ai_hardcoded_key(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_prompt_injection(node)
        self._check_torch_load(node)
        self._check_joblib_load(node)
        self._check_keras_load(node)
        self._check_pii_logging(node)
        self._check_api_call_in_loop(node)
        self._check_api_call_no_timeout(node)
        self._check_model_from_url(node)
        self._track_training_call(node)
        self.generic_visit(node)

    # ── Checks ───────────────────────────────────────────────────────────────

    def _check_prompt_injection(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_prompt_injection"):
            return
        for kw in node.keywords:
            if kw.arg in {"prompt", "content", "messages", "user_message", "input"}:
                if self._contains_user_input(kw.value):
                    self.add_issue(
                        "detect_prompt_injection",
                        self.RULES["detect_prompt_injection"]["message"],
                        self.get_rule_severity("detect_prompt_injection", self.RULES["detect_prompt_injection"]["severity"]),
                        node,
                    )
                    return
        if self._is_llm_call(node) and node.args and self._contains_user_input(node.args[0]):
            self.add_issue(
                "detect_prompt_injection",
                self.RULES["detect_prompt_injection"]["message"],
                self.get_rule_severity("detect_prompt_injection", self.RULES["detect_prompt_injection"]["severity"]),
                node,
            )

    def _check_ai_hardcoded_key(self, node: ast.Assign) -> None:
        if not self.is_rule_enabled("detect_ai_hardcoded_key"):
            return
        source = ast.unparse(node)
        if "os.environ" in source or "getenv" in source:
            return
        for pattern, env_var in self.AI_KEY_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                fix = Fix(
                    description=f"Use environment variable for {env_var}",
                    replacement_code=f"import os\n{env_var.lower()} = os.environ.get('{env_var}')",
                    confidence=0.95,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_ai_hardcoded_key",
                    f"Hardcoded {env_var} detected - use environment variables",
                    self.get_rule_severity("detect_ai_hardcoded_key", self.RULES["detect_ai_hardcoded_key"]["severity"]),
                    node,
                    fix=fix,
                )
                break

    def _check_torch_load(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_torch_load_unsafe"):
            return
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "torch"
        ):
            has_weights_only = any(
                kw.arg == "weights_only"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if not has_weights_only:
                fix = Fix(
                    description="Add weights_only=True",
                    replacement_code="torch.load(path, weights_only=True)",
                    confidence=0.95,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_torch_load_unsafe",
                    self.RULES["detect_torch_load_unsafe"]["message"],
                    self.get_rule_severity("detect_torch_load_unsafe", self.RULES["detect_torch_load_unsafe"]["severity"]),
                    node,
                    fix=fix,
                )

    def _check_joblib_load(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_joblib_load_unsafe"):
            return
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "joblib"
        ):
            self.add_issue(
                "detect_joblib_load_unsafe",
                self.RULES["detect_joblib_load_unsafe"]["message"],
                self.get_rule_severity("detect_joblib_load_unsafe", self.RULES["detect_joblib_load_unsafe"]["severity"]),
                node,
            )

    def _check_keras_load(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_keras_load_unsafe"):
            return
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("load_model", "load"):
            base = ast.unparse(node.func.value).lower()
            if any(kw in base for kw in ("keras", "saved_model", "tf")):
                self.add_issue(
                    "detect_keras_load_unsafe",
                    self.RULES["detect_keras_load_unsafe"]["message"],
                    self.get_rule_severity("detect_keras_load_unsafe", self.RULES["detect_keras_load_unsafe"]["severity"]),
                    node,
                )

    def _check_pii_logging(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_pii_logging"):
            return
        is_log = (isinstance(node.func, ast.Name) and node.func.id == "print") or (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ("info", "debug", "warning", "error", "critical")
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in ("logging", "logger", "log")
        )
        if not is_log:
            return
        for arg in node.args:
            if any(
                term in ast.unparse(arg).lower()
                for term in ("prompt", "response", "output", "user_input", "message", "completion")
            ):
                self.add_issue(
                    "detect_pii_logging",
                    self.RULES["detect_pii_logging"]["message"],
                    self.get_rule_severity("detect_pii_logging", self.RULES["detect_pii_logging"]["severity"]),
                    node,
                )
                return

    def _check_api_call_in_loop(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_api_call_in_loop"):
            return
        if self._loop_depth > 0 and self._is_llm_call(node):
            self.add_issue(
                "detect_api_call_in_loop",
                self.RULES["detect_api_call_in_loop"]["message"],
                self.get_rule_severity("detect_api_call_in_loop", self.RULES["detect_api_call_in_loop"]["severity"]),
                node,
            )

    def _check_api_call_no_timeout(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_api_call_no_timeout"):
            return
        if not self._is_llm_call(node):
            return
        kw_names = {kw.arg for kw in node.keywords}
        if not kw_names & {"max_tokens", "timeout", "max_new_tokens", "max_length"}:
            fix = Fix(
                description="Add max_tokens and timeout",
                replacement_code="...(max_tokens=512, timeout=30)",
                confidence=0.8,
                auto_applicable=False,
            )
            self.add_issue(
                "detect_api_call_no_timeout",
                self.RULES["detect_api_call_no_timeout"]["message"],
                self.get_rule_severity("detect_api_call_no_timeout", self.RULES["detect_api_call_no_timeout"]["severity"]),
                node,
                fix=fix,
            )

    def _check_model_from_url(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_model_from_url"):
            return
        if isinstance(node.func, ast.Attribute) and node.func.attr in (
            "hf_hub_download", "snapshot_download", "from_pretrained"
        ):
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.startswith("http"):
                    self.add_issue(
                        "detect_model_from_url",
                        self.RULES["detect_model_from_url"]["message"],
                        self.get_rule_severity("detect_model_from_url", self.RULES["detect_model_from_url"]["severity"]),
                        node,
                    )
                    return

    def _track_training_call(self, node: ast.Call) -> None:
        """Flag presence of training/fitting calls to trigger missing-seed check."""
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("fit", "train", "fit_transform"):
            self._has_training_call = True

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _is_llm_call(self, node: ast.Call) -> bool:
        if isinstance(node.func, ast.Attribute) and node.func.attr in self.LLM_API_METHODS:
            base = ast.unparse(node.func.value).lower()
            return any(name in base for name in self.LLM_CLIENT_NAMES)
        return False

    def _contains_user_input(self, node: ast.AST) -> bool:
        user_terms = ("input", "user", "query", "request", "message", "prompt", "text")
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and any(t in child.id.lower() for t in user_terms):
                return True
            if isinstance(child, (ast.BinOp, ast.JoinedStr)):
                return True
        return False

    def _is_seed_call(self, node: ast.Call) -> bool:
        return isinstance(node.func, ast.Attribute) and node.func.attr in ("seed", "manual_seed")
