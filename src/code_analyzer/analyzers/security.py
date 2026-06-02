"""Security analyzer - detects security vulnerabilities in Python code."""

import ast
import re
from typing import Optional

from .base import BaseAnalyzer, Fix, Severity


class SecurityAnalyzer(BaseAnalyzer):
    """Analyzer for security-related issues."""

    RULES = {
        "detect_sql_injection": {
            "message": "Potential SQL injection vulnerability - use parameterized queries",
            "severity": Severity.CRITICAL,
            "fixable": True,
        },
        "detect_hardcoded_secrets": {
            "message": "Hardcoded secret detected - use environment variables",
            "severity": Severity.CRITICAL,
            "fixable": True,
        },
        "detect_eval_usage": {
            "message": "Dangerous eval() usage - potential code injection",
            "severity": Severity.CRITICAL,
            "fixable": False,
        },
        "detect_exec_usage": {
            "message": "Dangerous exec() usage - potential code injection",
            "severity": Severity.CRITICAL,
            "fixable": False,
        },
        "detect_pickle_usage": {
            "message": "Unsafe pickle usage - potential arbitrary code execution",
            "severity": Severity.HIGH,
            "fixable": False,
        },
        "detect_yaml_load": {
            "message": "Unsafe yaml.load() - use yaml.safe_load() instead",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_weak_hashing": {
            "message": "Weak hashing algorithm detected - use hashlib.sha256 or better",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_debug_mode": {
            "message": "Debug mode enabled - disable in production",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_weak_crypto": {
            "message": "Weak cryptography detected - use strong algorithms",
            "severity": Severity.CRITICAL,
            "fixable": True,
        },
        "detect_temp_file_race": {
            "message": "Insecure temporary file creation - use tempfile.mkstemp()",
            "severity": Severity.MEDIUM,
            "fixable": True,
        },
        "detect_subprocess_shell": {
            "message": "subprocess called with shell=True - potential shell injection",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_assert_security": {
            "message": "assert used for security check - stripped with python -O flag",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_random_for_secrets": {
            "message": "random module used for security token - use secrets module instead",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_http_url": {
            "message": "Hardcoded http:// URL - use https:// for secure transport",
            "severity": Severity.MEDIUM,
            "fixable": True,
        },
        "detect_broad_except": {
            "message": "Broad except clause swallows all errors - may hide security failures",
            "severity": Severity.MEDIUM,
            "fixable": False,
        },
    }

    # Patterns for hardcoded secrets
    SECRET_PATTERNS = [
        (r'password\s*=\s*["\'][^"\']+["\']', "password"),
        (r'secret\s*=\s*["\'][^"\']+["\']', "secret"),
        (r'api_key\s*=\s*["\'][^"\']+["\']', "api_key"),
        (r'apikey\s*=\s*["\'][^"\']+["\']', "apikey"),
        (r'token\s*=\s*["\'][^"\']+["\']', "token"),
        (r'auth\s*=\s*["\'][^"\']+["\']', "auth"),
        (r'private_key\s*=\s*["\'][^"\']+["\']', "private_key"),
        (r'aws_access_key_id\s*=\s*["\'][^"\']+["\']', "aws_access_key_id"),
        (r'aws_secret_access_key\s*=\s*["\'][^"\']+["\']', "aws_secret_access_key"),
    ]

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls to detect security issues."""
        self._check_sql_injection(node)
        self._check_eval_usage(node)
        self._check_exec_usage(node)
        self._check_pickle_usage(node)
        self._check_yaml_load(node)
        self._check_weak_hashing(node)
        self._check_weak_crypto(node)
        self._check_temp_file_race(node)
        self._check_subprocess_shell(node)
        self._check_random_for_secrets(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignments to detect hardcoded secrets."""
        self._check_hardcoded_secrets(node)
        self._check_debug_mode(node)
        self._check_http_url(node)
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        """Visit assert statements to detect security misuse."""
        self._check_assert_security(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Visit except clauses to detect broad exception handling."""
        self._check_broad_except(node)
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Visit binary operations to detect SQL injection via string formatting."""
        self._check_sql_injection_binop(node)
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Visit f-strings to detect SQL injection."""
        self._check_sql_injection_fstring(node)
        self.generic_visit(node)

    def _check_sql_injection(self, node: ast.Call) -> None:
        """Check for potential SQL injection vulnerabilities."""
        if not self.is_rule_enabled("detect_sql_injection"):
            return

        # Check for cursor.execute() or similar with string formatting
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"execute", "executemany"}:
                if len(node.args) >= 1:
                    first_arg = node.args[0]
                    # Check if first argument contains string formatting
                    if self._contains_string_formatting(first_arg):
                        fix = Fix(
                            description="Use parameterized queries",
                            replacement_code="# Use parameterized query: cursor.execute('QUERY WHERE id = %s', (user_id,))",
                            confidence=0.8,
                            auto_applicable=False,
                        )
                        self.add_issue(
                            "detect_sql_injection",
                            self.RULES["detect_sql_injection"]["message"],
                            self.get_rule_severity(
                                "detect_sql_injection",
                                self.RULES["detect_sql_injection"]["severity"],
                            ),
                            node,
                            fix=fix,
                        )
                        return

        # Only flag execute/executemany — the broad call check produces too many false positives

    def _check_hardcoded_secrets(self, node: ast.Assign) -> None:
        """Check for hardcoded secrets in assignments."""
        if not self.is_rule_enabled("detect_hardcoded_secrets"):
            return

        source = ast.unparse(node)
        for pattern, secret_type in self.SECRET_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                # Skip if it's already using os.environ or similar
                if "os.environ" in source or "getenv" in source:
                    continue

                fix = Fix(
                    description=f"Use environment variable for {secret_type}",
                    replacement_code=f"import os\n{secret_type} = os.environ.get('{secret_type.upper()}')",
                    confidence=0.9,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_hardcoded_secrets",
                    f"Hardcoded {secret_type} detected - use environment variables",
                    self.get_rule_severity(
                        "detect_hardcoded_secrets",
                        self.RULES["detect_hardcoded_secrets"]["severity"],
                    ),
                    node,
                    fix=fix,
                )
                break  # Only report once per assignment

    def _check_eval_usage(self, node: ast.Call) -> None:
        """Check for dangerous eval() usage."""
        if not self.is_rule_enabled("detect_eval_usage"):
            return

        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            self.add_issue(
                "detect_eval_usage",
                self.RULES["detect_eval_usage"]["message"],
                self.get_rule_severity(
                    "detect_eval_usage",
                    self.RULES["detect_eval_usage"]["severity"],
                ),
                node,
            )

    def _check_exec_usage(self, node: ast.Call) -> None:
        """Check for dangerous exec() usage."""
        if not self.is_rule_enabled("detect_exec_usage"):
            return

        if isinstance(node.func, ast.Name) and node.func.id == "exec":
            self.add_issue(
                "detect_exec_usage",
                self.RULES["detect_exec_usage"]["message"],
                self.get_rule_severity(
                    "detect_exec_usage",
                    self.RULES["detect_exec_usage"]["severity"],
                ),
                node,
            )

    def _check_pickle_usage(self, node: ast.Call) -> None:
        """Check for unsafe pickle usage."""
        if not self.is_rule_enabled("detect_pickle_usage"):
            return

        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                if node.func.attr in ("load", "loads"):
                    self.add_issue(
                        "detect_pickle_usage",
                        self.RULES["detect_pickle_usage"]["message"],
                        self.get_rule_severity(
                            "detect_pickle_usage",
                            self.RULES["detect_pickle_usage"]["severity"],
                        ),
                        node,
                    )

    def _check_yaml_load(self, node: ast.Call) -> None:
        """Check for unsafe yaml.load() usage."""
        if not self.is_rule_enabled("detect_yaml_load"):
            return

        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "yaml":
                if node.func.attr == "load":
                    fix = Fix(
                        description="Use yaml.safe_load() instead",
                        replacement_code="yaml.safe_load(...)",
                        confidence=0.95,
                        auto_applicable=True,
                    )
                    self.add_issue(
                        "detect_yaml_load",
                        self.RULES["detect_yaml_load"]["message"],
                        self.get_rule_severity(
                            "detect_yaml_load",
                            self.RULES["detect_yaml_load"]["severity"],
                        ),
                        node,
                        fix=fix,
                    )

    def _check_weak_hashing(self, node: ast.Call) -> None:
        """Check for weak hashing algorithms."""
        if not self.is_rule_enabled("detect_weak_hashing"):
            return

        weak_hashes = {"md5", "sha1"}

        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "hashlib":
                if node.func.attr in weak_hashes:
                    fix = Fix(
                        description="Use hashlib.sha256() instead",
                        replacement_code="hashlib.sha256(data).hexdigest()",
                        confidence=0.95,
                        auto_applicable=False,
                    )
                    self.add_issue(
                        "detect_weak_hashing",
                        f"Weak hashing algorithm '{node.func.attr}' detected - use sha256 or better",
                        self.get_rule_severity(
                            "detect_weak_hashing",
                            self.RULES["detect_weak_hashing"]["severity"],
                        ),
                        node,
                        fix=fix,
                    )

    def _check_debug_mode(self, node: ast.Assign) -> None:
        """Check for debug mode enabled."""
        if not self.is_rule_enabled("detect_debug_mode"):
            return

        # Check for DEBUG = True
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id == "DEBUG":
                if isinstance(node.value, ast.Constant) and node.value.value is True:
                    fix = Fix(
                        description="Set DEBUG = False in production",
                        replacement_code="DEBUG = False",
                        confidence=0.9,
                        auto_applicable=True,
                    )
                    self.add_issue(
                        "detect_debug_mode",
                        self.RULES["detect_debug_mode"]["message"],
                        self.get_rule_severity(
                            "detect_debug_mode",
                            self.RULES["detect_debug_mode"]["severity"],
                        ),
                        node,
                        fix=fix,
                    )

    def _check_weak_crypto(self, node: ast.Call) -> None:
        """Check for weak cryptography usage."""
        if not self.is_rule_enabled("detect_weak_crypto"):
            return

        # Check for DES, 3DES, RC4, etc.
        weak_algorithms = {"DES", "TripleDES", "Blowfish", "RC4", "ARC4"}

        if isinstance(node.func, ast.Name):
            if node.func.id in weak_algorithms:
                self.add_issue(
                    "detect_weak_crypto",
                    f"Weak cryptography '{node.func.id}' detected - use AES or ChaCha20",
                    self.get_rule_severity(
                        "detect_weak_crypto",
                        self.RULES["detect_weak_crypto"]["severity"],
                    ),
                    node,
                )

    def _check_temp_file_race(self, node: ast.Call) -> None:
        """Check for insecure temporary file creation."""
        if not self.is_rule_enabled("detect_temp_file_race"):
            return

        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if len(node.args) >= 1:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                    if "/tmp/" in first_arg.value or first_arg.value.startswith("/tmp/"):
                        fix = Fix(
                            description="Use tempfile.mkstemp() for secure temp files",
                            replacement_code="import tempfile\nfd, path = tempfile.mkstemp()",
                            confidence=0.9,
                            auto_applicable=False,
                        )
                        self.add_issue(
                            "detect_temp_file_race",
                            self.RULES["detect_temp_file_race"]["message"],
                            self.get_rule_severity(
                                "detect_temp_file_race",
                                self.RULES["detect_temp_file_race"]["severity"],
                            ),
                            node,
                            fix=fix,
                        )

    def _check_sql_injection_binop(self, node: ast.BinOp) -> None:
        """Check for SQL injection in binary operations (string formatting)."""
        if not self.is_rule_enabled("detect_sql_injection"):
            return

        if isinstance(node.op, ast.Mod):
            # Check if left side contains SQL keywords
            if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
                sql_keywords = ["select", "insert", "update", "delete", "drop", "create"]
                if any(kw in node.left.value.lower() for kw in sql_keywords):
                    fix = Fix(
                        description="Use parameterized queries",
                        replacement_code="# Use parameterized query to prevent SQL injection",
                        confidence=0.8,
                        auto_applicable=False,
                    )
                    self.add_issue(
                        "detect_sql_injection",
                        self.RULES["detect_sql_injection"]["message"],
                        self.get_rule_severity(
                            "detect_sql_injection",
                            self.RULES["detect_sql_injection"]["severity"],
                        ),
                        node,
                        fix=fix,
                    )

    def _check_sql_injection_fstring(self, node: ast.JoinedStr) -> None:
        """Check for SQL injection in f-strings with dynamic interpolation."""
        if not self.is_rule_enabled("detect_sql_injection"):
            return

        # Only flag if f-string has both SQL keywords AND dynamic interpolation
        has_interpolation = any(isinstance(v, ast.FormattedValue) for v in node.values)
        if not has_interpolation:
            return

        sql_keywords = {"select", "insert", "update", "delete", "drop", "create"}
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                if any(kw in value.value.lower() for kw in sql_keywords):
                    fix = Fix(
                        description="Use parameterized queries",
                        replacement_code="# Use parameterized query to prevent SQL injection",
                        confidence=0.8,
                        auto_applicable=False,
                    )
                    self.add_issue(
                        "detect_sql_injection",
                        self.RULES["detect_sql_injection"]["message"],
                        self.get_rule_severity(
                            "detect_sql_injection",
                            self.RULES["detect_sql_injection"]["severity"],
                        ),
                        node,
                        fix=fix,
                    )
                    break

    def _check_subprocess_shell(self, node: ast.Call) -> None:
        """Check for subprocess called with shell=True."""
        if not self.is_rule_enabled("detect_subprocess_shell"):
            return
        func = node.func
        is_subprocess = (
            (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
             and func.value.id == "subprocess")
            or (isinstance(func, ast.Name) and func.id in ("call", "run", "Popen", "check_output", "check_call"))
        )
        if is_subprocess:
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    fix = Fix(
                        description="Pass command as a list and remove shell=True",
                        replacement_code="subprocess.run(['cmd', 'arg1'], shell=False)",
                        confidence=0.85,
                        auto_applicable=False,
                    )
                    self.add_issue(
                        "detect_subprocess_shell",
                        self.RULES["detect_subprocess_shell"]["message"],
                        self.get_rule_severity("detect_subprocess_shell", self.RULES["detect_subprocess_shell"]["severity"]),
                        node,
                        fix=fix,
                    )

    def _check_assert_security(self, node: ast.Assert) -> None:
        """Check for assert used as a security guard."""
        if not self.is_rule_enabled("detect_assert_security"):
            return
        # Heuristic: assert containing names like auth, permission, user, token, admin
        test_str = ast.unparse(node.test).lower()
        security_terms = ("auth", "permission", "user", "token", "admin", "role", "login", "logged")
        if any(t in test_str for t in security_terms):
            fix = Fix(
                description="Replace assert with an explicit if/raise check",
                replacement_code="if not condition:\n    raise PermissionError('Access denied')",
                confidence=0.8,
                auto_applicable=False,
            )
            self.add_issue(
                "detect_assert_security",
                self.RULES["detect_assert_security"]["message"],
                self.get_rule_severity("detect_assert_security", self.RULES["detect_assert_security"]["severity"]),
                node,
                fix=fix,
            )

    def _check_random_for_secrets(self, node: ast.Call) -> None:
        """Check for random module usage for token/secret generation."""
        if not self.is_rule_enabled("detect_random_for_secrets"):
            return
        random_funcs = ("random", "randint", "randrange", "choice", "choices", "sample", "token_hex", "token_urlsafe")
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "random"
            and node.func.attr in random_funcs
        ):
            fix = Fix(
                description="Use secrets.token_hex() or secrets.choice() instead",
                replacement_code="import secrets\nsecrets.token_hex(32)",
                confidence=0.8,
                auto_applicable=False,
            )
            self.add_issue(
                "detect_random_for_secrets",
                self.RULES["detect_random_for_secrets"]["message"],
                self.get_rule_severity("detect_random_for_secrets", self.RULES["detect_random_for_secrets"]["severity"]),
                node,
                fix=fix,
            )

    def _check_http_url(self, node: ast.Assign) -> None:
        """Check for hardcoded http:// URLs in assignments."""
        if not self.is_rule_enabled("detect_http_url"):
            return
        for value_node in ast.walk(node):
            if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                if value_node.value.startswith("http://"):
                    fix = Fix(
                        description="Replace http:// with https://",
                        replacement_code=value_node.value.replace("http://", "https://", 1),
                        confidence=0.8,
                        auto_applicable=False,
                    )
                    self.add_issue(
                        "detect_http_url",
                        self.RULES["detect_http_url"]["message"],
                        self.get_rule_severity("detect_http_url", self.RULES["detect_http_url"]["severity"]),
                        value_node,
                        fix=fix,
                    )
                    break

    def _check_broad_except(self, node: ast.ExceptHandler) -> None:
        """Check for bare except or except Exception/BaseException."""
        if not self.is_rule_enabled("detect_broad_except"):
            return
        is_broad = node.type is None or (
            isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException")
        )
        if is_broad:
            self.add_issue(
                "detect_broad_except",
                self.RULES["detect_broad_except"]["message"],
                self.get_rule_severity("detect_broad_except", self.RULES["detect_broad_except"]["severity"]),
                node,
            )

    def _contains_string_formatting(self, node: ast.AST) -> bool:
        """Check if node contains string formatting operations."""
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return True
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("format", "replace"):
                    return True
            if isinstance(node.func, ast.Name) and node.func.id == "format":
                return True
        if isinstance(node, ast.JoinedStr):
            return True
        return False
