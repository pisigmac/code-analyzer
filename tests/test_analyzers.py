"""Tests for code analyzers."""

import pytest

from code_analyzer.analyzers.performance import PerformanceAnalyzer
from code_analyzer.analyzers.security import SecurityAnalyzer


class TestPerformanceAnalyzer:
    """Tests for the performance analyzer."""

    def test_list_comprehension_detection(self):
        """Test detection of list comprehension opportunities."""
        code = """
result = []
for i in range(100):
    result.append(i * 2)
"""
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)

        assert len(issues) >= 1
        assert any(i.rule_id == "detect_list_comprehension_opportunities" for i in issues)

    def test_string_concatenation_detection(self):
        """Test detection of inefficient string concatenation."""
        code = """
result = ""
for i in range(100):
    result += str(i)
"""
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_inefficient_string_concatenation" for i in issues)

    def test_unnecessary_list_creation(self):
        """Test detection of unnecessary list() calls."""
        code = "data = list()"
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_unnecessary_list_creation" for i in issues)

    def test_import_in_function(self):
        """Test detection of imports inside functions."""
        code = """
def my_func():
    import json
    return json.dumps({})
"""
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_slow_imports" for i in issues)

    def test_no_issues_in_clean_code(self):
        """Test that clean code produces no issues."""
        code = """
def clean_function():
    return [i * 2 for i in range(100)]
"""
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "detect_list_comprehension_opportunities" for i in issues)

    def test_range_len_detection(self):
        code = """
items = [1, 2, 3]
for i in range(len(items)):
    print(items[i])
"""
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_range_len" for i in issues)

    def test_membership_in_list_detection(self):
        code = "result = x in [1, 2, 3]"
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_membership_in_list" for i in issues)

    def test_dict_keys_iteration_detection(self):
        code = """
d = {'a': 1}
for k in d.keys():
    print(k)
"""
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_dict_keys_iteration" for i in issues)

    def test_mutable_default_argument_detection(self):
        code = """
def f(items=[]):
    items.append(1)
    return items
"""
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_mutable_default_argument" for i in issues)

    def test_sorted_for_minmax_detection(self):
        code = "result = sorted(numbers)[0]"
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_sorted_for_minmax" for i in issues)

    def test_open_without_with_detection(self):
        code = "f = open('file.txt')\ndata = f.read()\nf.close()"
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_open_without_with" for i in issues)

    def test_open_without_encoding_detection(self):
        code = "with open('file.txt') as f:\n    data = f.read()"
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_open_without_encoding" for i in issues)

    def test_open_with_encoding_no_issue(self):
        code = "with open('file.txt', encoding='utf-8') as f:\n    data = f.read()"
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "detect_open_without_encoding" for i in issues)

    def test_open_binary_no_encoding_issue(self):
        code = "with open('file.bin', 'rb') as f:\n    data = f.read()"
        analyzer = PerformanceAnalyzer()
        issues = analyzer.analyze(code)
        assert not any(i.rule_id == "detect_open_without_encoding" for i in issues)


class TestSecurityAnalyzer:
    """Tests for the security analyzer."""

    def test_hardcoded_secret_detection(self):
        """Test detection of hardcoded secrets."""
        code = 'API_KEY = "sk-1234567890abcdef"'
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_hardcoded_secrets" for i in issues)

    def test_sql_injection_detection(self):
        """Test detection of SQL injection."""
        code = """
def query(user_id):
    return "SELECT * FROM users WHERE id = %s" % user_id
"""
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_sql_injection" for i in issues)

    def test_eval_usage_detection(self):
        """Test detection of eval() usage."""
        code = "result = eval(user_input)"
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_eval_usage" for i in issues)

    def test_weak_hash_detection(self):
        """Test detection of weak hashing."""
        code = """
import hashlib
result = hashlib.md5(b"password").hexdigest()
"""
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_weak_hashing" for i in issues)

    def test_debug_mode_detection(self):
        """Test detection of debug mode."""
        code = "DEBUG = True"
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_debug_mode" for i in issues)

    def test_pickle_usage_detection(self):
        """Test detection of pickle usage."""
        code = """
import pickle
data = pickle.loads(b"some data")
"""
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)

        assert any(i.rule_id == "detect_pickle_usage" for i in issues)

    def test_insecure_temp_file_detection(self):
        """Test detection of insecure temp files."""
        code = 'with open("/tmp/myfile.txt", "w") as f:\n    f.write("data")'
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_temp_file_race" for i in issues)

    def test_subprocess_shell_detection(self):
        code = "import subprocess\nsubprocess.run(cmd, shell=True)"
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_subprocess_shell" for i in issues)

    def test_assert_security_detection(self):
        code = "assert user.is_authenticated, 'Not logged in'"
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_assert_security" for i in issues)

    def test_random_for_secrets_detection(self):
        code = "import random\ntoken = random.token_hex(32)"
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_random_for_secrets" for i in issues)

    def test_http_url_detection(self):
        code = 'BASE_URL = "http://example.com/api"'
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_http_url" for i in issues)

    def test_broad_except_detection(self):
        code = "try:\n    pass\nexcept Exception:\n    pass"
        analyzer = SecurityAnalyzer()
        issues = analyzer.analyze(code)
        assert any(i.rule_id == "detect_broad_except" for i in issues)


class TestAISecurityAnalyzer:
    """Tests for the AI security analyzer."""

    def setup_method(self):
        from code_analyzer.analyzers.ai_security import AISecurityAnalyzer
        self.analyzer = AISecurityAnalyzer()

    def test_hardcoded_ai_key(self):
        code = 'OPENAI_API_KEY = "sk-abc123def456"'
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_ai_hardcoded_key" for i in issues)

    def test_torch_load_unsafe(self):
        code = "import torch\nmodel = torch.load('model.pt')"
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_torch_load_unsafe" for i in issues)

    def test_torch_load_safe(self):
        code = "import torch\nmodel = torch.load('model.pt', weights_only=True)"
        issues = self.analyzer.analyze(code)
        assert not any(i.rule_id == "detect_torch_load_unsafe" for i in issues)

    def test_joblib_load(self):
        code = "import joblib\nmodel = joblib.load('model.pkl')"
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_joblib_load_unsafe" for i in issues)

    def test_prompt_injection(self):
        code = "client.chat.create(prompt=f'Answer: {user_input}')"
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_prompt_injection" for i in issues)

    def test_pii_logging(self):
        code = "print(response.completion)"
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_pii_logging" for i in issues)

    def test_api_call_in_loop(self):
        code = """
for item in items:
    client.completions.create(prompt=item, max_tokens=10)
"""
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_api_call_in_loop" for i in issues)

    def test_api_call_no_timeout(self):
        code = "client.chat.generate(prompt=text)"
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_api_call_no_timeout" for i in issues)

    def test_api_call_with_limits_no_issue(self):
        code = "client.chat.generate(prompt=text, max_tokens=512, timeout=30)"
        issues = self.analyzer.analyze(code)
        assert not any(i.rule_id == "detect_api_call_no_timeout" for i in issues)

    def test_missing_seed(self):
        code = """
def train(model, X, y):
    model.fit(X, y)
"""
        issues = self.analyzer.analyze(code)
        assert any(i.rule_id == "detect_missing_seed" for i in issues)

    def test_seed_present_no_issue(self):
        code = """
import numpy as np
np.random.seed(42)
def train(model, X, y):
    model.fit(X, y)
"""
        issues = self.analyzer.analyze(code)
        assert not any(i.rule_id == "detect_missing_seed" for i in issues)
