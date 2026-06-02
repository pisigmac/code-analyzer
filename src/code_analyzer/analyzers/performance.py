"""Performance analyzer - detects performance anti-patterns in Python code."""

import ast
from typing import Optional

from .base import BaseAnalyzer, Fix, Severity


class PerformanceAnalyzer(BaseAnalyzer):
    """Analyzer for performance-related issues."""

    RULES = {
        "detect_list_comprehension_opportunities": {
            "message": "Loop can be replaced with list comprehension for better performance",
            "severity": Severity.MEDIUM,
            "fixable": True,
        },
        "detect_inefficient_string_concatenation": {
            "message": "Inefficient string concatenation in loop - use join() instead",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_generator_opportunities": {
            "message": "List comprehension can be replaced with generator expression",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_dict_lookup_in_loop": {
            "message": "Repeated dict lookup in loop - cache the value",
            "severity": Severity.MEDIUM,
            "fixable": True,
        },
        "detect_repeated_attribute_lookup": {
            "message": "Repeated attribute lookup in loop - cache the attribute",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_unnecessary_list_creation": {
            "message": "Unnecessary list() call - use literal [] instead",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_slow_imports": {
            "message": "Import inside function - move to module level",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_range_len": {
            "message": "range(len(x)) used in loop - use enumerate() or iterate directly",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_membership_in_list": {
            "message": "Membership test against list/tuple literal - use a set for O(1) lookup",
            "severity": Severity.MEDIUM,
            "fixable": True,
        },
        "detect_dict_keys_iteration": {
            "message": "Iterating over dict.keys() - iterate over dict directly",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_mutable_default_argument": {
            "message": "Mutable default argument - use None and assign inside function",
            "severity": Severity.HIGH,
            "fixable": True,
        },
        "detect_sorted_for_minmax": {
            "message": "sorted() used only for min/max - use min() or max() directly",
            "severity": Severity.LOW,
            "fixable": True,
        },
        "detect_open_without_with": {
            "message": "open() without 'with' statement - file may not be closed",
            "severity": Severity.MEDIUM,
            "fixable": True,
        },
        "detect_open_without_encoding": {
            "message": "open() without encoding argument - may cause platform-specific bugs",
            "severity": Severity.LOW,
            "fixable": True,
        },
    }

    def __init__(self, config=None):
        super().__init__(config)
        self._loop_depth = 0
        self._function_name = None
        # Track open() calls that are inside a With node
        self._with_open_nodes: set = set()

    def visit_Module(self, node: ast.Module) -> None:
        """Pre-scan to collect open() calls inside 'with' statements."""
        for child in ast.walk(node):
            if isinstance(child, ast.With):
                for item in child.items:
                    if self._is_open_call(item.context_expr):
                        self._with_open_nodes.add(id(item.context_expr))
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        """Visit for loops to detect performance issues."""
        self._loop_depth += 1
        self._check_list_comprehension_opportunity(node)
        self._check_string_concatenation(node)
        self._check_dict_lookup_in_loop(node)
        self._check_repeated_attribute_lookup(node)
        self._check_range_len(node)
        self._check_dict_keys_iteration(node)
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        """Visit while loops."""
        self._loop_depth += 1
        self._check_string_concatenation(node)
        self.generic_visit(node)
        self._loop_depth -= 1

    def visit_ListComp(self, node: ast.ListComp) -> None:
        """Visit list comprehensions to suggest generators."""
        self._check_generator_opportunity(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function calls."""
        self._check_unnecessary_list_creation(node)
        self._check_membership_in_list(node)
        self._check_sorted_for_minmax(node)
        self._check_open_without_with(node)
        self._check_open_without_encoding(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions."""
        old_function = self._function_name
        self._function_name = node.name
        self._check_imports_in_function(node)
        self._check_mutable_default_argument(node)
        self.generic_visit(node)
        self._function_name = old_function

    visit_AsyncFunctionDef = visit_FunctionDef

    # ── New checks ──────────────────────────────────────────────────────────

    def _check_range_len(self, node: ast.For) -> None:
        """Detect for i in range(len(x))."""
        if not self.is_rule_enabled("detect_range_len"):
            return
        iter_ = node.iter
        if (
            isinstance(iter_, ast.Call)
            and isinstance(iter_.func, ast.Name)
            and iter_.func.id == "range"
            and len(iter_.args) == 1
            and isinstance(iter_.args[0], ast.Call)
            and isinstance(iter_.args[0].func, ast.Name)
            and iter_.args[0].func.id == "len"
        ):
            seq = ast.unparse(iter_.args[0].args[0]) if iter_.args[0].args else "seq"
            target = ast.unparse(node.target)
            fix = Fix(
                description="Use enumerate() or iterate directly",
                replacement_code=f"for {target}, item in enumerate({seq}):",
                confidence=0.85,
                auto_applicable=False,
            )
            self.add_issue(
                "detect_range_len",
                self.RULES["detect_range_len"]["message"],
                self.get_rule_severity("detect_range_len", self.RULES["detect_range_len"]["severity"]),
                node,
                fix=fix,
            )

    def _check_dict_keys_iteration(self, node: ast.For) -> None:
        """Detect for x in d.keys()."""
        if not self.is_rule_enabled("detect_dict_keys_iteration"):
            return
        iter_ = node.iter
        if (
            isinstance(iter_, ast.Call)
            and isinstance(iter_.func, ast.Attribute)
            and iter_.func.attr == "keys"
            and not iter_.args
        ):
            d = ast.unparse(iter_.func.value)
            fix = Fix(
                description=f"Iterate over {d} directly",
                replacement_code=f"for {ast.unparse(node.target)} in {d}:",
                confidence=0.99,
                auto_applicable=True,
            )
            self.add_issue(
                "detect_dict_keys_iteration",
                self.RULES["detect_dict_keys_iteration"]["message"],
                self.get_rule_severity("detect_dict_keys_iteration", self.RULES["detect_dict_keys_iteration"]["severity"]),
                node,
                fix=fix,
            )

    def _check_membership_in_list(self, node: ast.Call) -> None:
        """Detect x in [a, b, c] or x in (a, b, c) patterns (via Compare nodes)."""
        # This is checked via visit_Compare instead; skip here.
        pass

    def visit_Compare(self, node: ast.Compare) -> None:
        """Detect membership tests against list/tuple literals."""
        if self.is_rule_enabled("detect_membership_in_list"):
            for op, comparator in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)) and isinstance(comparator, (ast.List, ast.Tuple)):
                    elements = ast.unparse(comparator)
                    fix = Fix(
                        description="Use a set literal for O(1) membership test",
                        replacement_code=elements.replace("[", "{", 1).replace("]", "}", 1)
                        if isinstance(comparator, ast.List)
                        else "set(" + elements + ")",
                        confidence=0.95,
                        auto_applicable=True,
                    )
                    self.add_issue(
                        "detect_membership_in_list",
                        self.RULES["detect_membership_in_list"]["message"],
                        self.get_rule_severity("detect_membership_in_list", self.RULES["detect_membership_in_list"]["severity"]),
                        node,
                        fix=fix,
                    )
                    break
        self.generic_visit(node)

    def _check_mutable_default_argument(self, node: ast.FunctionDef) -> None:
        """Detect mutable default arguments (list, dict, set literals)."""
        if not self.is_rule_enabled("detect_mutable_default_argument"):
            return
        for default in node.args.defaults + node.args.kw_defaults:
            if default is None:
                continue
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                fix = Fix(
                    description="Use None as default and assign inside function",
                    replacement_code="def f(x=None):\n    if x is None:\n        x = []  # or {} or set()",
                    confidence=0.95,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_mutable_default_argument",
                    self.RULES["detect_mutable_default_argument"]["message"],
                    self.get_rule_severity("detect_mutable_default_argument", self.RULES["detect_mutable_default_argument"]["severity"]),
                    default,
                    fix=fix,
                )

    def _check_sorted_for_minmax(self, node: ast.Call) -> None:
        """Detect sorted(x)[0] or sorted(x)[-1] — use min/max instead."""
        if not self.is_rule_enabled("detect_sorted_for_minmax"):
            return
        # Pattern is a Subscript whose value is a sorted() call — checked in visit_Subscript
        pass

    def visit_Subscript(self, node: ast.Subscript) -> None:
        """Detect sorted(x)[0] / sorted(x)[-1]."""
        if self.is_rule_enabled("detect_sorted_for_minmax"):
            if (
                isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id == "sorted"
                and isinstance(node.slice, ast.Constant)
                and node.slice.value in {0, -1}
            ):
                func = "min" if node.slice.value == 0 else "max"
                seq = ast.unparse(node.value.args[0]) if node.value.args else "seq"
                fix = Fix(
                    description=f"Use {func}({seq}) instead",
                    replacement_code=f"{func}({seq})",
                    confidence=0.95,
                    auto_applicable=True,
                )
                self.add_issue(
                    "detect_sorted_for_minmax",
                    self.RULES["detect_sorted_for_minmax"]["message"],
                    self.get_rule_severity("detect_sorted_for_minmax", self.RULES["detect_sorted_for_minmax"]["severity"]),
                    node,
                    fix=fix,
                )
        self.generic_visit(node)

    def _is_open_call(self, node: ast.AST) -> bool:
        return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"

    def _check_open_without_with(self, node: ast.Call) -> None:
        """Detect open() calls not inside a 'with' statement."""
        if not self.is_rule_enabled("detect_open_without_with"):
            return
        if self._is_open_call(node) and id(node) not in self._with_open_nodes:
            fix = Fix(
                description="Use 'with open(...) as f:' to ensure file is closed",
                replacement_code="with open(...) as f:\n    ...",
                confidence=0.9,
                auto_applicable=False,
            )
            self.add_issue(
                "detect_open_without_with",
                self.RULES["detect_open_without_with"]["message"],
                self.get_rule_severity("detect_open_without_with", self.RULES["detect_open_without_with"]["severity"]),
                node,
                fix=fix,
            )

    def _check_open_without_encoding(self, node: ast.Call) -> None:
        """Detect open() calls missing an encoding argument."""
        if not self.is_rule_enabled("detect_open_without_encoding"):
            return
        if not self._is_open_call(node):
            return
        # Check mode arg — skip binary modes
        mode = ""
        if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
            mode = node.args[1].value
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode = kw.value.value
        if "b" in mode:
            return
        has_encoding = any(kw.arg == "encoding" for kw in node.keywords)
        if not has_encoding:
            fix = Fix(
                description="Add encoding='utf-8' argument",
                replacement_code='open(..., encoding="utf-8")',
                confidence=0.85,
                auto_applicable=False,
            )
            self.add_issue(
                "detect_open_without_encoding",
                self.RULES["detect_open_without_encoding"]["message"],
                self.get_rule_severity("detect_open_without_encoding", self.RULES["detect_open_without_encoding"]["severity"]),
                node,
                fix=fix,
            )

    # ── Existing checks (unchanged) ─────────────────────────────────────────

    def _check_list_comprehension_opportunity(self, node: ast.For) -> None:
        if not self.is_rule_enabled("detect_list_comprehension_opportunities"):
            return
        if (
            len(node.body) == 1
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Call)
        ):
            call = node.body[0].value
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr == "append"
                and len(call.args) == 1
            ):
                fix = self._create_list_comp_fix(node, call.args[0])
                self.add_issue(
                    "detect_list_comprehension_opportunities",
                    self.RULES["detect_list_comprehension_opportunities"]["message"],
                    self.get_rule_severity(
                        "detect_list_comprehension_opportunities",
                        self.RULES["detect_list_comprehension_opportunities"]["severity"],
                    ),
                    node,
                    fix=fix,
                )

    def _check_string_concatenation(self, node: ast.AST) -> None:
        if not self.is_rule_enabled("detect_inefficient_string_concatenation"):
            return
        if self._loop_depth == 0:
            return
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                if isinstance(child.target, ast.Name):
                    # Skip obvious integer counters
                    name = child.target.id.lower()
                    if any(name.endswith(s) for s in ("count", "idx", "index", "i", "n", "total", "sum", "num")):
                        continue
                    if isinstance(child.value, ast.Constant) and isinstance(child.value.value, (int, float)):
                        continue
                    fix = Fix(
                        description="Use str.join() for efficient string concatenation",
                        replacement_code=self._create_join_fix(child),
                        confidence=0.9,
                        auto_applicable=False,
                    )
                    self.add_issue(
                        "detect_inefficient_string_concatenation",
                        self.RULES["detect_inefficient_string_concatenation"]["message"],
                        self.get_rule_severity(
                            "detect_inefficient_string_concatenation",
                            self.RULES["detect_inefficient_string_concatenation"]["severity"],
                        ),
                        child,
                        fix=fix,
                    )

    def _check_generator_opportunity(self, node: ast.ListComp) -> None:
        if not self.is_rule_enabled("detect_generator_opportunities"):
            return
        parent = getattr(node, "_parent", None)
        if parent and isinstance(parent, ast.Call):
            func = parent.func
            if isinstance(func, ast.Name) and func.id in ("sum", "max", "min", "any", "all"):
                fix = Fix(
                    description="Replace list comprehension with generator expression",
                    replacement_code=self._create_generator_fix(node),
                    confidence=0.95,
                    auto_applicable=True,
                )
                self.add_issue(
                    "detect_generator_opportunities",
                    self.RULES["detect_generator_opportunities"]["message"],
                    self.get_rule_severity(
                        "detect_generator_opportunities",
                        self.RULES["detect_generator_opportunities"]["severity"],
                    ),
                    node,
                    fix=fix,
                )

    def _check_dict_lookup_in_loop(self, node: ast.For) -> None:
        if not self.is_rule_enabled("detect_dict_lookup_in_loop"):
            return
        dict_lookups: dict = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                base = self._get_subscript_base(child)
                if base:
                    dict_lookups[base] = dict_lookups.get(base, 0) + 1
        for base, count in dict_lookups.items():
            if count > 2:
                fix = Fix(
                    description=f"Cache dict lookup: cached_value = {base}[key]",
                    replacement_code=f"# Cache this lookup before the loop\ncached_{base} = {base}[key]",
                    confidence=0.7,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_dict_lookup_in_loop",
                    f"Repeated dict lookup '{base}' in loop ({count} times) - cache the value",
                    self.get_rule_severity(
                        "detect_dict_lookup_in_loop",
                        self.RULES["detect_dict_lookup_in_loop"]["severity"],
                    ),
                    node,
                    fix=fix,
                )

    def _check_repeated_attribute_lookup(self, node: ast.For) -> None:
        if not self.is_rule_enabled("detect_repeated_attribute_lookup"):
            return
        attr_lookups: dict = {}
        _skip = {"self", "cls", "ast", "os", "re", "sys"}
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                base = self._get_attribute_base(child)
                if base and base not in _skip:
                    attr_lookups[base] = attr_lookups.get(base, 0) + 1
        for base, count in attr_lookups.items():
            if count > 3:
                fix = Fix(
                    description=f"Cache attribute lookup: cached = {base}",
                    replacement_code=f"# Cache this attribute before the loop\ncached_{base.split('.')[-1]} = {base}",
                    confidence=0.7,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_repeated_attribute_lookup",
                    f"Repeated attribute lookup '{base}' in loop ({count} times) - cache it",
                    self.get_rule_severity(
                        "detect_repeated_attribute_lookup",
                        self.RULES["detect_repeated_attribute_lookup"]["severity"],
                    ),
                    node,
                    fix=fix,
                )

    def _check_unnecessary_list_creation(self, node: ast.Call) -> None:
        if not self.is_rule_enabled("detect_unnecessary_list_creation"):
            return
        if isinstance(node.func, ast.Name) and node.func.id == "list" and len(node.args) == 0:
            fix = Fix(
                description="Replace list() with []",
                replacement_code="[]",
                confidence=0.99,
                auto_applicable=True,
            )
            self.add_issue(
                "detect_unnecessary_list_creation",
                self.RULES["detect_unnecessary_list_creation"]["message"],
                self.get_rule_severity(
                    "detect_unnecessary_list_creation",
                    self.RULES["detect_unnecessary_list_creation"]["severity"],
                ),
                node,
                fix=fix,
            )

    def _check_imports_in_function(self, node: ast.FunctionDef) -> None:
        if not self.is_rule_enabled("detect_slow_imports"):
            return
        for child in node.body:
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                fix = Fix(
                    description="Move import to module level",
                    replacement_code=ast.unparse(child),
                    confidence=0.9,
                    auto_applicable=False,
                )
                self.add_issue(
                    "detect_slow_imports",
                    self.RULES["detect_slow_imports"]["message"],
                    self.get_rule_severity(
                        "detect_slow_imports",
                        self.RULES["detect_slow_imports"]["severity"],
                    ),
                    child,
                    fix=fix,
                )

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _get_attribute_base(self, node: ast.AST) -> Optional[str]:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_attribute_base(node.value)
        return None

    def _get_subscript_base(self, node: ast.Subscript) -> Optional[str]:
        if isinstance(node.value, ast.Name):
            return node.value.id
        elif isinstance(node.value, ast.Attribute):
            return self._get_attribute_base(node.value)
        return None

    def _create_list_comp_fix(self, loop: ast.For, expr: ast.AST) -> Fix:
        target = ast.unparse(loop.target)
        iter_expr = ast.unparse(loop.iter)
        expr_str = ast.unparse(expr)
        return Fix(
            description="Replace loop with list comprehension",
            replacement_code=f"[{expr_str} for {target} in {iter_expr}]",
            confidence=0.9,
            auto_applicable=True,
        )

    def _create_join_fix(self, node: ast.AugAssign) -> str:
        return "# Use '\\n'.join(items) or similar pattern"

    def _create_generator_fix(self, node: ast.ListComp) -> str:
        comp_str = ast.unparse(node)
        return comp_str.replace("[", "(", 1).replace("]", ")", 1)
