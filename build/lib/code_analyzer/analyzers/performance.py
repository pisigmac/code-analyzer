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
    }

    def __init__(self, config=None):
        super().__init__(config)
        self._loop_depth = 0
        self._function_name = None

    def visit_For(self, node: ast.For) -> None:
        """Visit for loops to detect performance issues."""
        self._loop_depth += 1

        # Check for list comprehension opportunities
        self._check_list_comprehension_opportunity(node)

        # Check for inefficient string concatenation
        self._check_string_concatenation(node)

        # Check for repeated dict lookups
        self._check_dict_lookup_in_loop(node)

        # Check for repeated attribute lookups
        self._check_repeated_attribute_lookup(node)

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
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definitions."""
        old_function = self._function_name
        self._function_name = node.name

        # Check for imports inside function
        self._check_imports_in_function(node)

        self.generic_visit(node)
        self._function_name = old_function

    def _check_list_comprehension_opportunity(self, node: ast.For) -> None:
        """Check if a for loop can be replaced with list comprehension."""
        if not self.is_rule_enabled("detect_list_comprehension_opportunities"):
            return

        # Simple pattern: for x in y: result.append(expr(x))
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
        """Check for inefficient string concatenation in loops."""
        if not self.is_rule_enabled("detect_inefficient_string_concatenation"):
            return
        if self._loop_depth == 0:
            return

        # Find augmented assignments like += in loops
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign):
                if isinstance(child.op, ast.Add):
                    target = child.target
                    if isinstance(target, ast.Name):
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
                                self.RULES["detect_inefficient_string_concatenation"][
                                    "severity"
                                ],
                            ),
                            child,
                            fix=fix,
                        )

    def _check_generator_opportunity(self, node: ast.ListComp) -> None:
        """Check if list comprehension can be replaced with generator."""
        if not self.is_rule_enabled("detect_generator_opportunities"):
            return

        # Check if used in a context where generator would work
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
        """Check for repeated dict lookups in loops."""
        if not self.is_rule_enabled("detect_dict_lookup_in_loop"):
            return

        # Find repeated dict[key] patterns
        dict_lookups = {}
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
        """Check for repeated attribute lookups in loops."""
        if not self.is_rule_enabled("detect_repeated_attribute_lookup"):
            return

        attr_lookups = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                base = self._get_attribute_base(child)
                if base:
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
        """Check for unnecessary list() calls."""
        if not self.is_rule_enabled("detect_unnecessary_list_creation"):
            return

        if isinstance(node.func, ast.Name) and node.func.id == "list":
            if len(node.args) == 0:
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
        """Check for imports inside function definitions."""
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

    # Helper methods
    def _get_attribute_base(self, node: ast.AST) -> Optional[str]:
        """Get the base name of an attribute chain."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_attribute_base(node.value)
        return None

    def _get_subscript_base(self, node: ast.Subscript) -> Optional[str]:
        """Get the base of a subscript expression."""
        if isinstance(node.value, ast.Name):
            return node.value.id
        elif isinstance(node.value, ast.Attribute):
            return self._get_attribute_base(node.value)
        return None

    def _create_list_comp_fix(self, loop: ast.For, expr: ast.AST) -> Fix:
        """Create a fix for list comprehension opportunity."""
        target = ast.unparse(loop.target)
        iter_expr = ast.unparse(loop.iter)
        expr_str = ast.unparse(expr)

        replacement = f"[{expr_str} for {target} in {iter_expr}]"
        return Fix(
            description="Replace loop with list comprehension",
            replacement_code=replacement,
            confidence=0.9,
            auto_applicable=True,
        )

    def _create_join_fix(self, node: ast.AugAssign) -> str:
        """Create a fix for string concatenation."""
        return "# Use '\n'.join(items) or similar pattern"

    def _create_generator_fix(self, node: ast.ListComp) -> str:
        """Create a fix for generator expression."""
        comp_str = ast.unparse(node)
        return comp_str.replace("[", "(", 1).replace("]", ")", 1)
