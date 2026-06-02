"""AST-based fixer for applying code transformations."""

import ast
from typing import Optional

from .base import BaseFixer
from ..analyzers.base import Issue


class ASTFixer(BaseFixer):
    """Fixer that applies transformations using AST manipulation."""

    def apply_fix(self, source_code: str, issue: Issue) -> Optional[str]:
        """Apply a fix to source code and return modified code."""
        if not issue.fix:
            return None

        try:
            tree = ast.parse(source_code)
            transformer = self._get_transformer(issue)
            if transformer:
                modified_tree = transformer.visit(tree)
                return ast.unparse(modified_tree)
            else:
                # Fallback: simple text replacement
                return self._text_replace_fix(source_code, issue)
        except (ValueError, AttributeError, RecursionError):
            return None

    def _get_transformer(self, issue: Issue) -> Optional[ast.NodeTransformer]:
        """Get the appropriate AST transformer for an issue."""
        transformers = {
            "detect_list_comprehension_opportunities": ListCompTransformer,
            "detect_unnecessary_list_creation": ListLiteralTransformer,
            "detect_yaml_load": YAMLSafeLoadTransformer,
            "detect_debug_mode": DebugModeTransformer,
        }
        transformer_class = transformers.get(issue.rule_id)
        if transformer_class:
            return transformer_class()
        return None

    def _text_replace_fix(self, source_code: str, issue: Issue) -> Optional[str]:
        """Apply fix using simple text replacement."""
        if not issue.fix or not issue.fix.replacement_code:
            return None

        lines = source_code.split("\n")
        if issue.line < 1 or issue.line > len(lines):
            return None

        # Replace the line with the fix
        lines[issue.line - 1] = issue.fix.replacement_code
        return "\n".join(lines)


class ListCompTransformer(ast.NodeTransformer):
    """Transform loops into list comprehensions."""

    def visit_For(self, node: ast.For) -> ast.AST:
        """Convert simple append loops to list comprehensions."""
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
                # Create list comprehension
                list_comp = ast.ListComp(
                    elt=call.args[0],
                    generators=[
                        ast.comprehension(
                            target=node.target,
                            iter=node.iter,
                            ifs=[],
                            is_async=0,
                        )
                    ],
                )
                # Return assignment to list variable
                return ast.Assign(
                    targets=[call.func.value],
                    value=list_comp,
                )
        return self.generic_visit(node)


class ListLiteralTransformer(ast.NodeTransformer):
    """Transform list() calls to [] literals."""

    def visit_Call(self, node: ast.Call) -> ast.AST:
        """Replace list() with []."""
        if isinstance(node.func, ast.Name) and node.func.id == "list":
            if len(node.args) == 0 and len(node.keywords) == 0:
                return ast.List(elts=[], ctx=ast.Load())
        return self.generic_visit(node)


class YAMLSafeLoadTransformer(ast.NodeTransformer):
    """Transform yaml.load() to yaml.safe_load()."""

    def visit_Call(self, node: ast.Call) -> ast.AST:
        """Replace yaml.load with yaml.safe_load."""
        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "yaml"
                and node.func.attr == "load"
            ):
                node.func.attr = "safe_load"
                return node
        return self.generic_visit(node)


class DebugModeTransformer(ast.NodeTransformer):
    """Transform DEBUG = True to DEBUG = False."""

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        """Replace DEBUG = True with DEBUG = False."""
        if (
            len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "DEBUG"
        ):
            if isinstance(node.value, ast.Constant) and node.value.value is True:
                node.value = ast.Constant(value=False)
                return node
        return self.generic_visit(node)
