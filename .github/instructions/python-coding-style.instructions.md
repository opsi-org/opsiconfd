---
applyTo: "**/*.py"
---
# General Python coding standards

## Code Style
- Follow PEP 8 guidelines, except use tabs instead of spaces for indentation.
- Prefer early returns to minimize code nesting.
- Prefer StrEnum for enumerations when appropriate.

## Type Hints
- Add type hints to all function signatures.
- Use the most up-to-date type hints available in Python 3.13 or later.
- Use typing.TYPE_CHECKING to ensure that imports, which are only needed for type hints, do not get imported at runtime.
- Use `from __future__ import annotations` to enable postponed evaluation of type annotations.

## Docstrings
- Ensure every function, class, and module in the codebase has a docstring.
- Revise existing docstrings to be clear, concise, and informative.
- Update all Attributes, Args, Returns, Yields, Raises, and Examples sections to accurately reflect current variable names and types.
- Format all docstrings according to the Google Python style guide.
- If a function is defined inside another function, ensure the inner function's docstring is also updated. Use a brief description for the inner function, and do **not** add Attributes, Args, Returns, Yields, Raises or Examples.

## Comments
- Ensure complex logic is well-commented.
- Do not add comments for trivial code that is self-explanatory.
- Revise existing comments to be clear, concise, and informative.
- Remove any redundant or outdated comments.

