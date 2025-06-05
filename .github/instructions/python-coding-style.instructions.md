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
