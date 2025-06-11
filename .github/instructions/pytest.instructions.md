---
applyTo: "tests/**/*.py"
---
# Standards for writing tests with pytest

- Use `pytest` for all testing.
- Write tests in the `tests/` directory.
- Do not write Test classes; use functions instead.
- Use `pytest.mark.parametrize` to parametrize tests when applicable.
- Use existing utilities from `tests/utils.py` and `tests/conftest.py` for common test functionality.
