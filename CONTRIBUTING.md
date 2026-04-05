# Contributing to Whirlpool

Thank you for your interest in contributing to Whirlpool! This document provides guidelines and instructions for contributing.

## Development Environment Setup

### Prerequisites

- **Python** 3.9+ with pip
- **Git** for version control

### Getting Started

```bash
# Fork and clone the repository
git clone https://github.com/<your-username>/Whirlpool.git
cd Whirlpool

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run the full lint suite
ruff check whirlpool/
mypy whirlpool/
```

## Code Style

All code must pass the following checks before submission:

- **Linting:** `ruff check whirlpool/` -- zero warnings allowed
- **Type checking:** `mypy whirlpool/` -- all types must resolve
- **Tests:** `python -m pytest tests/ -v` -- all tests must pass

Run all three before submitting a PR:

```bash
ruff check whirlpool/
mypy whirlpool/
python -m pytest tests/ -v
```

## Testing Requirements

- All existing tests must continue to pass: `python -m pytest tests/ -v`
- New features must include tests
- Integration tests go in the `tests/` directory
- Unit tests go in the source file using standard pytest patterns

## Pull Request Process

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** with clear, focused commits.

3. **Test thoroughly:**
   ```bash
   ruff check whirlpool/
   mypy whirlpool/
   python -m pytest tests/ -v
   ```

4. **Push** your branch and open a Pull Request against `main`.

5. **Describe your changes** in the PR using the provided template.

6. **Respond to review feedback** promptly.

## Commit Message Format

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type       | Description                          |
| ---------- | ------------------------------------ |
| `feat`     | New feature                          |
| `fix`      | Bug fix                              |
| `docs`     | Documentation changes                |
| `style`    | Formatting, no code change           |
| `refactor` | Code restructuring, no behavior change |
| `test`     | Adding or updating tests             |
| `ci`       | CI/CD changes                        |
| `chore`    | Maintenance, dependencies            |
| `perf`     | Performance improvements             |

### Examples

```
feat(parser): add WinPEAS beta format support
fix(ranker): handle missing reliability scores gracefully
docs: update knowledge base entry counts
ci: add mypy type checking to CI pipeline
```

### Important

- Do **not** include AI co-author signatures in commits.
- Keep commits focused on a single logical change.

## Questions?

If you have questions about contributing, feel free to open a discussion or issue on GitHub.
