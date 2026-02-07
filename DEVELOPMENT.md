# Development Guide

This guide covers local development setup, running tests, and contributing.

## Prerequisites
- Python 3.8+
- pip
- Git

## Setup
1. Create a virtual environment:
```bash
python -m venv .venv
```

2. Activate it:
```bash
# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
pip install -e ".[dev]"
```

4. Verify installation:
```bash
wss --help
wss-web --help
```

## Running Tests
```bash
pytest
```

With coverage:
```bash
pytest --cov=website_security_scanner --cov-report=term-missing
```

## Project Structure
- `src/website_security_scanner/` core package
- `src/website_security_scanner/analyzers/` platform analyzers
- `src/website_security_scanner/web/` web interface
- `tests/` unit tests

## Contributing
1. Create a branch.
2. Add tests for new features.
3. Update docs and `CHANGELOG.md` as needed.
4. Run `pytest` before submitting.
