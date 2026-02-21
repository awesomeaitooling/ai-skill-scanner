# Contributing to Skills Scanner

Thank you for your interest in contributing! This guide will help you get started.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+ (for the visualization UI)
- An API key for at least one supported LLM provider (OpenAI, Google Gemini, Anthropic, AWS Bedrock, or Azure OpenAI)

### Development Setup

1. Clone the repository:

```bash
git clone https://github.com/your-org/skills-scanner.git
cd skills-scanner
```

2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

3. (Optional) Install AI provider dependencies:

```bash
pip install langchain langchain-openai     # For OpenAI
pip install langchain langchain-google-genai  # For Google Gemini
pip install langchain langchain-anthropic     # For Anthropic
pip install langchain langchain-aws           # For AWS Bedrock
```

4. Set up environment variables:

```bash
cp .env.example .env
# Edit .env with your API key
```

5. Set up the visualization UI:

```bash
cd viz
npm install
cd ..
```

## Running Tests

```bash
pytest
pytest --cov=scanner     # With coverage
pytest tests/ -v         # Verbose output
```

## Code Quality

We use the following tools to maintain code quality:

```bash
ruff check scanner/             # Lint
ruff check scanner/ --fix       # Lint with auto-fix
black scanner/ tests/           # Format
mypy scanner/                   # Type checking
```

Please ensure all checks pass before submitting a pull request.

## Making Changes

1. Create a feature branch from `main`:

```bash
git checkout -b feature/your-feature-name
```

2. Make your changes. Follow these guidelines:
   - Write clear, descriptive commit messages
   - Add tests for new functionality
   - Update documentation if you change behavior or add features
   - Keep changes focused — one feature or fix per pull request

3. Run the test suite and code quality checks before pushing.

4. Push your branch and open a pull request.

## Pull Request Guidelines

- Provide a clear description of what the PR does and why
- Reference any related issues (e.g., "Fixes #42")
- Keep PRs small and focused when possible
- Ensure CI checks pass
- Be responsive to review feedback

## Adding Security Rules

Security rules are defined as YAML files in `scanner/rules/yaml/`. Each rule file contains patterns for a specific vulnerability category. To add a new rule:

1. Create or edit a YAML file in `scanner/rules/yaml/`
2. Follow the existing rule format (id, pattern, severity, category, description)
3. Add tests covering the new patterns
4. Update documentation if adding a new category

## Reporting Security Issues

If you discover a security vulnerability in the scanner itself, please report it responsibly. Do **not** open a public issue. Instead, email the maintainers directly or use the repository's private vulnerability reporting feature.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
