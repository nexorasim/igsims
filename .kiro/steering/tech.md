# Technology Stack

## Primary Technologies

- **Language**: Python
- **Cloud Platform**: Firebase (Google Cloud)
- **AI Development**: Qodo platform integration

## Development Environment

- **Version Control**: Git
- **License**: Apache License 2.0
- **Python Package Management**: Supports multiple managers (pip, poetry, uv, pdm, pixi)

## Project Configuration

- Firebase project: `bamboo-reason-483913-i4`
- Qodo agents and workflows enabled
- Standard Python .gitignore with comprehensive exclusions

## Common Commands

Since the project is in early stages, specific build/test commands are not yet established. When implementing:

### Python Development
```bash
# Virtual environment setup (choose one)
python -m venv venv
# or
uv venv
# or  
poetry install

# Activate environment
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
# or
poetry install
# or
uv pip install -r requirements.txt
```

### Firebase Deployment
```bash
# Deploy to Firebase
firebase deploy

# Local Firebase emulation
firebase serve
```

### Testing
```bash
# Run tests (when implemented)
pytest
# or
python -m pytest

# With coverage
pytest --cov
```

## Code Quality Tools

Configure these tools as the project grows:
- **Linting**: ruff, flake8, or pylint
- **Formatting**: black or ruff format
- **Type Checking**: mypy
- **Testing**: pytest