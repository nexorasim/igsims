# Project Structure

## Current Directory Layout

```
igsims/
├── .firebaserc              # Firebase project configuration
├── .git/                    # Git version control
├── .gitignore              # Python-focused ignore patterns
├── .kiro/                  # Kiro AI assistant configuration
│   └── steering/           # AI guidance documents
├── .qodo/                  # Qodo AI platform integration
│   ├── agents/             # AI agent configurations
│   └── workflows/          # Automated workflow definitions
├── LICENSE                 # Apache License 2.0
└── README.md              # Project documentation
```

## Organization Principles

### Root Level
- Configuration files for tools and platforms
- License and documentation files
- Hidden directories for tooling (.git, .kiro, .qodo)

### Source Code (To Be Implemented)
When adding source code, follow these conventions:

```
src/                        # Main application source
├── main.py                # Application entry point
├── models/                # Data models and schemas
├── services/              # Business logic and services
├── utils/                 # Utility functions and helpers
└── config/                # Configuration management

tests/                     # Test suite
├── unit/                  # Unit tests
├── integration/           # Integration tests
└── fixtures/              # Test data and fixtures

docs/                      # Documentation
├── api/                   # API documentation
└── guides/                # User and developer guides
```

### Configuration Files
- Keep environment-specific configs in separate files
- Use `.env` files for local development (already in .gitignore)
- Store sensitive configs in Firebase/cloud configuration

### AI Integration
- `.kiro/steering/` - AI assistant guidance documents
- `.qodo/agents/` - Qodo AI agent configurations  
- `.qodo/workflows/` - Automated development workflows

## File Naming Conventions

- **Python files**: `snake_case.py`
- **Modules**: `snake_case/`
- **Constants**: `UPPER_SNAKE_CASE`
- **Classes**: `PascalCase`
- **Functions/variables**: `snake_case`

## Import Organization

Follow PEP 8 import ordering:
1. Standard library imports
2. Third-party imports  
3. Local application imports

Use absolute imports when possible.