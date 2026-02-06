# fnOS Mock Server Constitution

## 1. Technology Stack

### 1.1 Core Technologies
- **Language**: Python 3.11+
- **Web Framework**: FastAPI
- **WebSocket**: FastAPI WebSocket support
- **Cryptography**: pycryptodome (for RSA key generation)

### 1.2 Dependencies
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `websockets` - WebSocket support
- `pycryptodome` - Cryptographic operations
- `pydantic` - Data validation

## 2. Coding Standards

### 2.1 Code Style
- Follow PEP 8 style guide
- Use type hints for all function signatures
- Maximum line length: 100 characters
- Use meaningful variable and function names

### 2.2 Project Structure
```
fnos-mock-server/
├── server/              # Main application code
│   ├── __init__.py
│   ├── main.py         # Application entry point
│   ├── handlers.py     # Request handlers
│   ├── responses.py    # Response builders
│   └── utils.py        # Utility functions
├── responses/          # Pre-defined response JSON files
├── tests/              # Test files
├── spec.md            # Feature specification
├── constitution.md    # This file
└── pyproject.toml     # Project configuration
```

### 2.3 Naming Conventions
- **Files**: snake_case (e.g., `request_handler.py`)
- **Classes**: PascalCase (e.g., `RequestHandler`)
- **Functions**: snake_case (e.g., `handle_request`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `DEFAULT_PORT`)

## 3. Security Rules

### 3.1 Authentication
- Mock server does not require authentication
- No sensitive data should be logged

### 3.2 Input Validation
- Validate all incoming JSON data
- Handle malformed input gracefully
- Use Pydantic models for data validation

### 3.3 Cryptography
- Use standard cryptographic libraries (pycryptodome)
- Generate strong random keys for testing
- Never hardcode sensitive data in source code

## 4. Performance Requirements

### 4.1 Response Time
- Pre-defined responses: < 10ms
- Real-time responses: < 100ms

### 4.2 Concurrency
- Support at least 50 concurrent WebSocket connections
- Use async/await for all I/O operations

### 4.3 Memory Usage
- Memory usage should not exceed 100MB
- Load JSON files on demand, not all at startup

## 5. Testing Strategy

### 5.1 Unit Tests
- Test all request handlers
- Test response builders
- Test utility functions

### 5.2 Integration Tests
- Test WebSocket connection flow
- Test request-response cycle
- Test with actual pyfnos client

### 5.3 Test Coverage
- Aim for > 80% code coverage
- Test all edge cases defined in spec.md

## 6. Logging Guidelines

### 6.1 Log Levels
- **DEBUG**: Detailed information for debugging
- **INFO**: Normal operational messages
- **WARNING**: Unexpected but recoverable situations
- **ERROR**: Error conditions

### 6.2 Log Content
- Log incoming requests (at DEBUG level)
- Log errors with stack traces
- Do not log sensitive data (passwords, secrets)

## 7. Error Handling

### 7.1 Principles
- Never expose internal details to clients
- Always return valid JSON responses
- Log all errors for debugging

### 7.2 Error Response Format
```json
{
  "result": "fail",
  "reqid": "请求ID",
  "errmsg": "错误描述"
}
```

## 8. Documentation

### 8.1 Code Documentation
- Use docstrings for all public functions
- Include type hints in docstrings
- Document complex algorithms

### 8.2 External Documentation
- README.md with usage instructions
- API documentation (FastAPI auto-docs)
- Examples in examples/ directory

## 9. Version Control

### 9.1 Git Workflow
- Use feature branches for development
- Pull requests for code review
- Semantic versioning (MAJOR.MINOR.PATCH)

### 9.2 Commit Messages
- Use conventional commit format
- Examples:
  - `feat: add support for user.info request`
  - `fix: handle missing reqid field`
  - `docs: update README with new examples`

## 10. Deployment

### 10.1 Packaging
- Use pyproject.toml for dependency management
- Package as a Python package
- Include setup.py for compatibility

### 10.2 Configuration
- Use environment variables for configuration
- Support command-line arguments for common options
- Default configuration should work out of the box

### 10.3 Dependencies
- Pin dependency versions in pyproject.toml
- Use uv or pip-tools for dependency management
- Regularly update dependencies for security patches