# Audit Best Practices

> **📝 NOTA PER L'UTENTE**: Questo file è facilmente modificabile. 
> Aggiungi, rimuovi o modifica le best practices secondo le tue esigenze.
> Il sistema di audit caricherà automaticamente questo file e lo userà per verificare il codice.

This file contains the list of best practices that the AI auditor model should check for when analyzing code.

## General Principles

### 1. Code Agnosticism
- The application should be task-agnostic where possible
- Avoid hardcoding specific task details in order to be able to accomplish any kind of task
- Avoid hardcoding specific llms name: if you the code must take into account a specific model behaviour you need to abstract it in a parmeter to configure in models.json that can be shared in the future buy other llms

### 2. Configuration Management
- **NO hardcoded parameters in code** - All constant values should be in settings files
- Use environment variables for environment-specific configuration
- Configuration should be loaded at startup, not scattered throughout the code

### 3. System Prompts
- System prompts should be minimal and role-based
- Avoid embedding project-specific or task-specific knowledge in system prompts
- Use external files (like GUIDELINES.md) for project-specific context
- System prompts should be in english language where possible

### 4. Error Handling
- Use proper exception handling with specific exception types
- Never silently swallow exceptions
- Log errors with sufficient context for debugging
- Implement graceful degradation when dependencies fail

### 5. Security Best Practices
- Sensitive values (API keys, passwords) should NEVER be in code, but pnly in file .env
- Validate and sanitize all user inputs
- Use parameterized queries to prevent SQL injection
- Implement proper authentication and authorization checks
- Use HTTPS for all external communications


### 6. Code Quality
- Follow language-specific naming conventions (PEP 8 for Python, PSR for PHP)
- Write self-documenting code with clear function/method names
- Add docstrings to all public functions and classes
- Keep functions small and focused (single responsibility)
- Avoid code duplication (DRY principle)
- Use type hints where applicable


### 7. File and Resource Management
- Close file handles properly
- Clean up temporary files
- Handle file system errors gracefully

### 8. Documentation
- All features must be documented in a file inside the architecture/ folder
- Document API endpoints and their parameters
- Keep documentation up to date with code changes

### 9. Dependency Management
- Pin dependency versions in requirements files
- Avoid unnecessary dependencies
- Use virtual environment in venv/ folder for isolation

## Anti-Patterns to Detect

### 1. Code Smells
- Long functions (>50 lines)
- Deep nesting (>4 levels)
- God objects (classes doing too much)
- Feature envy (classes using too many other classes)
- Data clumps (groups of variables used together)

### 2. Security Anti-Patterns
- SQL injection vulnerabilities
- XSS vulnerabilities
- Hardcoded credentials
- Missing authentication/authorization
- Insecure direct object references
- Missing input validation

### 3. Performance Anti-Patterns
- N+1 query problems
- Missing database indexes
- Unnecessary database queries in loops
- Synchronous I/O operations
- Missing caching for expensive operations

### 4. Maintainability Anti-Patterns
- Magic numbers (unexplained constants)
- Dead code (unused functions/variables)
- Commented-out code (should be removed)
- Copy-paste programming
- Inconsistent naming conventions
- Missing or outdated comments

## Usage in Audit System

When running the audit, the model should:

1. **Check each file against applicable best practices**
2. **Report violations with specific line numbers**
3. **Provide actionable recommendations** for each issue
4. **Categorize issues by severity** (critical, high, medium, low)
5. **Prioritize security and performance issues**
6. **Reference specific best practices** from this document

The audit results should include:
- **Category**: Which best practice area is affected
- **Severity**: How critical the issue is
- **Description**: Clear explanation of the problem
- **Line Number**: Where the issue occurs
- **Code Snippet**: The problematic code
- **Recommendation**: How to fix the issue
- **Reference**: Which best practice this relates to
