# Contributing to PDB2JSON Scripting Examples

Thank you for your interest in contributing to this project! This repository contains scripts that demonstrate the use of the JSON-based interface to the network-hosted Code+PDB analysis server.

## Table of Contents
- [Getting Started](#getting-started)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)
- [Security](#security)

## Getting Started

### Prerequisites

**PowerShell Scripts:**
- PowerShell 5.0 or later
- ShowUI module for GUI functionality
- Administrative privileges for memory scanning operations

**Python Scripts:**
- Python 2.7 (for Volatility compatibility)
- Required packages listed in `requirements.txt`
- Volatility Framework 2.1

**Bash Scripts:**
- llvm-readobj-4 or higher
- curl
- bc (basic calculator)

### Setting Up Your Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/K2/Scripting.git
   cd Scripting
   ```

2. For Python development:
   ```bash
   pip install -r requirements.txt
   ```

3. For PowerShell development:
   ```powershell
   Import-Module ShowUI
   ```

## Code Style

### PowerShell
- Use approved PowerShell verbs (Get-, Set-, New-, etc.)
- Follow the [PowerShell Practice and Style guide](https://github.com/PoshCode/PowerShellPracticeAndStyle)
- Include comment-based help for all functions using `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, and `.NOTES`
- Use PascalCase for function names and parameters
- Use proper error handling with try/catch blocks

### Python
- Follow PEP 8 style guidelines
- Use docstrings for all classes and functions
- Include type hints where appropriate
- Keep compatibility with Python 2.7 for Volatility plugins

### Bash
- Follow the Google Shell Style Guide
- Include function documentation
- Use proper error handling
- Make scripts portable (avoid bash-specific features when possible)

## Submitting Changes

### Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the code style guidelines
4. Add tests if applicable
5. Update documentation to reflect your changes
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to your branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Commit Messages

- Use clear and descriptive commit messages
- Start with a verb in the imperative mood (e.g., "Add", "Fix", "Update")
- Keep the first line under 72 characters
- Provide additional context in the commit body if needed

Example:
```
Add validation for SHA256 hash format

- Implement regex pattern matching for Base64-encoded hashes
- Add error messages for invalid hash formats
- Include unit tests for validation function
```

## Reporting Issues

When reporting issues, please include:

1. **Description**: Clear description of the problem
2. **Steps to Reproduce**: Detailed steps to reproduce the issue
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Environment**:
   - Operating System and version
   - PowerShell/Python/Bash version
   - Relevant module/package versions
6. **Logs/Error Messages**: Any error messages or relevant log output
7. **Additional Context**: Any other context about the problem

## Security

### Reporting Security Vulnerabilities

If you discover a security vulnerability, please do NOT open a public issue. Instead:

1. Email the maintainer directly (refer to the LICENSE file for contact information)
2. Provide a detailed description of the vulnerability
3. Include steps to reproduce if possible
4. Allow time for the vulnerability to be addressed before public disclosure

### Security Best Practices

When contributing:
- Never commit credentials, API keys, or sensitive data
- Use environment variables for configuration
- Validate all user inputs
- Follow the principle of least privilege
- Use secure communication (HTTPS) for network requests
- Properly handle and sanitize file paths

## Code of Conduct

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them learn
- Focus on constructive criticism
- Respect differing viewpoints and experiences
- Accept responsibility and apologize for mistakes

### Unacceptable Behavior

- Harassment, discriminatory language, or personal attacks
- Publishing others' private information
- Trolling, insulting comments, or deliberate intimidation
- Other conduct which could reasonably be considered inappropriate

## Additional Resources

- [README.md](README.md) - Project overview and usage examples
- [Azure Functions Documentation](https://docs.microsoft.com/azure/azure-functions/)
- [Volatility Framework](https://www.volatilityfoundation.org/)
- [PowerShell Documentation](https://docs.microsoft.com/powershell/)

## Questions?

If you have questions about contributing, feel free to:
- Open an issue with the "question" label
- Check existing issues and discussions
- Refer to the project README for basic usage information

Thank you for contributing!
