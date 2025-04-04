# HAR File Sanitiser

A tool for sanitising HAR (HTTP Archive) files to safely prepare browser logs for sharing with third parties.

## Overview

This tool sanitises HAR files by removing or redacting sensitive and unnecessary data whilst preserving the essential application-specific information needed for analysis. It's designed with security in mind, using a whitelist-based approach to minimise accidental data leaks.

## Features

### Core Capabilities

- **Application-Specific Log Filtering**: Retains only necessary information for debugging and analysis
- **Robust Sensitive Data Detection**: Uses advanced regex patterns with validation to identify and redact sensitive information
- **Consistent Anonymisation**: Replaces sensitive values with hashed versions to maintain referential integrity
- **Error Resilience**: Continues processing even if individual entries have issues

### Data Sanitisation

Sanitises the following types of sensitive information:

- **Server Information**:
  - Internal/external server names and hostnames

- **Authentication & Authorisation Data**:
  - OAuth tokens, JWT tokens (with proper JWT structure validation)
  - Authorisation headers
  - API keys and secrets
  - Session IDs and access tokens

- **Personal Identifiable Information (PII)**:
  - Email addresses (RFC 5322 compliant detection)
  - Phone numbers (E.164 and common regional formats)
  - IP addresses (with proper range validation)
  - GUIDs/UUIDs (RFC 4122 compliant)
  - Credit card numbers (with Luhn algorithm validation)

- **Headers & Parameters**:
  - Custom proprietary headers
  - Cookies and session data
  - Sensitive query parameters
  - Tracking parameters (utm_*, fbclid, etc.)

- **Content**:
  - Request payloads
  - Response bodies
  - Form data
  - Base64-encoded content (with validation for actual encoded text)

### Security Considerations

- Whitelist-based approach for maximum security
- Consistent hashing to maintain data relationships
- Preservation of error message context whilst removing sensitive data
- Timestamps are preserved to maintain activity timing information
- Sanitisation metadata added to track processing
- Proper validation to reduce false positives

## Project Structure

```markdown
har-file-sanitiser/
├── src/                      # Source code
│   └── har_sanitiser/        # Main package
│       ├── __init__.py       # Package exports
│       ├── core.py           # Core sanitisation functionality
│       ├── utils.py          # Utility functions
│       └── cli.py            # Command-line interface
├── tests/                    # Test suite
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── fixtures/             # Test fixtures
├── examples/                 # Example usage
│   ├── example_usage.py      # Example script
│   ├── sample.har            # Sample HAR file
│   └── custom_config.json    # Example configuration
├── docs/                     # Documentation
├── setup.py                  # Package setup script
├── pyproject.toml            # Project metadata
└── requirements.txt          # Dependencies
```

## Prerequisites

- Python 3.6 or higher (recommended due to type hints)
- Git (for cloning the repository)

You can check your Python version with:
```bash
python --version
```

## Installation

This package can be installed either directly from the repository or by installing the requirements.

### Step 1: Clone the Repository

```bash
git clone https://github.com/grounzero/har-file-sanitiser.git
cd har-file-sanitiser
```

### Step 2: Set Up a Virtual Environment (Recommended)

Using a virtual environment ensures that the dependencies for this project don't interfere with other Python projects on your system.

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On macOS/Linux:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

When you're done working with the package, you can deactivate the virtual environment:

```bash
deactivate
```

### Step 3: Install the Package

Choose one of the following installation methods:

- Option 1: Install as an editable package (recommended for development)
```bash
pip install -e .
```
- Option 2: Install requirements only
```bash
pip install -r requirements.txt
```




## Verification

After installation, it's recommended to run the tests to ensure everything is working correctly:

```bash
# Install pytest if not already installed
pip install pytest

# Run the tests
python -m pytest
```

## Usage

### Command Line

Basic usage:
```bash
# Activate the virtual environment (if not already activated)
source venv/bin/activate  # On Windows, use: venv\Scripts\activate

# Run the sanitiser
har-sanitiser input.har sanitised.har
```

With additional options:
```bash
# Enable verbose logging
har-sanitiser --verbose input.har sanitised.har

# Use a custom configuration file
har-sanitiser --config my_config.json input.har sanitised.har

# Disable parallel processing (parallel processing is enabled by default)
har-sanitiser --no-parallel input.har sanitised.har

# Combine options
har-sanitiser --verbose --config my_config.json --no-parallel input.har sanitised.har

# Use default output filename (creates input_sanitised.har)
har-sanitiser --verbose --config my_config.json input.har
```

### Large File Processing

The sanitiser automatically detects large HAR files and uses streaming processing to handle them efficiently:
- Reduces memory usage by processing entries incrementally
- Provides progress reporting with a progress bar
- Automatically selects the best processing method based on file sise
- Uses parallel processing by default for faster sanitisation

```bash
# Disable parallel processing for large files
har-sanitiser --no-parallel input.har output.har

# Specify the number of processes to use for parallel processing
har-sanitiser --processes 4 input.har output.har
```

### Configuration File

Example configuration file (JSON format):
```json
{
  "log_level": "debug",
  "sensitive_headers": ["x-custom-header", "x-internal-id"],
  "sensitive_params": ["account", "user_id"],
  "preserve_timestamps": true,
  "remove_tracking_params": true
}
```

### As a Library

```python
from har_sanitiser import HARSanitiser, read_har_file, write_har_file

# Initialise the sanitiser
sanitiser = HARSanitiser()

# Load a HAR file using the utility function
har_data = read_har_file('input.har')

# Sanitise the HAR data
sanitised_har = sanitiser.sanitise(har_data)

# Save the sanitised HAR file using the utility function
write_har_file('sanitised.har', sanitised_har)

# For large files, use the streaming API (parallel processing is enabled by default)
duration = sanitiser.sanitise_har_streaming('input.har', 'sanitised.har')
print(f"Sanitisation completed in {duration:.2f} seconds")
print(f"Sensitive data found: {sum(sanitiser.metrics['sensitive_data_found'].values())} instances")

# To disable parallel processing
duration = sanitiser.sanitise_har_streaming('input.har', 'sanitised.har', use_parallel=False)
```

### Custom Configuration

```python
# Configure with custom options
config = {
    "log_level": "info",
    "preserve_timestamps": True,
    "remove_tracking_params": True
}

sanitiser = HARSanitiser(config=config)
```
The configuration file supports the following options:

| Option | Description | Default |
|--------|-------------|---------|
| `log_level` | Logging level (debug, info, warning, error) | info |
| `sensitive_headers` | List of headers to redact | ['authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-client-id', 'x-session-id', 'user-agent', 'referer', 'x-forwarded-for', 'etag', 'if-modified-since', 'last-modified'] |
| `sensitive_params` | List of query parameters to redact | ['token', 'key', 'password', 'secret', 'auth'] |
| `tracking_params` | List of tracking parameters to remove | ['utm_', 'fbclid', 'gclid', '_ga'] |
| `preserve_timestamps` | Whether to preserve original timestamps | true |
| `remove_tracking_params` | Whether to remove tracking parameters | true |
| `hash_sensitive_values` | Whether to hash sensitive values | true |
| `redact_base64_content` | Whether to redact base64 content | true |
| `parallel` | Whether to use parallel processing | true |
| `processes` | Number of processes to use for parallel processing | number of CPU cores |
| `excluded_domains` | List of domains to exclude from sanitisation | [] |
| `content_types_to_sanitise` | List of content types to sanitise | ['application/json', 'application/x-www-form-urlencoded', 'text/plain', 'text/html'] |
| `sanitisation_options` | Options for specific data types | {'ip_addresses': true, 'email_addresses': true, 'credit_cards': true, 'phone_numbers': true, 'guid_uuid': true, 'jwt_tokens': true} |


## Running Tests

The project includes a comprehensive test suite to verify sanitisation functionality:

```bash
# Install pytest if not already installed
pip install pytest

# Run the tests
python -m pytest
```

The test suite covers:
- Unit tests for individual components
- Validation for data pattern recognition
- Credit card Luhn algorithm checks
- Integration tests for full sanitisation flow

## Sanitisation Details

| Data Type | Treatment |
|-----------|-----------|
| Authentication Tokens | Redacted with hash |
| Cookies | Completely redacted |
| API Keys | Redacted with hash |
| PII (email, phone) | Replaced with pattern markers |
| Credit Cards | Validated with Luhn check before redaction, supports various formats (spaces, dashes) |
| Base64 Content | Removed after validation |
| Query Parameters | Sensitive ones redacted, tracking ones removed |
| User-Agent | Redacted |
| Referer | Redacted |
| JSON Content | Recursively sanitised |
| Problematic Entries | Logged and skipped |

## Example

**Before (simplified excerpt):**
```json
{
  "request": {
    "headers": [
      { "name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." },
      { "name": "User-Agent", "value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..." }
    ],
    "url": "https://api.example.com/users?token=12345&email=user@example.com"
  }
}
```

**After sanitisation:**
```json
{
  "request": {
    "headers": [
      { "name": "Authorization", "value": "[REDACTED-a1b2c3d4e5f6]" },
      { "name": "User-Agent", "value": "[REDACTED-7890abcdef12]" }
    ],
    "url": "https://api.example.com/users?token=[REDACTED-abcdef123456]&email=[REDACTED-email]"
  }
}
```

## Implementation Notes

- **Enhanced Regex Patterns**: Improved regex patterns for better detection and fewer false positives
- **Comprehensive Credit Card Detection**: Support for various credit card formats including those with spaces, dashes, and other separators
- **Luhn Algorithm**: Credit card numbers are validated with the Luhn check algorithm
- **Error Handling**: Graceful handling of problematic entries
- **Directory Creation**: Automatically creates output directories if they don't exist
- **Configurable Logging**: Adjustable log levels via configuration or command line flags
- **Modern Timestamp Handling**: Uses timezone-aware datetime objects for accurate metadata

## Security Considerations

- This tool is designed for preparing HAR files for sharing with third parties.
- Always review sanitised files before sharing to ensure all sensitive data has been removed.
- Consider implementing additional domain-specific sanitisation as needed.


## Troubleshooting

### Common Issues

1. **Missing dependencies**: If you encounter import errors, ensure you've installed the package correctly using one of the installation methods.

2. **Invalid HAR file**: If you get JSON parsing errors, verify that your HAR file is valid. You can use online JSON validators to check.

3. **Configuration errors**: If the sanitiser isn't behaving as expected, check your configuration file for syntax errors or invalid options.

### Debugging

Enable verbose logging to get more information about the sanitisation process:

```bash
python har_sanitiser.py --verbose input.har sanitised.har
```

## Licence

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
