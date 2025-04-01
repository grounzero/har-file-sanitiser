# har-file-sanitiser

# HAR File Sanitizer

A comprehensive tool for sanitizing HAR (HTTP Archive) files to safely prepare browser logs for sharing with third parties.

## Overview

This tool thoroughly sanitizes HAR files by removing or redacting sensitive and unnecessary data while preserving the essential application-specific information needed for analysis. It's designed with security in mind, using a whitelist-based approach to minimize accidental data leaks.

## Features

### Core Capabilities

- **Application-Specific Log Filtering**: Retains only necessary information for debugging and analysis
- **Robust Sensitive Data Detection**: Uses regex patterns to identify and redact sensitive information
- **Consistent Anonymization**: Replaces sensitive values with hashed versions to maintain referential integrity

### Data Sanitization

Sanitizes the following types of sensitive information:

- **Server Information**:
  - Internal/external server names and hostnames

- **Authentication & Authorization Data**:
  - OAuth tokens, JWT tokens
  - Authorization headers
  - API keys and secrets
  - Session IDs and access tokens

- **Personal Identifiable Information (PII)**:
  - Email addresses
  - Phone numbers
  - IP addresses
  - GUIDs/UUIDs
  - Credit card numbers

- **Headers & Parameters**:
  - Custom proprietary headers
  - Cookies and session data
  - Sensitive query parameters
  - Tracking parameters (utm_*, fbclid, etc.)

- **Content**:
  - Request payloads
  - Response bodies
  - Form data
  - Base64-encoded content

### Security Considerations

- Whitelist-based approach for maximum security
- Consistent hashing to maintain data relationships
- Preservation of error message context while removing sensitive data
- Timestamps are preserved to maintain activity timing information
- Sanitization metadata added to track processing

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/har-sanitizer.git
cd har-sanitizer

# Option 1: Install directly
pip install -e .

# Option 2: Install requirements only
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
python har_sanitizer.py input.har sanitized.har
```

### As a Library

```python
from har_sanitizer import HARSanitizer

# Initialize the sanitizer
sanitizer = HARSanitizer()

# Load a HAR file
with open('input.har', 'r') as f:
    har_data = json.load(f)

# Sanitize the HAR data
sanitized_har = sanitizer.sanitize_har(har_data)

# Save the sanitized HAR file
with open('sanitized.har', 'w') as f:
    json.dump(sanitized_har, f, indent=2)
```

### Custom Configuration

```python
# Configure with custom options
config = {
    "preserve_timestamps": True,
    "remove_tracking_params": True
}

sanitizer = HARSanitizer(config=config)
```

## Sanitization Details

| Data Type | Treatment |
|-----------|-----------|
| Authentication Tokens | Redacted with hash |
| Cookies | Completely redacted |
| API Keys | Redacted with hash |
| PII (email, phone) | Replaced with pattern markers |
| Base64 Content | Removed completely |
| Query Parameters | Sensitive ones redacted, tracking ones removed |
| User-Agent | Redacted |
| Referer | Redacted |
| JSON Content | Recursively sanitized |

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

**After sanitization:**
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

## Security Considerations

- This tool is designed for preparing HAR files for sharing with third parties.
- Always review sanitized files before sharing to ensure all sensitive data has been removed.
- Consider implementing additional domain-specific sanitization as needed.

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
