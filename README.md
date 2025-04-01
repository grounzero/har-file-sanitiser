# HAR File Sanitiser

A comprehensive tool for sanitising HAR (HTTP Archive) files to safely prepare browser logs for sharing with third parties.

## Overview

This tool thoroughly sanitises HAR files by removing or redacting sensitive and unnecessary data whilst preserving the essential application-specific information needed for analysis. It's designed with security in mind, using a whitelist-based approach to minimise accidental data leaks.

## Features

### Core Capabilities

- **Application-Specific Log Filtering**: Retains only necessary information for debugging and analysis
- **Robust Sensitive Data Detection**: Uses regex patterns to identify and redact sensitive information
- **Consistent Anonymisation**: Replaces sensitive values with hashed versions to maintain referential integrity

### Data Sanitisation

Sanitises the following types of sensitive information:

- **Server Information**:
  - Internal/external server names and hostnames

- **Authentication & Authorisation Data**:
  - OAuth tokens, JWT tokens
  - Authorisation headers
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
- Preservation of error message context whilst removing sensitive data
- Timestamps are preserved to maintain activity timing information
- Sanitisation metadata added to track processing

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/har-sanitiser.git
cd har-sanitiser

# Option 1: Install directly
pip install -e .

# Option 2: Install requirements only
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
python har_sanitiser.py input.har sanitised.har
```

### As a Library

```python
from har_sanitiser import HARSanitiser

# Initialise the sanitiser
sanitiser = HARSanitiser()

# Load a HAR file
with open('input.har', 'r') as f:
    har_data = json.load(f)

# Sanitise the HAR data
sanitised_har = sanitiser.sanitise_har(har_data)

# Save the sanitised HAR file
with open('sanitised.har', 'w') as f:
    json.dump(sanitised_har, f, indent=2)
```

### Custom Configuration

```python
# Configure with custom options
config = {
    "preserve_timestamps": True,
    "remove_tracking_params": True
}

sanitiser = HARSanitiser(config=config)
```

## Sanitisation Details

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
| JSON Content | Recursively sanitised |

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

## Security Considerations

- This tool is designed for preparing HAR files for sharing with third parties.
- Always review sanitised files before sharing to ensure all sensitive data has been removed.
- Consider implementing additional domain-specific sanitisation as needed.

## Licence

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
