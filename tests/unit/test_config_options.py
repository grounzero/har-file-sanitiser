import json
import copy
from datetime import datetime, UTC
from har_sanitiser_improved import HARSanitiser

# --- Sample HAR data for testing ---
sample_har_entry = {
    "log": {
        "version": "1.2",
        "creator": {"name": "test", "version": "1.0"},
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://example.com/api?token=abcd1234&user=test&utm_source=google&fbclid=123",
                    "headers": [
                        {"name": "Authorization", "value": "Bearer abcdef"},
                        {"name": "User-Agent", "value": "Mozilla/5.0"},
                        {"name": "X-Custom-Header", "value": "custom-value"},
                        {"name": "X-Internal-ID", "value": "internal-123"}
                    ]
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Set-Cookie", "value": "sessionid=xyz"}],
                    "content": {
                        "mimeType": "application/json",
                        "text": json.dumps({
                            "email": "test@example.com",
                            "credit_card": "4111 1111 1111 1111",
                            "guid": "123e4567-e89b-12d3-a456-426614174000",
                            "timestamp": "2023-04-04T10:00:00.000Z",
                            "base64_content": "SGVsbG8gd29ybGQ="  # "Hello world" in base64
                        })
                    }
                }
            }
        ]
    }
}

# --- Test custom sensitive headers ---
def test_custom_sensitive_headers():
    """Test that custom sensitive headers are redacted"""
    config = {
        "sensitive_headers": ["x-custom-header", "x-internal-id"]
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Sanitize the entry
    entry = har_data["log"]["entries"][0]
    s._sanitise_entry(entry)
    
    # Check that custom headers are redacted
    headers = entry["request"]["headers"]
    custom_header = next(h for h in headers if h["name"] == "X-Custom-Header")
    internal_id = next(h for h in headers if h["name"] == "X-Internal-ID")
    
    assert custom_header["value"].startswith("[REDACTED-")
    assert internal_id["value"].startswith("[REDACTED-")
    
    # Standard headers should also be redacted
    auth_header = next(h for h in headers if h["name"] == "Authorization")
    assert auth_header["value"].startswith("[REDACTED-")

# --- Test custom sensitive parameters ---
def test_custom_sensitive_params():
    """Test that custom sensitive parameters are redacted"""
    config = {
        "sensitive_params": ["user", "custom_param"]
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Add a custom parameter to the URL
    entry = har_data["log"]["entries"][0]
    entry["request"]["url"] = entry["request"]["url"] + "&custom_param=secret"
    
    # Sanitize the entry
    s._sanitise_entry(entry)
    
    # Check that custom parameters are redacted
    url = entry["request"]["url"]
    assert "user=[REDACTED-" in url
    assert "custom_param=[REDACTED-" in url
    
    # Standard sensitive parameters should also be redacted
    assert "token=[REDACTED-" in url

# --- Test tracking parameters removal ---
def test_tracking_params_removal():
    """Test that tracking parameters are removed"""
    config = {
        "remove_tracking_params": True,
        "tracking_params": ["utm_", "fbclid", "custom_tracking"]
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Add a custom tracking parameter to the URL
    entry = har_data["log"]["entries"][0]
    entry["request"]["url"] = entry["request"]["url"] + "&custom_tracking=123"
    
    # Sanitize the entry
    s._sanitise_entry(entry)
    
    # Check that tracking parameters are removed
    url = entry["request"]["url"]
    assert "utm_source" not in url
    assert "fbclid" not in url
    assert "custom_tracking" not in url
    
    # Non-tracking parameters should still be present
    assert "token=" in url
    assert "user=" in url

# --- Test disable tracking parameters removal ---
def test_disable_tracking_params_removal():
    """Test that tracking parameters are not removed when disabled"""
    config = {
        "remove_tracking_params": False
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Sanitize the entry
    entry = har_data["log"]["entries"][0]
    s._sanitise_entry(entry)
    
    # Check that tracking parameters are not removed
    url = entry["request"]["url"]
    assert "utm_source" in url
    assert "fbclid" in url
    
    # Sensitive parameters should still be redacted
    assert "token=[REDACTED-" in url

# --- Test base64 content redaction ---
def test_base64_content_redaction():
    """Test that base64 content is redacted"""
    config = {
        "redact_base64_content": True
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Create a response with base64 content
    entry = har_data["log"]["entries"][0]
    entry["response"]["content"]["text"] = json.dumps({
        "base64_content": "SGVsbG8gd29ybGQ="  # "Hello world" in base64
    })
    
    # Sanitize the entry
    s._sanitise_entry(entry)
    
    # Check that base64 content is redacted
    content = json.loads(entry["response"]["content"]["text"])
    assert content["base64_content"] == "[BASE64-CONTENT-REMOVED]"

# --- Test disable base64 content redaction ---
def test_disable_base64_content_redaction():
    """Test that base64 content is not redacted when disabled"""
    config = {
        "redact_base64_content": False
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Create a response with base64 content
    entry = har_data["log"]["entries"][0]
    entry["response"]["content"]["text"] = json.dumps({
        "base64_content": "SGVsbG8gd29ybGQ="  # "Hello world" in base64
    })
    
    # Sanitize the entry
    s._sanitise_entry(entry)
    
    # Check that base64 content is not redacted
    content = json.loads(entry["response"]["content"]["text"])
    assert content["base64_content"] == "SGVsbG8gd29ybGQ="

# --- Test excluded domains ---
def test_excluded_domains():
    """Test that excluded domains are not sanitized"""
    config = {
        "excluded_domains": ["example.com", "test.org"]
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Sanitize the entry
    entry = har_data["log"]["entries"][0]
    original_url = entry["request"]["url"]
    original_headers = copy.deepcopy(entry["request"]["headers"])
    
    s._sanitise_entry(entry)
    
    # Check that the entry was not sanitized
    assert entry["request"]["url"] == original_url
    assert entry["request"]["headers"] == original_headers

# --- Test content types to sanitize ---
def test_content_types_to_sanitize():
    """Test that only specified content types are sanitized"""
    config = {
        "content_types_to_sanitise": ["application/json"]
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Create a response with different content types
    entry1 = har_data["log"]["entries"][0]
    entry1["response"]["content"]["mimeType"] = "application/json"
    entry1["response"]["content"]["text"] = json.dumps({
        "email": "test@example.com"
    })
    
    # Add a second entry with a different content type
    entry2 = copy.deepcopy(entry1)
    entry2["response"]["content"]["mimeType"] = "text/plain"
    entry2["response"]["content"]["text"] = "Email: test@example.com"
    har_data["log"]["entries"].append(entry2)
    
    # Sanitize the entries
    for entry in har_data["log"]["entries"]:
        s._sanitise_entry(entry)
    
    # Check that only JSON content was sanitized
    content1 = json.loads(har_data["log"]["entries"][0]["response"]["content"]["text"])
    assert content1["email"].startswith("[REDACTED-")
    
    # Plain text content should not be sanitized
    assert har_data["log"]["entries"][1]["response"]["content"]["text"] == "Email: test@example.com"

# --- Test sanitization options ---
def test_sanitization_options():
    """Test that sanitization options control what types of data are sanitized"""
    config = {
        "sanitisation_options": {
            "email_addresses": True,
            "credit_cards": False,
            "phone_numbers": True,
            "guid_uuid": False
        }
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Create a response with different types of sensitive data
    entry = har_data["log"]["entries"][0]
    entry["response"]["content"]["text"] = json.dumps({
        "email": "test@example.com",
        "credit_card": "4111 1111 1111 1111",
        "phone": "+1 (555) 123-4567",
        "guid": "123e4567-e89b-12d3-a456-426614174000"
    })
    
    # Sanitize the entry
    s._sanitise_entry(entry)
    
    # Debug print
    print("\nContent after sanitization:", entry["response"]["content"]["text"])
    
    # Check that only enabled data types were sanitized
    content = json.loads(entry["response"]["content"]["text"])
    assert content["email"].startswith("[REDACTED-")  # Email should be redacted
    assert content["credit_card"] == "4111 1111 1111 1111"  # Credit card should not be redacted
    assert content["phone"].startswith("[REDACTED-")  # Phone should be redacted
    assert content["guid"] == "123e4567-e89b-12d3-a456-426614174000"  # GUID should not be redacted

# --- Test log level configuration ---
def test_log_level_configuration():
    """Test that log level can be configured"""
    import logging
    
    # Test debug level
    config = {
        "log_level": "debug"
    }
    s = HARSanitiser(config=config)
    assert s.logger.level == logging.DEBUG
    
    # Test info level
    config = {
        "log_level": "info"
    }
    s = HARSanitiser(config=config)
    assert s.logger.level == logging.INFO
    
    # Test warning level
    config = {
        "log_level": "warning"
    }
    s = HARSanitiser(config=config)
    assert s.logger.level == logging.WARNING
    
    # Test error level
    config = {
        "log_level": "error"
    }
    s = HARSanitiser(config=config)
    assert s.logger.level == logging.ERROR
    
    # Test invalid level (should default to INFO)
    config = {
        "log_level": "invalid"
    }
    s = HARSanitiser(config=config)
    assert s.logger.level == logging.INFO

# --- Test combined configuration options ---
def test_combined_configuration():
    """Test multiple configuration options together"""
    config = {
        "sensitive_headers": ["x-custom-header"],
        "sensitive_params": ["user"],
        "remove_tracking_params": True,
        "tracking_params": ["utm_"],
        "redact_base64_content": True,
        "sanitisation_options": {
            "email_addresses": True,
            "credit_cards": True,
            "phone_numbers": False,
            "guid_uuid": False
        }
    }
    
    s = HARSanitiser(config=config)
    har_data = copy.deepcopy(sample_har_entry)
    
    # Add additional data to test
    entry = har_data["log"]["entries"][0]
    entry["response"]["content"]["text"] = json.dumps({
        "email": "test@example.com",
        "credit_card": "4111 1111 1111 1111",
        "phone": "+1 (555) 123-4567",
        "guid": "123e4567-e89b-12d3-a456-426614174000",
        "base64_content": "SGVsbG8gd29ybGQ="
    })
    
    # Sanitize the entry
    s._sanitise_entry(entry)
    
    # Check URL sanitization
    url = entry["request"]["url"]
    assert "token=[REDACTED-" in url  # Standard sensitive param
    assert "user=[REDACTED-" in url  # Custom sensitive param
    assert "utm_source" not in url  # Tracking param removed
    
    # Check header sanitization
    headers = entry["request"]["headers"]
    custom_header = next(h for h in headers if h["name"] == "X-Custom-Header")
    assert custom_header["value"].startswith("[REDACTED-")  # Custom header redacted
    
    # Check content sanitization
    content = json.loads(entry["response"]["content"]["text"])
    assert content["email"].startswith("[REDACTED-")  # Email redacted
    assert content["credit_card"].startswith("[REDACTED-")  # Credit card redacted
    assert content["phone"] == "+1 (555) 123-4567"  # Phone not redacted
    assert content["guid"] == "123e4567-e89b-12d3-a456-426614174000"  # GUID not redacted
    assert content["base64_content"] == "[BASE64-CONTENT-REMOVED]"  # Base64 content redacted