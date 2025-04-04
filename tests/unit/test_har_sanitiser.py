import json
from copy import deepcopy
from har_sanitiser_improved import HARSanitiser 

# --- Sample HAR data for integration test ---
sample_har_entry = {
    "log": {
        "version": "1.2",
        "creator": {"name": "test", "version": "1.0"},
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://example.com/api?token=abcd1234&user=test",
                    "headers": [{"name": "Authorization", "value": "Bearer abcdef"}]
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
                            "additional_cards": [
                                "5555555555554444",     # Mastercard
                                "34343434343434",       # American Express
                                "6011000400000000",     # Discover
                                "3528000700000000"      # JCB
                            ]
                        })
                    }
                }
            }
        ]
    }
}

# --- Unit Tests ---

def test_hash_value_consistency():
    s = HARSanitiser()
    assert s._hash_value("abc123") == s._hash_value("abc123")

def test_base64_detection():
    s = HARSanitiser()
    assert s._is_base64("SGVsbG8gd29ybGQ=") is True
    assert s._is_base64("not_base64") is False
def test_credit_card_luhn_check():
    s = HARSanitiser()
    # Test the original test cases
    assert s._luhn_check("4111111111111111") is True
    assert s._luhn_check("4111111111111121") is False
    
    # Test with the provided credit card numbers
    # Airplus
    assert s._luhn_check("122000000000003") is True
    # American Express
    assert s._luhn_check("34343434343434") is True
    # Cartebleue
    assert s._luhn_check("5555555555554444") is True
    # Dankort
    assert s._luhn_check("5019717010103742") is True
    # Diners
    assert s._luhn_check("36700102000000") is True
    assert s._luhn_check("36148900647913") is True
    # Discover card
    assert s._luhn_check("6011000400000000") is True
    # JCB
    assert s._luhn_check("3528000700000000") is True
    # Laser
    assert s._luhn_check("630495060000000000") is True
    assert s._luhn_check("630490017740292441") is True
    # Maestro
    assert s._luhn_check("6759649826438453") is True
    assert s._luhn_check("6799990100000000019") is True
    # Mastercard
    assert s._luhn_check("5454545454545454") is True
    # Visa
    assert s._luhn_check("4444333322221111") is True
    assert s._luhn_check("4911830000000") is True
    assert s._luhn_check("4917610000000000") is True
    # Visa Debit
    assert s._luhn_check("4462030000000000") is True
    assert s._luhn_check("4917610000000000003") is True
    # Visa Electron
    assert s._luhn_check("4917300800000000") is True
    # Visa Purchasing
    assert s._luhn_check("4484070000000000") is True
    assert s._luhn_check("4111111111111121") is False

def test_redact_credit_card_text():
    s = HARSanitiser()
    # Test with various credit card formats
    test_cases = [
        # Original test case
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        
        # Airplus
        "122000000000003",
        "1220-0000-0000-0003",
        
        # American Express
        "34343434343434",
        "3434-343434-3434",
        
        # Cartebleue/Mastercard
        "5555555555554444",
        "5555-5555-5555-4444",
        
        # Dankort
        "5019717010103742",
        "5019-7170-1010-3742",
        
        # Diners
        "36700102000000",
        "3670-010200-0000",
        "36148900647913",
        "3614-890064-7913",
        
        # Discover
        "6011000400000000",
        "6011-0004-0000-0000",
        
        # JCB
        "3528000700000000",
        "3528-0007-0000-0000",
        
        # Laser
        "630495060000000000",
        "6304-9506-0000-0000-00",
        "630490017740292441",
        "6304-9001-7740-2924-41",
        
        # Maestro
        "6759649826438453",
        "6759-6498-2643-8453",
        "6799990100000000019",
        "6799-9901-0000-0000-019",
        
        # Mastercard
        "5454545454545454",
        "5454-5454-5454-5454",
        
        # Visa
        "4444333322221111",
        "4444-3333-2222-1111",
        "4911830000000",
        "4911-8300-0000-0",
        "4917610000000000",
        "4917-6100-0000-0000",
        
        # Visa Electron
        "4917300800000000",
        "4917-3008-0000-0000"
    ]
    
    for card in test_cases:
        # Print debugging information
        print(f"\nTesting card: {card}")
        print(f"Matches pattern: {bool(s.patterns['credit_card'].search(card))}")
        clean_number = ''.join(c for c in card if c.isdigit())
        print(f"Clean number: {clean_number}")
        print(f"Passes Luhn check: {s._luhn_check(clean_number)}")
        
        redacted = s._maybe_redact_credit_card(card)
        print(f"Original: {card}")
        print(f"Redacted: {redacted}")
        assert "[REDACTED-credit_card]" in redacted

def test_sanitise_headers_redacts_sensitive():
    s = HARSanitiser()
    headers = [{"name": "Authorization", "value": "Bearer secret"}]
    # Make a copy of the headers for testing
    result = headers.copy()
    s._sanitise_headers(result)
    assert result[0]["value"].startswith("[REDACTED-")

def test_sanitise_query_params_redacts_token():
    s = HARSanitiser()
    url = "https://site.com/?token=12345&name=foo"
    redacted = s._sanitise_query_params(url)
    assert "token=" in redacted
    assert "[REDACTED-" in redacted

def test_sanitise_json_redacts_sensitive():
    s = HARSanitiser()
    # Test with various credit card types
    test_cases = [
        # Original test case
        "4111 1111 1111 1111",
        "4111-1111-1111-1111",
        
        # Airplus
        "122000000000003",
        "1220-0000-0000-0003",
        
        # American Express
        "34343434343434",
        "3434-343434-3434",
        
        # Cartebleue/Mastercard
        "5555555555554444",
        "5555-5555-5555-4444",
        
        # Dankort
        "5019717010103742",
        "5019-7170-1010-3742",
        
        # Diners
        "36700102000000",
        "3670-010200-0000",
        "36148900647913",
        "3614-890064-7913",
        
        # Discover
        "6011000400000000",
        "6011-0004-0000-0000",
        
        # JCB
        "3528000700000000",
        "3528-0007-0000-0000",
        
        # Laser
        "630495060000000000",
        "6304-9506-0000-0000-00",
        "630490017740292441",
        "6304-9001-7740-2924-41",
        
        # Maestro
        "6759649826438453",
        "6759-6498-2643-8453",
        "6799990100000000019",
        "6799-9901-0000-0000-019",
        
        # Mastercard
        "5454545454545454",
        "5454-5454-5454-5454",
        
        # Visa
        "4444333322221111",
        "4444-3333-2222-1111",
        "4911830000000",
        "4911-8300-0000-0",
        "4917610000000000",
        "4917-6100-0000-0000",
        
        # Visa Electron
        "4917300800000000",
        "4917-3008-0000-0000"
    ]
    
    for card in test_cases:
        # Print debugging information
        print(f"\nTesting card in JSON: {card}")
        print(f"Matches pattern: {bool(s.patterns['credit_card'].search(card))}")
        clean_number = ''.join(c for c in card if c.isdigit())
        print(f"Clean number: {clean_number}")
        print(f"Passes Luhn check: {s._luhn_check(clean_number)}")
        
        data = {
            "email": "someone@example.com",
            "credit_card": card
        }
        redacted = s._sanitise_json(deepcopy(data))
        print(f"Original: {data}")
        print(f"Redacted: {redacted}")
        assert redacted["email"].startswith("[REDACTED-email")
        assert redacted["credit_card"].startswith("[REDACTED-credit_card")

def test_sanitise_har_full_flow():
    s = HARSanitiser()
    # Make a deep copy of the sample HAR entry
    har_data = deepcopy(sample_har_entry)
    # Sanitize the entry directly
    entry = har_data["log"]["entries"][0]
    s._sanitise_entry(entry)
    
    # Check that sensitive information has been redacted
    assert "[REDACTED-" in entry["request"]["url"]
    assert "[REDACTED-" in entry["request"]["headers"][0]["value"]
    assert "[REDACTED-" in entry["response"]["headers"][0]["value"]
    assert "[REDACTED-email" in entry["response"]["content"]["text"]
    assert "[REDACTED-credit_card" in entry["response"]["content"]["text"]

# --- Additional Tests for New Functionality ---

def test_default_output_filename():
    """Test that default output filename is correctly generated"""
    import os
    import sys
    from io import StringIO
    
    # Capture stdout to check the output message
    old_stdout = sys.stdout
    sys.stdout = mystdout = StringIO()
    
    try:
        # Mock sys.argv
        old_argv = sys.argv
        sys.argv = ['har_sanitiser.py', 'test.har']
        
        # Import the main function
        from har_sanitiser import main
        
        # Run the main function with mock arguments
        try:
            main()
        except SystemExit:
            pass  # Ignore SystemExit
        
        # Check that the default output filename was generated correctly
        output = mystdout.getvalue()
        assert "No output file specified, using default: test_sanitised.har" in output
    finally:
        # Restore stdout and argv
        sys.stdout = old_stdout
        sys.argv = old_argv

def test_streaming_processing():
    """Test that streaming processing is used for large files"""
    import os
    import tempfile
    import json
    
    # Create a temporary large HAR file
    temp_file = tempfile.mktemp(suffix='.har')
    with open(temp_file, 'w') as f:
        # Create a minimal HAR structure
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "test", "version": "1.0"},
                "entries": []
            }
        }
        
        # Add enough entries to make the file large
        for i in range(100):
            entry = {
                "request": {
                    "method": "GET",
                    "url": f"https://example.com/api?token=token{i}&user=test{i}",
                    "headers": [{"name": "Authorization", "value": f"Bearer token{i}"}]
                },
                "response": {
                    "status": 200,
                    "headers": [{"name": "Set-Cookie", "value": f"sessionid=xyz{i}"}],
                    "content": {
                        "mimeType": "application/json",
                        "text": json.dumps({
                            "email": f"test{i}@example.com",
                            "credit_card": "4111 1111 1111 1111"
                        })
                    }
                }
            }
            har_data["log"]["entries"].append(entry)
        
        # Write the HAR data to the file
        json.dump(har_data, f)
        
    try:
        # Set file path
        file_path = temp_file
        # Import the improved sanitizer
        from har_sanitiser_improved import HARSanitiser
        
        # Create a sanitizer instance
        s = HARSanitiser()
        
        # Create a temporary output file
        output_file = f"{file_path}_sanitised.har"
        
        # Sanitize the HAR file
        s.sanitise_har_streaming(file_path, output_file)
        
        # Check that the output file exists and contains sanitized data
        assert os.path.exists(output_file)
        
        # Read the sanitized HAR file as text first to handle any formatting issues
        with open(output_file, 'r') as f:
            content = f.read()
            
        # Check that sensitive information has been redacted in the raw content
        assert "[REDACTED-" in content
        assert "Bearer token" not in content
        assert "sessionid=xyz" not in content
        assert "@example.com" not in content
        assert "4111 1111 1111 1111" not in content
    finally:
        # Clean up temporary files
        os.unlink(file_path)
        if os.path.exists(output_file):
            os.unlink(output_file)
