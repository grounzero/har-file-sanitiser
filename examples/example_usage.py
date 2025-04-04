#!/usr/bin/env python
"""
Example usage of the HAR File Sanitiser as a library.
"""

import json
import os
from har_sanitiser import HARSanitiser, read_har_file, write_har_file

def example_basic_usage():
    """Basic usage example"""
    print("=== Basic Usage Example ===")
    
    # Initialize the sanitiser
    sanitiser = HARSanitiser()
    
    # Load a HAR file
    import os
    input_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.har")
    print(f"Loading HAR file: {input_file}")
    har_data = read_har_file(input_file)
    
    # Sanitise the HAR data
    print("Sanitising HAR data...")
    sanitised_har = sanitiser.sanitise(har_data)
    
    # Save the sanitised HAR file
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "sanitised_basic.har")
    print(f"Saving sanitised HAR file: {output_file}")
    write_har_file(output_file, sanitised_har)
    
    print(f"Done! Sanitised HAR file saved to {output_file}")
    print()

def example_with_custom_config():
    """Example with custom configuration"""
    print("=== Custom Configuration Example ===")
    
    # Define custom configuration
    config = {
        "log_level": "info",
        "sensitive_headers": ["x-custom-header", "x-internal-id"],
        "sensitive_params": ["account", "user_id"],
        "tracking_params": ["utm_source", "utm_medium", "utm_campaign"],
        "remove_tracking_params": True,
        "redact_base64_content": True,
        "excluded_domains": ["trusted-domain.com"],
        "content_types_to_sanitise": [
            "application/json", 
            "application/x-www-form-urlencoded", 
            "text/plain", 
            "text/html"
        ],
        "sanitisation_options": {
            "email_addresses": True,
            "phone_numbers": True,
            "credit_cards": True,
            "guid_uuid": True,
            "jwt_tokens": True,
            "ip_addresses": True
        }
    }
    
    # Initialize the sanitiser with custom configuration
    sanitiser = HARSanitiser(config=config)
    
    # Load a HAR file
    import os
    input_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.har")
    print(f"Loading HAR file: {input_file}")
    har_data = read_har_file(input_file)
    
    # Sanitise the HAR data
    print("Sanitising HAR data with custom configuration...")
    sanitised_har = sanitiser.sanitise(har_data)
    
    # Save the sanitised HAR file
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "sanitised_custom.har")
    print(f"Saving sanitised HAR file: {output_file}")
    write_har_file(output_file, sanitised_har)
    
    print(f"Done! Sanitised HAR file saved to {output_file}")
    print()

def example_streaming_api():
    """Example using the streaming API for large files"""
    print("=== Streaming API Example ===")
    
    # Initialize the sanitiser
    sanitiser = HARSanitiser()
    
    # Define input and output files
    import os
    input_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample.har")
    output_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output", "sanitised_streaming.har")
    
    print(f"Sanitising HAR file using streaming API: {input_file}")
    
    # Use the streaming API
    duration = sanitiser.sanitise_har_streaming(
        input_file=input_file,
        output_file=output_file,
        use_parallel=True
    )
    
    print(f"Done! Sanitised HAR file saved to {output_file}")
    print(f"Time taken: {duration:.2f} seconds")
    print(f"Total entries processed: {sanitiser.metrics['total_entries']}")
    print(f"Entries skipped: {sanitiser.metrics['skipped_entries']}")
    
    # Display sensitive data metrics
    total_sensitive = sum(sanitiser.metrics['sensitive_data_found'].values())
    print(f"Sensitive data found: {total_sensitive} instances")
    
    # Only show detailed metrics if sensitive data was found
    if total_sensitive > 0:
        print("  Breakdown by type:")
        for data_type, count in sanitiser.metrics["sensitive_data_found"].items():
            if count > 0:
                print(f"    - {data_type}: {count}")
    print()

if __name__ == "__main__":
    # Create output directory if it doesn't exist
    os.makedirs("output", exist_ok=True)
    
    # Change to output directory
    os.chdir("output")
    
    # Run examples
    example_basic_usage()
    example_with_custom_config()
    example_streaming_api()
    
    print("All examples completed successfully!")