"""
Utility functions for HAR file sanitisation.
"""

import json
import os
from typing import Dict, Any


def read_har_file(file_path: str) -> Dict[str, Any]:
    """
    Read HAR data from a file.

    Args:
        file_path: Path to the HAR file

    Returns:
        Dictionary containing HAR data
        
    Raises:
        FileNotFoundError: If the file does not exist
        json.JSONDecodeError: If the file is not valid JSON
    """
    with open(file_path, 'r') as f:
        return json.load(f)


def write_har_file(file_path: str, har_data: Dict[str, Any]) -> None:
    """
    Write HAR data to a file.

    Args:
        file_path: Path to write the HAR file
        har_data: HAR data to write
        
    Raises:
        PermissionError: If the file cannot be written
    """
    # Ensure the output directory exists
    output_dir = os.path.dirname(file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    with open(file_path, 'w') as f:
        json.dump(har_data, f, indent=2)


def format_duration(seconds: float) -> str:
    """
    Format a duration in seconds to a human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Human-readable duration string
    """
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    
    if hours > 0:
        return f"{int(hours)}h {int(minutes)}m {seconds:.2f}s"
    elif minutes > 0:
        return f"{int(minutes)}m {seconds:.2f}s"
    else:
        return f"{seconds:.2f}s"