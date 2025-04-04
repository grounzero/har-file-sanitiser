"""
Command-line interface for HAR file sanitisation.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, Any, Optional

from .core import HARSanitiser
from .utils import read_har_file, write_har_file


def parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='Sanitise HAR files')
    parser.add_argument('input_file', help='Input HAR file path')
    parser.add_argument('output_file', nargs='?', help='Output HAR file path (optional, defaults to input_file_sanitised.har)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging (DEBUG level)')
    parser.add_argument('--config', help='Path to JSON configuration file')
    parser.add_argument('--no-parallel', action='store_true', help='Disable parallel processing (parallel processing is enabled by default)')
    parser.add_argument('--processes', type=int, help='Number of processes to use for parallel processing (default: number of CPU cores)')
    
    return parser.parse_args()


def load_config(config_path: str) -> Optional[Dict[str, Any]]:
    """
    Load configuration from a JSON file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Configuration dictionary or None if loading fails
    """
    try:
        with open(config_path, 'r') as config_file:
            return json.load(config_file)
    except Exception as e:
        logging.error(f"Failed to load configuration: {str(e)}")
        return None


def get_default_output_filename(input_file: str) -> str:
    """
    Generate a default output filename based on the input filename.
    
    Args:
        input_file: Input file path
        
    Returns:
        Default output file path
    """
    input_base = os.path.basename(input_file)
    input_name, input_ext = os.path.splitext(input_base)
    return f"{input_name}_sanitised{input_ext}"


def main() -> int:
    """
    Main entry point for the command-line interface.
    
    Returns:
        Exit code (0 for success, 1 for error)
    """
    args = parse_args()
    
    # If output_file is not specified, create a default one based on the input file name
    if not args.output_file:
        args.output_file = get_default_output_filename(args.input_file)
        print(f"No output file specified, using default: {args.output_file}")

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)

    try:
        # Load configuration if provided
        config = None
        if args.config:
            config = load_config(args.config)
            if config is None:
                return 1
            logger.info(f"Loaded configuration from {args.config}")
        
        # Read input HAR file
        logger.debug(f"Reading HAR file from {args.input_file}")
        har_data = read_har_file(args.input_file)
        
        # Create sanitiser and process HAR file
        logger.debug("Initializing HAR sanitiser")
        sanitiser = HARSanitiser(config=config)
        
        logger.info("Sanitising HAR file...")
        
        # Use streaming processing for better performance
        duration = sanitiser.sanitise_har_streaming(
            args.input_file,
            args.output_file,
            use_parallel=not args.no_parallel,
            num_processes=args.processes
        )
        
        # Calculate compression ratio
        compression_ratio = 1.0
        if sanitiser.metrics["input_size"] > 0:
            compression_ratio = sanitiser.metrics["output_size"] / sanitiser.metrics["input_size"]
        
        # Display results
        logger.info(f"Successfully sanitised HAR file from {args.input_file} to {args.output_file}")
        print(f"Successfully sanitised HAR file from {args.input_file} to {args.output_file}")
        print(f"Time taken: {duration:.2f} seconds")
        print(f"Total entries processed: {sanitiser.metrics['total_entries']}")
        print(f"Entries skipped: {sanitiser.metrics['skipped_entries']}")
        print(f"File size: {sanitiser.metrics['input_size']/1024:.2f}KB -> {sanitiser.metrics['output_size']/1024:.2f}KB (ratio: {compression_ratio:.2f})")
        
        # Display sensitive data metrics
        total_sensitive = sum(sanitiser.metrics['sensitive_data_found'].values())
        print(f"Sensitive data found: {total_sensitive} instances")
        
        # Only show detailed metrics if sensitive data was found
        if total_sensitive > 0:
            print("  Breakdown by type:")
            for data_type, count in sanitiser.metrics["sensitive_data_found"].items():
                if count > 0:
                    print(f"    - {data_type}: {count}")
                    
        return 0
    except Exception as e:
        logger.error(f"Error processing HAR file: {str(e)}", exc_info=args.verbose)
        print(f"Error processing HAR file: {str(e)}")
        return 1


if __name__ == '__main__':
    sys.exit(main())