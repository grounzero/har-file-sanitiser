"""
HAR File Sanitiser - A tool for sanitising HAR files to safely prepare browser logs for sharing.
"""

from .core import HARSanitiser
from .utils import read_har_file, write_har_file

__version__ = "1.0.0"