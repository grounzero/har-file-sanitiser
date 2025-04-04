#!/usr/bin/env python
"""
Setup script for har-file-sanitiser.
This is kept for backward compatibility with older pip versions.
For modern Python packaging, see pyproject.toml.
"""

from setuptools import setup, find_packages

setup(
    name="har-file-sanitiser",
    version="1.0.0",
    description="A tool for sanitising HAR files to safely prepare browser logs for sharing",
    author="grounzero",
    url="https://github.com/grounzero/har-file-sanitiser",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "ijson>=3.1.4",
        "tqdm>=4.64.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    entry_points={
        "console_scripts": [
            "har-sanitiser=har_sanitiser.cli:main",
        ],
    },
)