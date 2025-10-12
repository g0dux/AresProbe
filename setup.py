"""
AresProbe Setup Script
Installation and distribution configuration
"""

from setuptools import setup, find_packages
import os

# Read the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="aresprobe",
    version="1.0.0",
    author="AresProbe Team",
    author_email="team@aresprobe.com",
    description="Advanced Web Security Testing Framework - More Powerful Than Burp Suite + SQLMap",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/aresprobe/aresprobe",
    project_urls={
        "Bug Tracker": "https://github.com/aresprobe/aresprobe/issues",
        "Documentation": "https://github.com/aresprobe/aresprobe/wiki",
        "Source Code": "https://github.com/aresprobe/aresprobe",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "myst-parser>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "aresprobe=main:main",
        ],
    },
    keywords=[
        "security",
        "penetration-testing",
        "web-security",
        "sql-injection",
        "xss",
        "vulnerability-scanner",
        "proxy",
        "burp-suite",
        "sqlmap",
        "cybersecurity",
        "ethical-hacking",
    ],
    include_package_data=True,
    package_data={
        "aresprobe": [
            "plugins/examples/*.py",
            "*.json",
            "*.yaml",
            "*.yml",
        ],
    },
    zip_safe=False,
)
