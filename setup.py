from setuptools import setup
from pathlib import Path

long_description = Path("README.md").read_text(encoding="utf-8")

setup(
    name="starker-scanner",
    version="5.0.1",
    author="STARKER Consulting",
    author_email="contact@starkerconsulting.com",
    description="Enterprise defensive security scanner. Audits SSL, DNS, headers, ports, subdomains and more.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/YOUR_USERNAME/starker-scanner",
    py_modules=["scanner"],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "python-whois>=0.8.0",
        "dnspython>=2.4.0",
    ],
    entry_points={
        "console_scripts": [
            "starker-scan=scanner:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    keywords=[
        "security", "scanner", "audit", "ssl", "dns", "headers",
        "ports", "subdomains", "waf", "tls", "infosec", "cybersecurity",
    ],
    project_urls={
        "Bug Reports": "https://github.com/YOUR_USERNAME/starker-scanner/issues",
        "Source": "https://github.com/YOUR_USERNAME/starker-scanner",
        "Documentation": "https://github.com/YOUR_USERNAME/starker-scanner#readme",
    },
)
