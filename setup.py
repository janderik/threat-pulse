from setuptools import setup, find_packages

setup(
    name="threatpulse",
    version="0.1.0",
    description="ThreatPulse - Open Source Threat Intelligence Platform",
    author="ThreatPulse",
    python_requires=">=3.11",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "fastapi>=0.115.0",
        "uvicorn[standard]>=0.34.0",
        "sqlalchemy>=2.0.0",
        "psycopg2-binary>=2.9.0",
        "httpx>=0.28.0",
        "pydantic>=2.10.0",
        "pydantic-settings>=2.7.0",
        "python-dateutil>=2.9.0",
        "pyyaml>=6.0.0",
        "aiofiles>=24.1.0",
        "apscheduler>=3.10.0",
    ],
    extras_require={
        "dev": [
            "ruff>=0.8.0",
            "pytest>=8.0.0",
            "pytest-asyncio>=0.24.0",
            "pytest-cov>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "threatpulse=src.main:main",
        ],
    },
)
