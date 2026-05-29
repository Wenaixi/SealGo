"""Setup for SealGo Python package (bundles CLI binary)."""

import os
import platform
import sys
from setuptools import setup


def _binary_name():
    """Return the platform-specific CLI binary filename."""
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Linux":
        if machine in ("x86_64", "amd64"):
            return "SealGo-linux-amd64"
        elif machine in ("aarch64", "arm64"):
            return "SealGo-linux-arm64"
        elif machine.startswith("arm"):
            return "SealGo-linux-arm"
    elif system == "Darwin":
        if machine == "arm64":
            return "SealGo-darwin-arm64"
        else:
            return "SealGo-darwin-amd64"
    elif system == "Windows":
        return "SealGo-windows-amd64.exe"

    raise OSError(f"unsupported platform: {system} {machine}")


setup(
    name="sealgo",
    version="0.1.1",
    description="XChaCha20-Poly1305 streaming encryption for Python (bundles CLI)",
    long_description=open(os.path.join(os.path.dirname(__file__), "README.md"), encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/Wenaixi/SealGo",
    license="MIT",
    packages=["sealgo"],
    package_dir={"": "src"},
    package_data={"sealgo": [_binary_name()]},
    include_package_data=True,
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
    ],
)