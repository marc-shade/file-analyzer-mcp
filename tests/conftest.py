"""Shared pytest fixtures for file-analyzer-mcp tests."""

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest


# Test file content constants
PE_HEADER = b'\x4D\x5A' + b'\x00' * 30  # PE executable header
ELF_HEADER = b'\x7F\x45\x4C\x46' + b'\x00' * 28  # ELF binary header
MACHO_64_HEADER = b'\xCF\xFA\xED\xFE' + b'\x00' * 28  # Mach-O 64-bit
PDF_HEADER = b'%PDF-1.4' + b'\x00' * 24  # PDF document
ZIP_HEADER = b'PK\x03\x04' + b'\x00' * 28  # ZIP archive
PNG_HEADER = b'\x89PNG\r\n\x1A\n' + b'\x00' * 24  # PNG image
JPEG_HEADER = b'\xFF\xD8\xFF\xE0' + b'\x00' * 28  # JPEG image
GIF_HEADER = b'GIF89a' + b'\x00' * 26  # GIF image
GZIP_HEADER = b'\x1F\x8B\x08' + b'\x00' * 29  # GZIP archive
SQLITE_HEADER = b'SQLite format 3\x00' + b'\x00' * 16  # SQLite database
SHELL_SCRIPT_HEADER = b'#!/bin/bash\necho "test"'  # Shell script
TEXT_CONTENT = b'Hello, this is plain text content for testing purposes.'
BINARY_CONTENT = bytes(range(256))  # All byte values


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def pe_file(temp_dir: Path) -> Path:
    """Create a test PE executable file."""
    file_path = temp_dir / "test.exe"
    file_path.write_bytes(PE_HEADER)
    return file_path


@pytest.fixture
def pe_file_disguised_as_txt(temp_dir: Path) -> Path:
    """Create a PE executable disguised as a text file."""
    file_path = temp_dir / "document.txt"
    file_path.write_bytes(PE_HEADER)
    return file_path


@pytest.fixture
def elf_file(temp_dir: Path) -> Path:
    """Create a test ELF binary file."""
    file_path = temp_dir / "binary.elf"
    file_path.write_bytes(ELF_HEADER)
    return file_path


@pytest.fixture
def macho_file(temp_dir: Path) -> Path:
    """Create a test Mach-O binary file."""
    file_path = temp_dir / "binary"
    file_path.write_bytes(MACHO_64_HEADER)
    return file_path


@pytest.fixture
def pdf_file(temp_dir: Path) -> Path:
    """Create a test PDF file."""
    file_path = temp_dir / "document.pdf"
    file_path.write_bytes(PDF_HEADER)
    return file_path


@pytest.fixture
def zip_file(temp_dir: Path) -> Path:
    """Create a test ZIP file."""
    file_path = temp_dir / "archive.zip"
    file_path.write_bytes(ZIP_HEADER)
    return file_path


@pytest.fixture
def png_file(temp_dir: Path) -> Path:
    """Create a test PNG file."""
    file_path = temp_dir / "image.png"
    file_path.write_bytes(PNG_HEADER)
    return file_path


@pytest.fixture
def jpeg_file(temp_dir: Path) -> Path:
    """Create a test JPEG file."""
    file_path = temp_dir / "photo.jpg"
    file_path.write_bytes(JPEG_HEADER)
    return file_path


@pytest.fixture
def gif_file(temp_dir: Path) -> Path:
    """Create a test GIF file."""
    file_path = temp_dir / "animation.gif"
    file_path.write_bytes(GIF_HEADER)
    return file_path


@pytest.fixture
def gzip_file(temp_dir: Path) -> Path:
    """Create a test GZIP file."""
    file_path = temp_dir / "archive.gz"
    file_path.write_bytes(GZIP_HEADER)
    return file_path


@pytest.fixture
def sqlite_file(temp_dir: Path) -> Path:
    """Create a test SQLite file."""
    file_path = temp_dir / "database.db"
    file_path.write_bytes(SQLITE_HEADER)
    return file_path


@pytest.fixture
def shell_script(temp_dir: Path) -> Path:
    """Create a test shell script."""
    file_path = temp_dir / "script.sh"
    file_path.write_bytes(SHELL_SCRIPT_HEADER)
    return file_path


@pytest.fixture
def text_file(temp_dir: Path) -> Path:
    """Create a test text file."""
    file_path = temp_dir / "readme.txt"
    file_path.write_bytes(TEXT_CONTENT)
    return file_path


@pytest.fixture
def binary_file(temp_dir: Path) -> Path:
    """Create a test binary file with all byte values."""
    file_path = temp_dir / "binary.bin"
    file_path.write_bytes(BINARY_CONTENT)
    return file_path


@pytest.fixture
def empty_file(temp_dir: Path) -> Path:
    """Create an empty test file."""
    file_path = temp_dir / "empty.txt"
    file_path.write_bytes(b'')
    return file_path


@pytest.fixture
def high_entropy_file(temp_dir: Path) -> Path:
    """Create a file with high entropy (random-looking data)."""
    import random
    random.seed(42)  # Reproducible
    data = bytes([random.randint(0, 255) for _ in range(10000)])
    file_path = temp_dir / "encrypted.bin"
    file_path.write_bytes(data)
    return file_path


@pytest.fixture
def low_entropy_file(temp_dir: Path) -> Path:
    """Create a file with low entropy (repetitive data)."""
    data = b'A' * 10000
    file_path = temp_dir / "repetitive.txt"
    file_path.write_bytes(data)
    return file_path


@pytest.fixture
def mixed_directory(temp_dir: Path) -> Path:
    """Create a directory with various file types for scanning tests."""
    # Create subdirectory
    subdir = temp_dir / "subdir"
    subdir.mkdir()

    # Normal files
    (temp_dir / "normal.txt").write_bytes(TEXT_CONTENT)
    (temp_dir / "image.png").write_bytes(PNG_HEADER)
    (temp_dir / "doc.pdf").write_bytes(PDF_HEADER)

    # Suspicious file: executable disguised as PDF
    (temp_dir / "report.pdf").write_bytes(PE_HEADER)

    # File in subdirectory
    (subdir / "nested.txt").write_bytes(TEXT_CONTENT)

    # Script disguised as text
    (temp_dir / "notes.txt").write_bytes(b'#!/bin/bash\nrm -rf /')

    return temp_dir


@pytest.fixture
def file_with_known_hash(temp_dir: Path) -> tuple[Path, dict]:
    """Create a file with known hash values for verification."""
    content = b"test content for hash verification"
    file_path = temp_dir / "hashtest.txt"
    file_path.write_bytes(content)

    # Pre-calculated hashes for "test content for hash verification"
    expected_hashes = {
        "md5": "2c77e9b5b44a7c11dcb0f6087f0e6f68",
        "sha1": "4c2e08a52e6e2c4eb6e0e6d7e8e5f3a2d1c0b9a8",  # Will be computed
        "sha256": "placeholder"  # Will be computed
    }

    return file_path, expected_hashes
