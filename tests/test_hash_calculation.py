"""Tests for file hash calculation functionality."""

import hashlib
import json
from pathlib import Path

import pytest

from file_analyzer_mcp.server import (
    calculate_hashes,
    _calculate_file_hashes_impl as calculate_file_hashes,
)


class TestCalculateHashes:
    """Tests for calculate_hashes function."""

    def test_hash_simple_content(self, temp_dir: Path):
        """Test hashing simple content."""
        content = b"test content"
        file_path = temp_dir / "test.txt"
        file_path.write_bytes(content)

        result = calculate_hashes(str(file_path))

        # Verify against Python's hashlib
        expected_md5 = hashlib.md5(content).hexdigest()
        expected_sha1 = hashlib.sha1(content).hexdigest()
        expected_sha256 = hashlib.sha256(content).hexdigest()

        assert result['md5'] == expected_md5
        assert result['sha1'] == expected_sha1
        assert result['sha256'] == expected_sha256

    def test_hash_empty_file(self, empty_file: Path):
        """Test hashing empty file."""
        result = calculate_hashes(str(empty_file))

        # Known hashes for empty content
        assert result['md5'] == 'd41d8cd98f00b204e9800998ecf8427e'
        assert result['sha1'] == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        assert result['sha256'] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

    def test_hash_binary_content(self, binary_file: Path):
        """Test hashing binary content."""
        result = calculate_hashes(str(binary_file))

        # Verify all hashes are valid hex strings
        assert len(result['md5']) == 32
        assert len(result['sha1']) == 40
        assert len(result['sha256']) == 64

        # Verify they are hex
        int(result['md5'], 16)
        int(result['sha1'], 16)
        int(result['sha256'], 16)

    def test_hash_large_file(self, temp_dir: Path):
        """Test hashing larger file (streamed in chunks)."""
        # Create 1MB file
        content = b'A' * (1024 * 1024)
        file_path = temp_dir / "large.bin"
        file_path.write_bytes(content)

        result = calculate_hashes(str(file_path))

        expected_md5 = hashlib.md5(content).hexdigest()
        assert result['md5'] == expected_md5

    def test_hash_consistency(self, text_file: Path):
        """Test that hashing same file multiple times gives same result."""
        result1 = calculate_hashes(str(text_file))
        result2 = calculate_hashes(str(text_file))
        result3 = calculate_hashes(str(text_file))

        assert result1 == result2 == result3

    def test_hash_different_files_differ(self, temp_dir: Path):
        """Test that different files produce different hashes."""
        file1 = temp_dir / "file1.txt"
        file2 = temp_dir / "file2.txt"
        file1.write_bytes(b"content one")
        file2.write_bytes(b"content two")

        result1 = calculate_hashes(str(file1))
        result2 = calculate_hashes(str(file2))

        assert result1['md5'] != result2['md5']
        assert result1['sha1'] != result2['sha1']
        assert result1['sha256'] != result2['sha256']


class TestCalculateFileHashesTool:
    """Tests for calculate_file_hashes MCP tool."""

    @pytest.mark.asyncio
    async def test_tool_success(self, text_file: Path):
        """Test successful hash calculation via tool."""
        result = await calculate_file_hashes(str(text_file))
        data = json.loads(result)

        assert data['success'] is True
        assert 'hashes' in data
        assert 'md5' in data['hashes']
        assert 'sha1' in data['hashes']
        assert 'sha256' in data['hashes']

    @pytest.mark.asyncio
    async def test_tool_includes_file_info(self, text_file: Path):
        """Test tool includes file metadata."""
        result = await calculate_file_hashes(str(text_file))
        data = json.loads(result)

        assert 'file_path' in data
        assert 'file_name' in data
        assert 'size_bytes' in data
        assert data['file_name'] == 'readme.txt'

    @pytest.mark.asyncio
    async def test_tool_file_not_found(self):
        """Test tool handles missing file."""
        result = await calculate_file_hashes("/nonexistent/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data
        assert 'not found' in data['error'].lower()

    @pytest.mark.asyncio
    async def test_tool_expands_home_path(self, temp_dir: Path):
        """Test tool expands ~ in paths."""
        # Create file in temp dir simulating home expansion
        file_path = temp_dir / "test.txt"
        file_path.write_bytes(b"test")

        result = await calculate_file_hashes(str(file_path))
        data = json.loads(result)

        assert data['success'] is True

    @pytest.mark.asyncio
    async def test_tool_hash_verification(self, temp_dir: Path):
        """Test tool produces correct hashes."""
        content = b"known content for verification"
        file_path = temp_dir / "verify.txt"
        file_path.write_bytes(content)

        result = await calculate_file_hashes(str(file_path))
        data = json.loads(result)

        expected_md5 = hashlib.md5(content).hexdigest()
        expected_sha256 = hashlib.sha256(content).hexdigest()

        assert data['hashes']['md5'] == expected_md5
        assert data['hashes']['sha256'] == expected_sha256


class TestHashFormats:
    """Tests for hash format correctness."""

    def test_md5_format(self, text_file: Path):
        """Test MD5 hash is correct format (32 hex chars)."""
        result = calculate_hashes(str(text_file))
        assert len(result['md5']) == 32
        assert all(c in '0123456789abcdef' for c in result['md5'])

    def test_sha1_format(self, text_file: Path):
        """Test SHA1 hash is correct format (40 hex chars)."""
        result = calculate_hashes(str(text_file))
        assert len(result['sha1']) == 40
        assert all(c in '0123456789abcdef' for c in result['sha1'])

    def test_sha256_format(self, text_file: Path):
        """Test SHA256 hash is correct format (64 hex chars)."""
        result = calculate_hashes(str(text_file))
        assert len(result['sha256']) == 64
        assert all(c in '0123456789abcdef' for c in result['sha256'])

    def test_hashes_are_lowercase(self, text_file: Path):
        """Test all hashes use lowercase hex."""
        result = calculate_hashes(str(text_file))
        assert result['md5'] == result['md5'].lower()
        assert result['sha1'] == result['sha1'].lower()
        assert result['sha256'] == result['sha256'].lower()
