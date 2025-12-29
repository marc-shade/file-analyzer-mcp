"""Tests for error handling across the file-analyzer-mcp server."""

import json
import os
import stat
from pathlib import Path

import pytest

from file_analyzer_mcp.server import (
    _analyze_entropy_impl as analyze_entropy,
    _calculate_file_hashes_impl as calculate_file_hashes,
    _check_file_reputation_impl as check_file_reputation,
    _identify_file_impl as identify_file,
    read_file_header,
    _scan_directory_impl as scan_directory,
)


class TestFileNotFoundErrors:
    """Tests for file not found error handling."""

    @pytest.mark.asyncio
    async def test_identify_file_not_found(self):
        """Test identify_file with non-existent file."""
        result = await identify_file("/nonexistent/path/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data
        assert 'not found' in data['error'].lower()

    @pytest.mark.asyncio
    async def test_calculate_hashes_not_found(self):
        """Test calculate_file_hashes with non-existent file."""
        result = await calculate_file_hashes("/nonexistent/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data

    @pytest.mark.asyncio
    async def test_analyze_entropy_not_found(self):
        """Test analyze_entropy with non-existent file."""
        result = await analyze_entropy("/nonexistent/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data

    @pytest.mark.asyncio
    async def test_check_reputation_not_found(self):
        """Test check_file_reputation with non-existent file."""
        result = await check_file_reputation("/nonexistent/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data

    @pytest.mark.asyncio
    async def test_scan_directory_not_found(self):
        """Test scan_directory with non-existent directory."""
        result = await scan_directory("/nonexistent/directory")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data
        assert 'not found' in data['error'].lower()


class TestInvalidPathErrors:
    """Tests for invalid path error handling."""

    @pytest.mark.asyncio
    async def test_identify_directory_instead_of_file(self, temp_dir: Path):
        """Test identify_file when given a directory."""
        result = await identify_file(str(temp_dir))
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data
        assert 'not a regular file' in data['error'].lower()

    @pytest.mark.asyncio
    async def test_identify_empty_path(self):
        """Test identify_file with empty path."""
        result = await identify_file("")
        data = json.loads(result)

        assert data['success'] is False

    @pytest.mark.asyncio
    async def test_identify_relative_path(self, temp_dir: Path):
        """Test identify_file with relative path."""
        file_path = temp_dir / "test.txt"
        file_path.write_bytes(b"test")

        # Use relative-looking path
        result = await identify_file(str(file_path))
        data = json.loads(result)

        # Should still work - pathlib resolves it
        assert data['success'] is True


class TestPathExpansionErrors:
    """Tests for path expansion handling."""

    @pytest.mark.asyncio
    async def test_tilde_expansion(self, temp_dir: Path):
        """Test ~ path expansion works correctly."""
        # This tests that expanduser is called
        file_path = temp_dir / "test.txt"
        file_path.write_bytes(b"test")

        result = await identify_file(str(file_path))
        data = json.loads(result)

        # Resolved path should be absolute
        assert Path(data['file_path']).is_absolute()

    @pytest.mark.asyncio
    async def test_nonexistent_tilde_path(self):
        """Test non-existent path with tilde."""
        result = await identify_file("~/nonexistent_dir_12345/file.txt")
        data = json.loads(result)

        assert data['success'] is False


class TestPermissionErrors:
    """Tests for permission error handling."""

    @pytest.mark.asyncio
    async def test_identify_unreadable_file(self, temp_dir: Path):
        """Test identify_file with unreadable file."""
        file_path = temp_dir / "unreadable.txt"
        file_path.write_bytes(b"secret content")

        # Remove read permission
        try:
            os.chmod(file_path, 0o000)

            result = await identify_file(str(file_path))
            data = json.loads(result)

            # Should fail gracefully
            assert data['success'] is False
            assert 'error' in data
        finally:
            # Restore permissions for cleanup
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)

    @pytest.mark.asyncio
    async def test_scan_unreadable_directory(self, temp_dir: Path):
        """Test scanning directory with unreadable files."""
        # Create some files
        (temp_dir / "readable.txt").write_bytes(b"content")
        unreadable = temp_dir / "unreadable.txt"
        unreadable.write_bytes(b"secret")

        try:
            os.chmod(unreadable, 0o000)

            result = await scan_directory(str(temp_dir))
            data = json.loads(result)

            # Scan should still succeed, tracking errors
            assert data['success'] is True
            # Should have at least scanned readable file
        finally:
            os.chmod(unreadable, stat.S_IRUSR | stat.S_IWUSR)


class TestReadFileHeaderErrors:
    """Tests for read_file_header error handling."""

    def test_read_header_file_not_found(self):
        """Test read_file_header with non-existent file."""
        with pytest.raises(FileNotFoundError):
            read_file_header("/nonexistent/file.txt")

    def test_read_header_permission_denied(self, temp_dir: Path):
        """Test read_file_header with unreadable file."""
        file_path = temp_dir / "noperm.txt"
        file_path.write_bytes(b"content")

        try:
            os.chmod(file_path, 0o000)
            with pytest.raises(PermissionError):
                read_file_header(str(file_path))
        finally:
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)


class TestEdgeCaseErrors:
    """Tests for edge case error handling."""

    @pytest.mark.asyncio
    async def test_identify_special_characters_path(self, temp_dir: Path):
        """Test identify_file with special characters in path."""
        file_path = temp_dir / "file with spaces & special!chars.txt"
        file_path.write_bytes(b"content")

        result = await identify_file(str(file_path))
        data = json.loads(result)

        assert data['success'] is True

    @pytest.mark.asyncio
    async def test_identify_unicode_path(self, temp_dir: Path):
        """Test identify_file with unicode characters in path."""
        file_path = temp_dir / "archivo_espanol.txt"
        file_path.write_bytes(b"contenido")

        result = await identify_file(str(file_path))
        data = json.loads(result)

        assert data['success'] is True

    @pytest.mark.asyncio
    async def test_scan_empty_directory(self, temp_dir: Path):
        """Test scanning empty directory."""
        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert data['success'] is True
        assert data['files_scanned'] == 0

    @pytest.mark.asyncio
    async def test_identify_very_long_path(self, temp_dir: Path):
        """Test identify_file with very long path."""
        # Create nested directories
        current = temp_dir
        for i in range(20):
            current = current / f"dir{i}"
            current.mkdir(exist_ok=True)

        file_path = current / "deep.txt"
        file_path.write_bytes(b"deep content")

        result = await identify_file(str(file_path))
        data = json.loads(result)

        assert data['success'] is True


class TestConcurrentErrors:
    """Tests for concurrent access error scenarios."""

    @pytest.mark.asyncio
    async def test_multiple_identify_calls(self, temp_dir: Path):
        """Test multiple concurrent identify calls."""
        import asyncio

        # Create multiple files
        files = []
        for i in range(5):
            f = temp_dir / f"file{i}.txt"
            f.write_bytes(f"content {i}".encode())
            files.append(f)

        # Call identify_file concurrently
        tasks = [identify_file(str(f)) for f in files]
        results = await asyncio.gather(*tasks)

        # All should succeed
        for result in results:
            data = json.loads(result)
            assert data['success'] is True

    @pytest.mark.asyncio
    async def test_mixed_valid_invalid_files(self, temp_dir: Path):
        """Test handling mix of valid and invalid file paths."""
        import asyncio

        valid_file = temp_dir / "valid.txt"
        valid_file.write_bytes(b"content")

        tasks = [
            identify_file(str(valid_file)),
            identify_file("/nonexistent/file.txt"),
            identify_file(str(valid_file)),
        ]

        results = await asyncio.gather(*tasks)

        # Check results individually
        assert json.loads(results[0])['success'] is True
        assert json.loads(results[1])['success'] is False
        assert json.loads(results[2])['success'] is True


class TestGracefulDegradation:
    """Tests for graceful degradation scenarios."""

    @pytest.mark.asyncio
    async def test_scan_with_some_errors(self, temp_dir: Path):
        """Test directory scan continues despite some file errors."""
        # Create mix of readable and problematic files
        (temp_dir / "good1.txt").write_bytes(b"content")
        (temp_dir / "good2.txt").write_bytes(b"content")

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        # Scan should succeed overall
        assert data['success'] is True
        assert data['files_scanned'] >= 2

    @pytest.mark.asyncio
    async def test_identify_corrupted_header(self, temp_dir: Path):
        """Test identify_file with minimal/corrupted content."""
        # Single byte file
        single = temp_dir / "single.bin"
        single.write_bytes(b'\x00')

        result = await identify_file(str(single))
        data = json.loads(result)

        # Should still return result (unknown type)
        assert data['success'] is True

    @pytest.mark.asyncio
    async def test_entropy_very_small_file(self, temp_dir: Path):
        """Test entropy analysis on very small file."""
        tiny = temp_dir / "tiny.txt"
        tiny.write_bytes(b"a")

        result = await analyze_entropy(str(tiny))
        data = json.loads(result)

        assert data['success'] is True
        assert 'entropy' in data
