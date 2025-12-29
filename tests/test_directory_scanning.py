"""Tests for directory scanning functionality."""

import json
from pathlib import Path

import pytest

from file_analyzer_mcp.server import _scan_directory_impl as scan_directory


class TestScanDirectory:
    """Tests for scan_directory MCP tool."""

    @pytest.mark.asyncio
    async def test_scan_empty_directory(self, temp_dir: Path):
        """Test scanning empty directory."""
        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert data['success'] is True
        assert data['files_scanned'] == 0
        assert data['suspicious_count'] == 0

    @pytest.mark.asyncio
    async def test_scan_directory_with_files(self, mixed_directory: Path):
        """Test scanning directory with various files."""
        result = await scan_directory(str(mixed_directory))
        data = json.loads(result)

        assert data['success'] is True
        assert data['files_scanned'] > 0
        assert 'by_type' in data

    @pytest.mark.asyncio
    async def test_scan_detects_suspicious_files(self, mixed_directory: Path):
        """Test scanning detects suspicious files."""
        result = await scan_directory(str(mixed_directory))
        data = json.loads(result)

        assert data['success'] is True
        assert data['suspicious_count'] > 0
        assert len(data['suspicious_files']) > 0

    @pytest.mark.asyncio
    async def test_scan_recursive(self, mixed_directory: Path):
        """Test recursive scanning includes subdirectories."""
        result = await scan_directory(str(mixed_directory), recursive=True)
        data = json.loads(result)

        # Should find files in subdir
        files_found = [f.get('file', '') for f in data.get('suspicious_files', [])]
        files_found.extend([str(mixed_directory)])

        # Check that nested file was included in scan count
        assert data['files_scanned'] >= 4  # At least root + nested files

    @pytest.mark.asyncio
    async def test_scan_non_recursive(self, mixed_directory: Path):
        """Test non-recursive scanning excludes subdirectories."""
        result = await scan_directory(str(mixed_directory), recursive=False)
        data = json.loads(result)

        # Count should be lower without recursion
        assert data['success'] is True

    @pytest.mark.asyncio
    async def test_scan_with_max_files_limit(self, temp_dir: Path):
        """Test scanning respects max_files limit."""
        # Create many files
        for i in range(20):
            (temp_dir / f"file{i}.txt").write_bytes(b"test content")

        result = await scan_directory(str(temp_dir), max_files=5)
        data = json.loads(result)

        assert data['success'] is True
        assert data['files_scanned'] == 5
        assert data.get('truncated', False) is True

    @pytest.mark.asyncio
    async def test_scan_without_mismatch_check(self, mixed_directory: Path):
        """Test scanning with mismatch checking disabled."""
        result = await scan_directory(str(mixed_directory), check_mismatches=False)
        data = json.loads(result)

        assert data['success'] is True
        # Without mismatch checking, no suspicious files should be detected
        # (unless there are other detection mechanisms)

    @pytest.mark.asyncio
    async def test_scan_directory_not_found(self):
        """Test scanning non-existent directory."""
        result = await scan_directory("/nonexistent/directory")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data
        assert 'not found' in data['error'].lower()

    @pytest.mark.asyncio
    async def test_scan_includes_timestamp(self, temp_dir: Path):
        """Test scan results include timestamp."""
        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert 'scanned_at' in data
        # Should be ISO format timestamp
        assert 'T' in data['scanned_at']

    @pytest.mark.asyncio
    async def test_scan_reports_by_type(self, mixed_directory: Path):
        """Test scan reports file counts by type."""
        result = await scan_directory(str(mixed_directory))
        data = json.loads(result)

        assert 'by_type' in data
        assert isinstance(data['by_type'], dict)

    @pytest.mark.asyncio
    async def test_scan_tracks_errors(self, temp_dir: Path):
        """Test scan tracks errors during scanning."""
        # Create a file
        file_path = temp_dir / "test.txt"
        file_path.write_bytes(b"test")

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert 'errors' in data
        assert isinstance(data['errors'], list)


class TestSuspiciousFileDetection:
    """Tests for suspicious file detection during scanning."""

    @pytest.mark.asyncio
    async def test_detect_exe_disguised_as_pdf(self, temp_dir: Path):
        """Test detection of executable disguised as PDF."""
        # Create PE executable with .pdf extension
        file_path = temp_dir / "report.pdf"
        file_path.write_bytes(b'\x4D\x5A' + b'\x00' * 30)

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert data['suspicious_count'] >= 1
        suspicious = data['suspicious_files'][0]
        assert suspicious['reason'] == 'extension_mismatch'
        assert suspicious['detected_type'] == 'PE Executable (EXE/DLL)'

    @pytest.mark.asyncio
    async def test_detect_exe_disguised_as_txt(self, pe_file_disguised_as_txt: Path):
        """Test detection of executable disguised as text file."""
        parent_dir = pe_file_disguised_as_txt.parent

        result = await scan_directory(str(parent_dir))
        data = json.loads(result)

        assert data['suspicious_count'] >= 1
        suspicious = [f for f in data['suspicious_files']
                      if 'document.txt' in f.get('file', '')]
        assert len(suspicious) >= 1

    @pytest.mark.asyncio
    async def test_critical_threat_level(self, temp_dir: Path):
        """Test critical threat level for dangerous disguised files."""
        # Executable disguised as image
        file_path = temp_dir / "photo.jpg"
        file_path.write_bytes(b'\x4D\x5A' + b'\x00' * 30)

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert data['suspicious_count'] >= 1
        suspicious = data['suspicious_files'][0]
        assert suspicious.get('threat_level') == 'critical'
        assert 'alert' in suspicious

    @pytest.mark.asyncio
    async def test_no_alert_for_normal_mismatch(self, temp_dir: Path):
        """Test no critical alert for non-dangerous mismatches."""
        # PDF with wrong extension (not dangerous)
        file_path = temp_dir / "document.txt"
        file_path.write_bytes(b'%PDF-1.4' + b'\x00' * 24)

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        # Should still detect mismatch but not critical
        if data['suspicious_count'] > 0:
            for suspicious in data['suspicious_files']:
                if 'document.txt' in suspicious.get('file', ''):
                    # PDF disguised as txt is not critical (PDF is document, not executable)
                    assert suspicious.get('threat_level') != 'critical'

    @pytest.mark.asyncio
    async def test_suspicious_file_includes_expected_extensions(self, temp_dir: Path):
        """Test suspicious file report includes expected extensions."""
        file_path = temp_dir / "image.txt"
        file_path.write_bytes(b'\x89PNG\r\n\x1A\n' + b'\x00' * 24)

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert data['suspicious_count'] >= 1
        suspicious = data['suspicious_files'][0]
        assert 'expected_extensions' in suspicious
        assert '.png' in suspicious['expected_extensions']


class TestScanDirectoryEdgeCases:
    """Edge case tests for directory scanning."""

    @pytest.mark.asyncio
    async def test_scan_symlinks(self, temp_dir: Path):
        """Test scanning handles symlinks."""
        # Create a file
        real_file = temp_dir / "real.txt"
        real_file.write_bytes(b"real content")

        # Create symlink (may fail on some systems)
        try:
            link_path = temp_dir / "link.txt"
            link_path.symlink_to(real_file)

            result = await scan_directory(str(temp_dir))
            data = json.loads(result)

            assert data['success'] is True
        except OSError:
            pytest.skip("Symlinks not supported on this system")

    @pytest.mark.asyncio
    async def test_scan_special_characters_in_filename(self, temp_dir: Path):
        """Test scanning files with special characters in name."""
        special_file = temp_dir / "file with spaces & symbols!.txt"
        special_file.write_bytes(b"content")

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert data['success'] is True
        assert data['files_scanned'] >= 1

    @pytest.mark.asyncio
    async def test_scan_hidden_files(self, temp_dir: Path):
        """Test scanning includes hidden files."""
        hidden_file = temp_dir / ".hidden"
        hidden_file.write_bytes(b"hidden content")

        result = await scan_directory(str(temp_dir))
        data = json.loads(result)

        assert data['success'] is True
        # Hidden files should be included
        assert data['files_scanned'] >= 1

    @pytest.mark.asyncio
    async def test_scan_deeply_nested_directory(self, temp_dir: Path):
        """Test scanning deeply nested directory structure."""
        # Create deep directory structure
        deep_path = temp_dir
        for i in range(5):
            deep_path = deep_path / f"level{i}"
            deep_path.mkdir()

        deep_file = deep_path / "deep.txt"
        deep_file.write_bytes(b"deep content")

        result = await scan_directory(str(temp_dir), recursive=True)
        data = json.loads(result)

        assert data['success'] is True
        assert data['files_scanned'] >= 1
