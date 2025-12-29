"""Tests for MCP tool endpoints."""

import json
from pathlib import Path

import pytest

from file_analyzer_mcp.server import (
    _check_file_reputation_impl as check_file_reputation,
    _get_magic_signatures_impl as get_magic_signatures,
    _identify_file_impl as identify_file,
)


class TestIdentifyFileTool:
    """Tests for identify_file MCP tool."""

    @pytest.mark.asyncio
    async def test_identify_pe_file(self, pe_file: Path):
        """Test identifying PE executable."""
        result = await identify_file(str(pe_file))
        data = json.loads(result)

        assert data['success'] is True
        assert data['magic_analysis']['type'] == 'executable'
        assert 'PE' in data['magic_analysis']['name']

    @pytest.mark.asyncio
    async def test_identify_pdf_file(self, pdf_file: Path):
        """Test identifying PDF document."""
        result = await identify_file(str(pdf_file))
        data = json.loads(result)

        assert data['success'] is True
        assert data['magic_analysis']['type'] == 'document'
        assert data['extension'] == '.pdf'

    @pytest.mark.asyncio
    async def test_identify_png_file(self, png_file: Path):
        """Test identifying PNG image."""
        result = await identify_file(str(png_file))
        data = json.loads(result)

        assert data['success'] is True
        assert data['magic_analysis']['type'] == 'image'

    @pytest.mark.asyncio
    async def test_identify_text_file(self, text_file: Path):
        """Test identifying plain text file."""
        result = await identify_file(str(text_file))
        data = json.loads(result)

        assert data['success'] is True
        assert data['magic_analysis']['type'] == 'text'

    @pytest.mark.asyncio
    async def test_identify_includes_file_metadata(self, text_file: Path):
        """Test identification includes file metadata."""
        result = await identify_file(str(text_file))
        data = json.loads(result)

        assert 'file_path' in data
        assert 'file_name' in data
        assert 'extension' in data
        assert 'size_bytes' in data
        assert 'size_human' in data

    @pytest.mark.asyncio
    async def test_identify_includes_header_info(self, pe_file: Path):
        """Test identification includes header information."""
        result = await identify_file(str(pe_file))
        data = json.loads(result)

        assert 'header_hex' in data
        assert 'header_ascii' in data
        assert len(data['header_hex']) == 32  # 16 bytes * 2

    @pytest.mark.asyncio
    async def test_identify_detects_extension_mismatch(self, pe_file_disguised_as_txt: Path):
        """Test detection of extension mismatch."""
        result = await identify_file(str(pe_file_disguised_as_txt))
        data = json.loads(result)

        assert data['success'] is True
        assert data['extension_mismatch'] is True
        assert 'warning' in data
        assert 'expected_extensions' in data

    @pytest.mark.asyncio
    async def test_identify_critical_alert_for_disguised_exe(self, pe_file_disguised_as_txt: Path):
        """Test critical alert for executable disguised as safe file."""
        result = await identify_file(str(pe_file_disguised_as_txt))
        data = json.loads(result)

        assert data['threat_level'] == 'critical'
        assert 'alert' in data
        assert 'CRITICAL' in data['alert']

    @pytest.mark.asyncio
    async def test_identify_file_not_found(self):
        """Test handling of non-existent file."""
        result = await identify_file("/nonexistent/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data

    @pytest.mark.asyncio
    async def test_identify_directory_error(self, temp_dir: Path):
        """Test handling of directory instead of file."""
        result = await identify_file(str(temp_dir))
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data
        assert 'regular file' in data['error'].lower()

    @pytest.mark.asyncio
    async def test_identify_expands_tilde(self, temp_dir: Path):
        """Test path expansion for ~ character."""
        # This test verifies the expanduser functionality
        file_path = temp_dir / "test.txt"
        file_path.write_bytes(b"test")

        result = await identify_file(str(file_path))
        data = json.loads(result)

        assert data['success'] is True

    @pytest.mark.asyncio
    async def test_identify_human_readable_size(self, temp_dir: Path):
        """Test human-readable size formatting."""
        # Create files of different sizes
        small_file = temp_dir / "small.txt"
        small_file.write_bytes(b"x" * 500)

        result = await identify_file(str(small_file))
        data = json.loads(result)

        assert 'KB' in data['size_human']

    @pytest.mark.asyncio
    async def test_identify_large_file_size_format(self, temp_dir: Path):
        """Test human-readable size for larger files."""
        large_file = temp_dir / "large.bin"
        large_file.write_bytes(b"x" * (2 * 1024 * 1024))  # 2MB

        result = await identify_file(str(large_file))
        data = json.loads(result)

        assert 'MB' in data['size_human']


class TestCheckFileReputationTool:
    """Tests for check_file_reputation MCP tool."""

    @pytest.mark.asyncio
    async def test_reputation_success(self, text_file: Path):
        """Test successful file reputation check."""
        result = await check_file_reputation(str(text_file))
        data = json.loads(result)

        assert data['success'] is True
        assert 'hashes' in data
        assert 'reputation_links' in data

    @pytest.mark.asyncio
    async def test_reputation_includes_all_hashes(self, text_file: Path):
        """Test reputation check includes all hash types."""
        result = await check_file_reputation(str(text_file))
        data = json.loads(result)

        assert 'md5' in data['hashes']
        assert 'sha1' in data['hashes']
        assert 'sha256' in data['hashes']

    @pytest.mark.asyncio
    async def test_reputation_includes_virustotal_link(self, text_file: Path):
        """Test reputation check includes VirusTotal link."""
        result = await check_file_reputation(str(text_file))
        data = json.loads(result)

        assert 'virustotal' in data['reputation_links']
        sha256 = data['hashes']['sha256']
        assert sha256 in data['reputation_links']['virustotal']

    @pytest.mark.asyncio
    async def test_reputation_includes_hybrid_analysis_link(self, text_file: Path):
        """Test reputation check includes Hybrid Analysis link."""
        result = await check_file_reputation(str(text_file))
        data = json.loads(result)

        assert 'hybrid_analysis' in data['reputation_links']

    @pytest.mark.asyncio
    async def test_reputation_includes_malwarebazaar_link(self, text_file: Path):
        """Test reputation check includes MalwareBazaar link."""
        result = await check_file_reputation(str(text_file))
        data = json.loads(result)

        assert 'malwarebazaar' in data['reputation_links']

    @pytest.mark.asyncio
    async def test_reputation_includes_detected_type(self, pe_file: Path):
        """Test reputation check includes detected file type."""
        result = await check_file_reputation(str(pe_file))
        data = json.loads(result)

        assert 'detected_type' in data
        assert 'PE' in data['detected_type'] or 'Executable' in data['detected_type']

    @pytest.mark.asyncio
    async def test_reputation_file_not_found(self):
        """Test reputation check for non-existent file."""
        result = await check_file_reputation("/nonexistent/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data

    @pytest.mark.asyncio
    async def test_reputation_includes_file_info(self, text_file: Path):
        """Test reputation check includes basic file info."""
        result = await check_file_reputation(str(text_file))
        data = json.loads(result)

        assert 'file_path' in data
        assert 'file_name' in data
        assert 'size_bytes' in data


class TestGetMagicSignaturesTool:
    """Tests for get_magic_signatures MCP tool."""

    @pytest.mark.asyncio
    async def test_get_signatures_success(self):
        """Test successful retrieval of magic signatures."""
        result = await get_magic_signatures()
        data = json.loads(result)

        assert data['success'] is True
        assert 'signatures' in data
        assert 'total_signatures' in data

    @pytest.mark.asyncio
    async def test_signatures_count(self):
        """Test signature count is reported correctly."""
        result = await get_magic_signatures()
        data = json.loads(result)

        assert data['total_signatures'] == len(data['signatures'])
        assert data['total_signatures'] >= 30

    @pytest.mark.asyncio
    async def test_signature_format(self):
        """Test signature entries have correct format."""
        result = await get_magic_signatures()
        data = json.loads(result)

        for sig in data['signatures']:
            assert 'magic_hex' in sig
            assert 'magic_preview' in sig
            assert 'type' in sig
            assert 'name' in sig
            assert 'extensions' in sig

    @pytest.mark.asyncio
    async def test_signatures_include_common_types(self):
        """Test signatures include common file types."""
        result = await get_magic_signatures()
        data = json.loads(result)

        names = [sig['name'] for sig in data['signatures']]

        # Check for common types
        assert any('PE' in name or 'EXE' in name for name in names)
        assert any('PDF' in name for name in names)
        assert any('PNG' in name for name in names)
        assert any('ZIP' in name for name in names)

    @pytest.mark.asyncio
    async def test_magic_hex_is_valid(self):
        """Test magic_hex values are valid hex strings."""
        result = await get_magic_signatures()
        data = json.loads(result)

        for sig in data['signatures']:
            # Should be valid hex
            int(sig['magic_hex'], 16)

    @pytest.mark.asyncio
    async def test_magic_preview_printable(self):
        """Test magic_preview contains only printable chars or dots."""
        result = await get_magic_signatures()
        data = json.loads(result)

        for sig in data['signatures']:
            preview = sig['magic_preview']
            for char in preview:
                assert char == '.' or (32 <= ord(char) < 127)


class TestMCPToolResponseFormat:
    """Tests for consistent MCP tool response format."""

    @pytest.mark.asyncio
    async def test_identify_file_json_format(self, text_file: Path):
        """Test identify_file returns valid JSON."""
        result = await identify_file(str(text_file))
        # Should not raise
        json.loads(result)

    @pytest.mark.asyncio
    async def test_reputation_json_format(self, text_file: Path):
        """Test check_file_reputation returns valid JSON."""
        result = await check_file_reputation(str(text_file))
        json.loads(result)

    @pytest.mark.asyncio
    async def test_signatures_json_format(self):
        """Test get_magic_signatures returns valid JSON."""
        result = await get_magic_signatures()
        json.loads(result)

    @pytest.mark.asyncio
    async def test_error_response_format(self):
        """Test error responses have consistent format."""
        result = await identify_file("/nonexistent/file.txt")
        data = json.loads(result)

        assert 'success' in data
        assert data['success'] is False
        assert 'error' in data
