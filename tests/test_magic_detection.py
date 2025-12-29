"""Tests for magic number file type detection."""

import json
from pathlib import Path

import pytest

from file_analyzer_mcp.server import (
    MAGIC_SIGNATURES,
    identify_by_magic,
    read_file_header,
)


class TestReadFileHeader:
    """Tests for read_file_header function."""

    def test_read_header_default_bytes(self, pe_file: Path):
        """Test reading default 32 bytes from file header."""
        header = read_file_header(str(pe_file))
        assert len(header) == 32
        assert header.startswith(b'\x4D\x5A')

    def test_read_header_custom_bytes(self, text_file: Path):
        """Test reading custom number of bytes."""
        header = read_file_header(str(text_file), num_bytes=5)
        assert len(header) == 5
        assert header == b'Hello'

    def test_read_header_small_file(self, temp_dir: Path):
        """Test reading header from file smaller than requested bytes."""
        small_file = temp_dir / "tiny.txt"
        small_file.write_bytes(b'Hi')
        header = read_file_header(str(small_file), num_bytes=100)
        assert len(header) == 2
        assert header == b'Hi'

    def test_read_header_empty_file(self, empty_file: Path):
        """Test reading header from empty file."""
        header = read_file_header(str(empty_file))
        assert header == b''


class TestIdentifyByMagic:
    """Tests for identify_by_magic function."""

    def test_identify_pe_executable(self):
        """Test identification of PE executable."""
        header = b'\x4D\x5A' + b'\x00' * 30
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'executable'
        assert result['name'] == 'PE Executable (EXE/DLL)'
        assert '.exe' in result['extensions']

    def test_identify_elf_binary(self):
        """Test identification of ELF binary."""
        header = b'\x7F\x45\x4C\x46' + b'\x00' * 28
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'executable'
        assert result['name'] == 'ELF Binary'

    def test_identify_macho_64bit(self):
        """Test identification of Mach-O 64-bit binary."""
        header = b'\xCF\xFA\xED\xFE' + b'\x00' * 28
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'executable'
        assert 'Mach-O' in result['name']

    def test_identify_macho_32bit(self):
        """Test identification of Mach-O 32-bit binary."""
        header = b'\xFE\xED\xFA\xCE' + b'\x00' * 28
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'executable'

    def test_identify_pdf(self):
        """Test identification of PDF document."""
        header = b'%PDF-1.4' + b'\x00' * 24
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'document'
        assert result['name'] == 'PDF Document'

    def test_identify_zip(self):
        """Test identification of ZIP archive."""
        header = b'PK\x03\x04' + b'\x00' * 28
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'archive'
        assert 'ZIP' in result['name']

    def test_identify_gzip(self):
        """Test identification of GZIP archive."""
        header = b'\x1F\x8B' + b'\x00' * 30
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'archive'
        assert result['name'] == 'GZIP'

    def test_identify_7zip(self):
        """Test identification of 7-Zip archive."""
        header = b'7z\xBC\xAF\x27\x1C' + b'\x00' * 26
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['name'] == '7-Zip'

    def test_identify_rar(self):
        """Test identification of RAR archive."""
        header = b'Rar!\x1A\x07' + b'\x00' * 26
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['name'] == 'RAR'

    def test_identify_bzip2(self):
        """Test identification of BZIP2 archive."""
        header = b'BZh' + b'\x00' * 29
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['name'] == 'BZIP2'

    def test_identify_png(self):
        """Test identification of PNG image."""
        header = b'\x89PNG\r\n\x1A\n' + b'\x00' * 24
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'image'
        assert result['name'] == 'PNG'

    def test_identify_jpeg(self):
        """Test identification of JPEG image."""
        header = b'\xFF\xD8\xFF' + b'\x00' * 29
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'image'
        assert result['name'] == 'JPEG'

    def test_identify_gif87(self):
        """Test identification of GIF87 image."""
        header = b'GIF87a' + b'\x00' * 26
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'image'
        assert 'GIF' in result['name']

    def test_identify_gif89(self):
        """Test identification of GIF89 image."""
        header = b'GIF89a' + b'\x00' * 26
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'image'

    def test_identify_bmp(self):
        """Test identification of BMP image."""
        header = b'BM' + b'\x00' * 30
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'image'
        assert result['name'] == 'BMP'

    def test_identify_mp3_id3(self):
        """Test identification of MP3 with ID3 tag."""
        header = b'ID3' + b'\x00' * 29
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'media'
        assert 'MP3' in result['name']

    def test_identify_mp3_raw(self):
        """Test identification of raw MP3."""
        header = b'\xFF\xFB' + b'\x00' * 30
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['name'] == 'MP3'

    def test_identify_ogg(self):
        """Test identification of OGG container."""
        header = b'OggS' + b'\x00' * 28
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'media'
        assert result['name'] == 'OGG'

    def test_identify_flac(self):
        """Test identification of FLAC audio."""
        header = b'fLaC' + b'\x00' * 28
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['name'] == 'FLAC'

    def test_identify_riff(self):
        """Test identification of RIFF container."""
        header = b'RIFF' + b'\x00' * 28
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'media'

    def test_identify_sqlite(self):
        """Test identification of SQLite database."""
        header = b'SQLite format 3\x00' + b'\x00' * 16
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'database'
        assert result['name'] == 'SQLite'

    def test_identify_shell_script(self):
        """Test identification of shell script."""
        header = b'#!/bin/bash\necho test'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'script'

    def test_identify_php_script(self):
        """Test identification of PHP script."""
        header = b'<?php echo "test"; ?>'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'script'
        assert 'PHP' in result['name']

    def test_identify_html_doctype(self):
        """Test identification of HTML with doctype."""
        header = b'<!DOCTYPE html><html>'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'web'

    def test_identify_html_tag(self):
        """Test identification of HTML by tag."""
        header = b'<html><head><title>Test</title>'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'web'

    def test_identify_xml(self):
        """Test identification of XML document."""
        header = b'<?xml version="1.0"?>'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'data'
        assert result['name'] == 'XML'

    def test_identify_pem_certificate(self):
        """Test identification of PEM certificate."""
        header = b'-----BEGIN CERTIFICATE-----\n'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'certificate'

    def test_identify_private_key(self):
        """Test identification of private key."""
        header = b'-----BEGIN PRIVATE KEY-----\n'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'key'

    def test_identify_rsa_private_key(self):
        """Test identification of RSA private key."""
        header = b'-----BEGIN RSA PRIVATE KEY-----'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'key'

    def test_identify_plain_text(self):
        """Test identification of plain text (UTF-8 decodable)."""
        header = b'This is plain text content'
        result = identify_by_magic(header)
        assert result['identified'] is True
        assert result['type'] == 'text'
        assert 'Text' in result['name']

    def test_identify_unknown_binary(self):
        """Test identification of unknown binary data."""
        header = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x80\x81\x82\x83\x84\x85'
        result = identify_by_magic(header)
        assert result['identified'] is False
        assert result['type'] == 'unknown'

    def test_magic_bytes_hex_output(self):
        """Test that magic bytes are converted to hex correctly."""
        header = b'\x4D\x5A' + b'\x00' * 30
        result = identify_by_magic(header)
        assert 'magic_bytes' in result
        assert result['magic_bytes'] == '4d5a'


class TestMagicSignaturesCompleteness:
    """Tests for MAGIC_SIGNATURES dictionary completeness."""

    def test_signatures_have_required_fields(self):
        """Test all signatures have required fields."""
        for magic, info in MAGIC_SIGNATURES.items():
            assert 'type' in info, f"Missing 'type' for magic {magic.hex()}"
            assert 'name' in info, f"Missing 'name' for magic {magic.hex()}"
            assert 'extensions' in info, f"Missing 'extensions' for magic {magic.hex()}"

    def test_signatures_extensions_are_lists(self):
        """Test all extensions are lists."""
        for magic, info in MAGIC_SIGNATURES.items():
            assert isinstance(info['extensions'], list), f"Extensions should be list for {magic.hex()}"

    def test_signature_types_are_valid(self):
        """Test all type values are from expected set."""
        valid_types = {
            'executable', 'script', 'document', 'archive', 'image',
            'media', 'web', 'data', 'database', 'certificate', 'key'
        }
        for magic, info in MAGIC_SIGNATURES.items():
            assert info['type'] in valid_types, f"Invalid type '{info['type']}' for {magic.hex()}"

    def test_total_signature_count(self):
        """Test we have a reasonable number of signatures."""
        assert len(MAGIC_SIGNATURES) >= 30, "Should have at least 30 magic signatures"


class TestFileIdentificationIntegration:
    """Integration tests for file identification."""

    def test_identify_actual_pe_file(self, pe_file: Path):
        """Test identifying actual PE file."""
        header = read_file_header(str(pe_file))
        result = identify_by_magic(header)
        assert result['type'] == 'executable'

    def test_identify_actual_pdf_file(self, pdf_file: Path):
        """Test identifying actual PDF file."""
        header = read_file_header(str(pdf_file))
        result = identify_by_magic(header)
        assert result['type'] == 'document'

    def test_identify_actual_png_file(self, png_file: Path):
        """Test identifying actual PNG file."""
        header = read_file_header(str(png_file))
        result = identify_by_magic(header)
        assert result['type'] == 'image'

    def test_identify_actual_text_file(self, text_file: Path):
        """Test identifying actual text file."""
        header = read_file_header(str(text_file))
        result = identify_by_magic(header)
        assert result['type'] == 'text'
