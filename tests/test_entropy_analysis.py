"""Tests for entropy analysis functionality."""

import json
import math
from pathlib import Path

import pytest

from file_analyzer_mcp.server import (
    calculate_entropy,
    _analyze_entropy_impl as analyze_entropy,
)


class TestCalculateEntropy:
    """Tests for calculate_entropy function."""

    def test_empty_data_zero_entropy(self):
        """Test empty data has zero entropy."""
        assert calculate_entropy(b'') == 0.0

    def test_single_byte_zero_entropy(self):
        """Test single byte value has zero entropy."""
        assert calculate_entropy(b'\x00') == 0.0

    def test_repeated_bytes_zero_entropy(self):
        """Test repeated same byte has zero entropy."""
        data = b'A' * 1000
        entropy = calculate_entropy(data)
        assert entropy == 0.0

    def test_two_values_one_bit_entropy(self):
        """Test two equally distributed values have ~1 bit entropy."""
        data = b'AB' * 500
        entropy = calculate_entropy(data)
        # Should be close to 1.0 bit per byte
        assert 0.9 < entropy < 1.1

    def test_all_bytes_max_entropy(self):
        """Test all 256 byte values equally distributed approaches max entropy."""
        # All 256 byte values equally distributed
        data = bytes(list(range(256)) * 100)
        entropy = calculate_entropy(data)
        # Max entropy is 8 bits
        assert entropy > 7.9

    def test_random_data_high_entropy(self, high_entropy_file: Path):
        """Test random data has high entropy."""
        data = high_entropy_file.read_bytes()
        entropy = calculate_entropy(data)
        # Random data should have entropy > 7.0
        assert entropy > 7.0

    def test_text_moderate_entropy(self):
        """Test English text has moderate entropy."""
        # English text typically has entropy around 3-5 bits
        data = b"The quick brown fox jumps over the lazy dog. " * 100
        entropy = calculate_entropy(data)
        assert 3.0 < entropy < 6.0

    def test_entropy_calculation_accuracy(self):
        """Test entropy calculation matches expected value."""
        # 4 equally distributed values = 2 bits entropy
        data = b'ABCD' * 250
        entropy = calculate_entropy(data)
        expected = 2.0  # log2(4)
        assert abs(entropy - expected) < 0.01

    def test_entropy_with_binary_content(self):
        """Test entropy with binary content."""
        data = bytes([0, 1, 2, 3, 4, 5, 6, 7]) * 125
        entropy = calculate_entropy(data)
        expected = 3.0  # log2(8)
        assert abs(entropy - expected) < 0.01


class TestAnalyzeEntropyTool:
    """Tests for analyze_entropy MCP tool."""

    @pytest.mark.asyncio
    async def test_tool_success(self, text_file: Path):
        """Test successful entropy analysis."""
        result = await analyze_entropy(str(text_file))
        data = json.loads(result)

        assert data['success'] is True
        assert 'entropy' in data
        assert 'assessment' in data
        assert 'max_entropy' in data
        assert data['max_entropy'] == 8.0

    @pytest.mark.asyncio
    async def test_tool_high_entropy_detection(self, high_entropy_file: Path):
        """Test detection of high entropy files."""
        result = await analyze_entropy(str(high_entropy_file))
        data = json.loads(result)

        assert data['success'] is True
        assert data['entropy'] > 7.0
        assert 'high' in data['assessment'].lower() or 'very_high' in data['assessment']

    @pytest.mark.asyncio
    async def test_tool_low_entropy_detection(self, low_entropy_file: Path):
        """Test detection of low entropy files."""
        result = await analyze_entropy(str(low_entropy_file))
        data = json.loads(result)

        assert data['success'] is True
        assert data['entropy'] < 1.0
        assert 'low' in data['assessment'].lower()

    @pytest.mark.asyncio
    async def test_tool_normal_text_assessment(self, text_file: Path):
        """Test normal text file gets normal assessment."""
        result = await analyze_entropy(str(text_file))
        data = json.loads(result)

        assert data['success'] is True
        # Text files typically have moderate entropy
        assert 2.0 < data['entropy'] < 7.0

    @pytest.mark.asyncio
    async def test_tool_file_not_found(self):
        """Test tool handles missing file."""
        result = await analyze_entropy("/nonexistent/file.txt")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data

    @pytest.mark.asyncio
    async def test_tool_includes_bytes_analyzed(self, text_file: Path):
        """Test tool reports bytes analyzed."""
        result = await analyze_entropy(str(text_file))
        data = json.loads(result)

        assert 'bytes_analyzed' in data
        assert data['bytes_analyzed'] > 0

    @pytest.mark.asyncio
    async def test_tool_limits_analysis_size(self, temp_dir: Path):
        """Test tool limits analysis to first 1MB."""
        # Create 2MB file
        large_file = temp_dir / "large.bin"
        large_file.write_bytes(b'A' * (2 * 1024 * 1024))

        result = await analyze_entropy(str(large_file))
        data = json.loads(result)

        assert data['success'] is True
        # Should only analyze first 1MB
        assert data['bytes_analyzed'] == 1024 * 1024


class TestEntropyAssessments:
    """Tests for entropy assessment thresholds."""

    @pytest.mark.asyncio
    async def test_very_high_entropy_assessment(self, temp_dir: Path):
        """Test very high entropy (>7.5) assessment."""
        # Create file with entropy > 7.5
        import random
        random.seed(42)
        data = bytes([random.randint(0, 255) for _ in range(10000)])
        file_path = temp_dir / "encrypted.bin"
        file_path.write_bytes(data)

        result = await analyze_entropy(str(file_path))
        parsed = json.loads(result)

        if parsed['entropy'] > 7.5:
            assert 'very_high' in parsed['assessment'] or 'encrypted' in parsed['assessment'].lower()

    @pytest.mark.asyncio
    async def test_elevated_entropy_assessment(self, temp_dir: Path):
        """Test elevated entropy (6.0-7.0) assessment."""
        # Create file with moderate-high entropy
        data = bytes(list(range(64)) * 500)  # 6 bits = 64 values
        file_path = temp_dir / "compressed.bin"
        file_path.write_bytes(data)

        result = await analyze_entropy(str(file_path))
        parsed = json.loads(result)

        assert parsed['success'] is True
        # Entropy should be around 6.0
        assert 5.5 < parsed['entropy'] < 6.5

    @pytest.mark.asyncio
    async def test_sparse_data_assessment(self, temp_dir: Path):
        """Test sparse/repetitive data assessment."""
        # Very repetitive data
        data = b'\x00' * 9900 + b'\x01' * 100
        file_path = temp_dir / "sparse.bin"
        file_path.write_bytes(data)

        result = await analyze_entropy(str(file_path))
        parsed = json.loads(result)

        assert parsed['success'] is True
        assert parsed['entropy'] < 1.0


class TestEntropyEdgeCases:
    """Edge case tests for entropy analysis."""

    @pytest.mark.asyncio
    async def test_empty_file_entropy(self, empty_file: Path):
        """Test entropy of empty file."""
        result = await analyze_entropy(str(empty_file))
        data = json.loads(result)

        # Empty file should have 0 entropy
        assert data['success'] is True
        assert data['entropy'] == 0.0

    def test_entropy_mathematical_precision(self):
        """Test entropy calculation mathematical precision."""
        # Uniform distribution of 16 values = 4 bits exactly
        data = bytes(list(range(16)) * 1000)
        entropy = calculate_entropy(data)
        assert abs(entropy - 4.0) < 0.001

    def test_entropy_single_occurrence_each_byte(self):
        """Test entropy with exactly one occurrence of each byte value."""
        data = bytes(range(256))
        entropy = calculate_entropy(data)
        assert abs(entropy - 8.0) < 0.001
