"""Tests for password analysis functionality."""

import json

import pytest

from file_analyzer_mcp.password_analyzer import (
    analyze_password,
    analyze_password_policy,
    calculate_entropy,
    check_common_patterns,
    estimate_crack_time,
    generate_password_requirements,
)


class TestPasswordEntropy:
    """Tests for password entropy calculation."""

    def test_entropy_lowercase_only(self):
        """Test entropy for lowercase-only password."""
        entropy = calculate_entropy("abcdefgh")
        # 26 lowercase chars, 8 length = 8 * log2(26) ~ 37.6 bits
        assert 35 < entropy < 40

    def test_entropy_mixed_case(self):
        """Test entropy for mixed case password."""
        entropy = calculate_entropy("AbCdEfGh")
        # 52 chars (upper+lower), 8 length = 8 * log2(52) ~ 45.6 bits
        assert 43 < entropy < 48

    def test_entropy_with_digits(self):
        """Test entropy with digits included."""
        entropy = calculate_entropy("Abc12345")
        # 62 chars (upper+lower+digits), 8 length ~ 47.6 bits
        assert 45 < entropy < 50

    def test_entropy_with_special(self):
        """Test entropy with special characters."""
        entropy = calculate_entropy("Abc123!@")
        # 94 chars (all printable), 8 length ~ 52.4 bits
        assert 50 < entropy < 55

    def test_entropy_empty_password(self):
        """Test entropy of empty password."""
        entropy = calculate_entropy("")
        assert entropy == 0

    def test_entropy_longer_password(self):
        """Test entropy scales with length."""
        short_entropy = calculate_entropy("abcd")
        long_entropy = calculate_entropy("abcdefghijkl")
        assert long_entropy > short_entropy * 2


class TestCommonPatterns:
    """Tests for common pattern detection."""

    def test_detect_common_password(self):
        """Test detection of common passwords."""
        issues = check_common_patterns("password")
        assert any(i['type'] == 'common_password' for i in issues)
        assert any(i['severity'] == 'critical' for i in issues)

    def test_detect_keyboard_pattern(self):
        """Test detection of keyboard patterns."""
        issues = check_common_patterns("qwerty123")
        assert any(i['type'] == 'keyboard_pattern' for i in issues)

    def test_detect_repeated_chars(self):
        """Test detection of repeated characters."""
        issues = check_common_patterns("passssword")
        assert any(i['type'] == 'repeated_chars' for i in issues)

    def test_detect_sequential_numbers(self):
        """Test detection of sequential numbers."""
        issues = check_common_patterns("pass1234")
        assert any(i['type'] == 'sequential_numbers' for i in issues)

    def test_detect_sequential_letters(self):
        """Test detection of sequential letters."""
        issues = check_common_patterns("abcdefgh")
        assert any(i['type'] == 'sequential_letters' for i in issues)

    def test_detect_year_pattern(self):
        """Test detection of year patterns."""
        issues = check_common_patterns("password2023")
        assert any(i['type'] == 'contains_year' for i in issues)

    def test_detect_leetspeak(self):
        """Test detection of leetspeak common passwords."""
        issues = check_common_patterns("p@ssw0rd")
        assert any(i['type'] == 'leet_common' for i in issues)

    def test_no_issues_strong_password(self):
        """Test no issues for strong random password."""
        issues = check_common_patterns("Xk9#mP2$vL7@")
        assert len(issues) == 0


class TestCrackTimeEstimation:
    """Tests for crack time estimation."""

    def test_instant_crack_time(self):
        """Test instant crack time for very low entropy."""
        result = estimate_crack_time(10)
        assert result['severity'] == 'critical'

    def test_seconds_crack_time(self):
        """Test seconds crack time."""
        result = estimate_crack_time(34)  # ~2^34 / 10^10 < 1 minute
        assert 'seconds' in result['time'].lower() or 'minutes' in result['time'].lower()

    def test_years_crack_time(self):
        """Test years crack time for high entropy."""
        result = estimate_crack_time(80)
        assert 'year' in result['time'].lower() or 'centuries' in result['time'].lower()

    def test_centuries_crack_time(self):
        """Test centuries crack time for very high entropy."""
        result = estimate_crack_time(128)
        assert result['severity'] == 'excellent'


class TestAnalyzePassword:
    """Tests for analyze_password function."""

    @pytest.mark.asyncio
    async def test_analyze_weak_password(self):
        """Test analysis of weak password."""
        result = await analyze_password("password")
        data = json.loads(result)

        assert data['success'] is True
        assert data['strength'] == 'Very Weak'
        assert data['score'] < 40
        assert len(data['issues']) > 0

    @pytest.mark.asyncio
    async def test_analyze_strong_password(self):
        """Test analysis of strong password."""
        result = await analyze_password("Xk9#mP2$vL7@qR5!")
        data = json.loads(result)

        assert data['success'] is True
        assert data['strength'] in ['Strong', 'Moderate']
        assert data['score'] > 60

    @pytest.mark.asyncio
    async def test_analyze_includes_character_analysis(self):
        """Test password analysis includes character breakdown."""
        result = await analyze_password("Test123!")
        data = json.loads(result)

        char_analysis = data['character_analysis']
        assert char_analysis['has_lowercase'] is True
        assert char_analysis['has_uppercase'] is True
        assert char_analysis['has_digits'] is True
        assert char_analysis['has_special'] is True
        assert char_analysis['character_types'] == 4

    @pytest.mark.asyncio
    async def test_analyze_includes_recommendations(self):
        """Test password analysis includes recommendations."""
        result = await analyze_password("weak")
        data = json.loads(result)

        assert 'recommendations' in data
        assert len(data['recommendations']) > 0

    @pytest.mark.asyncio
    async def test_analyze_includes_crack_time(self):
        """Test password analysis includes crack time estimate."""
        result = await analyze_password("Test123!")
        data = json.loads(result)

        assert 'crack_time_estimate' in data
        assert 'time' in data['crack_time_estimate']
        assert 'severity' in data['crack_time_estimate']

    @pytest.mark.asyncio
    async def test_analyze_with_hibp_check(self):
        """Test password analysis with HIBP check option."""
        result = await analyze_password("Test123!", check_hibp=True)
        data = json.loads(result)

        assert 'hibp_check' in data
        assert 'hash_prefix' in data['hibp_check']
        assert len(data['hibp_check']['hash_prefix']) == 5

    @pytest.mark.asyncio
    async def test_analyze_privacy_note(self):
        """Test password analysis includes privacy note."""
        result = await analyze_password("anypassword")
        data = json.loads(result)

        assert 'note' in data
        assert 'NOT transmitted' in data['note'] or 'NOT stored' in data['note']


class TestAnalyzePasswordPolicy:
    """Tests for analyze_password_policy function."""

    @pytest.mark.asyncio
    async def test_analyze_default_policy(self):
        """Test analysis of default policy."""
        result = await analyze_password_policy()
        data = json.loads(result)

        assert data['success'] is True
        assert 'score' in data
        assert 'grade' in data

    @pytest.mark.asyncio
    async def test_analyze_weak_policy(self):
        """Test analysis of weak policy."""
        result = await analyze_password_policy(
            min_length=4,
            require_uppercase=False,
            require_lowercase=True,
            require_digit=False,
            require_special=False
        )
        data = json.loads(result)

        assert data['grade'] in ['D', 'F']
        assert len(data['issues']) > 0

    @pytest.mark.asyncio
    async def test_analyze_strong_policy(self):
        """Test analysis of strong policy."""
        result = await analyze_password_policy(
            min_length=14,
            require_uppercase=True,
            require_lowercase=True,
            require_digit=True,
            require_special=True,
            max_length=128,
            password_history=12
        )
        data = json.loads(result)

        assert data['grade'] in ['A', 'B']

    @pytest.mark.asyncio
    async def test_nist_compliance_check(self):
        """Test NIST 800-63B compliance checking."""
        result = await analyze_password_policy(
            min_length=8,
            max_length=64
        )
        data = json.loads(result)

        assert 'nist_800_63b' in data
        assert 'compliant' in data['nist_800_63b']

    @pytest.mark.asyncio
    async def test_nist_non_compliant(self):
        """Test NIST non-compliance detection."""
        result = await analyze_password_policy(
            min_length=6,
            max_length=20
        )
        data = json.loads(result)

        assert data['nist_800_63b']['compliant'] is False
        assert len(data['nist_800_63b']['notes']) > 0

    @pytest.mark.asyncio
    async def test_policy_includes_best_practices(self):
        """Test policy analysis includes best practices."""
        result = await analyze_password_policy()
        data = json.loads(result)

        assert 'best_practices' in data
        assert len(data['best_practices']) > 0


class TestGeneratePasswordRequirements:
    """Tests for generate_password_requirements function."""

    @pytest.mark.asyncio
    async def test_generate_basic_requirements(self):
        """Test generating basic security level requirements."""
        result = await generate_password_requirements(security_level="basic")
        data = json.loads(result)

        assert data['success'] is True
        assert data['security_level'] == 'basic'
        assert data['recommended_policy']['min_length'] == 8

    @pytest.mark.asyncio
    async def test_generate_standard_requirements(self):
        """Test generating standard security level requirements."""
        result = await generate_password_requirements(security_level="standard")
        data = json.loads(result)

        assert data['recommended_policy']['min_length'] == 12

    @pytest.mark.asyncio
    async def test_generate_high_requirements(self):
        """Test generating high security level requirements."""
        result = await generate_password_requirements(security_level="high")
        data = json.loads(result)

        assert data['recommended_policy']['min_length'] == 14
        assert data['recommended_policy']['mfa_required'] is True

    @pytest.mark.asyncio
    async def test_generate_critical_requirements(self):
        """Test generating critical security level requirements."""
        result = await generate_password_requirements(security_level="critical")
        data = json.loads(result)

        assert data['recommended_policy']['min_length'] == 16
        assert data['recommended_policy']['hardware_token'] is True

    @pytest.mark.asyncio
    async def test_generate_invalid_level(self):
        """Test generating with invalid security level."""
        result = await generate_password_requirements(security_level="invalid")
        data = json.loads(result)

        assert data['success'] is False
        assert 'error' in data
        assert 'valid_levels' in data

    @pytest.mark.asyncio
    async def test_generate_includes_implementation_notes(self):
        """Test generated requirements include implementation notes."""
        result = await generate_password_requirements()
        data = json.loads(result)

        assert 'implementation_notes' in data
        assert len(data['implementation_notes']) > 0
