#!/usr/bin/env python3
"""Comprehensive test suite for anonymizer patterns."""

import pytest
from anonymizer import PatternMatcher, anonymize_content, process_single_file


@pytest.fixture
def matcher():
    """Create a PatternMatcher instance for testing."""
    return PatternMatcher()


class TestEmailPattern:
    """Tests for email address detection and anonymization."""

    def test_simple_email(self, matcher):
        content = "Contact us at john.doe@example.com for help"
        result, counts = anonymize_content(content, matcher)
        assert "@example.com" not in result
        assert "@redacted.com" in result
        assert counts["email"] == 1

    def test_multiple_emails(self, matcher):
        content = "From: alice@company.org To: bob@company.org CC: charlie@test.net"
        result, counts = anonymize_content(content, matcher)
        assert "@company.org" not in result
        assert "@test.net" not in result
        assert counts["email"] == 3

    def test_email_with_plus(self, matcher):
        content = "Email: user+tag@gmail.com"
        result, counts = anonymize_content(content, matcher)
        assert "user+tag@gmail.com" not in result
        assert counts["email"] == 1

    def test_email_with_dots(self, matcher):
        content = "Contact: first.middle.last@subdomain.example.co.uk"
        result, counts = anonymize_content(content, matcher)
        assert "first.middle.last@subdomain.example.co.uk" not in result
        assert counts["email"] == 1

    def test_email_consistency(self, matcher):
        """Same email should get same replacement."""
        content = "User john@test.com logged in. Alert sent to john@test.com"
        result, counts = anonymize_content(content, matcher)
        # Find the replacement pattern used
        parts = result.split("@redacted.com")
        assert len(parts) == 3  # Two occurrences means 3 parts
        assert counts["email"] == 2


class TestInternalIPPattern:
    """Tests for internal/private IP address detection."""

    def test_class_a_private(self, matcher):
        content = "Server at 10.0.0.1 responded"
        result, counts = anonymize_content(content, matcher)
        assert "10.0.0.1" not in result
        assert counts["internal_ip"] == 1

    def test_class_b_private(self, matcher):
        content = "Router: 172.16.254.1, Gateway: 172.31.0.1"
        result, counts = anonymize_content(content, matcher)
        assert "172.16.254.1" not in result
        assert "172.31.0.1" not in result
        assert counts["internal_ip"] == 2

    def test_class_c_private(self, matcher):
        content = "Local network 192.168.1.100 to 192.168.1.200"
        result, counts = anonymize_content(content, matcher)
        assert "192.168.1.100" not in result
        assert "192.168.1.200" not in result
        assert counts["internal_ip"] == 2

    def test_non_private_ip_not_matched(self, matcher):
        """Public IPs should NOT be matched by internal_ip pattern."""
        content = "External server at 8.8.8.8"
        result, counts = anonymize_content(content, matcher)
        # 8.8.8.8 is public, should not be matched
        assert "8.8.8.8" in result
        assert counts.get("internal_ip", 0) == 0

    def test_ip_boundary(self, matcher):
        """IPs should only match as complete addresses."""
        content = "Version 10.0.0.1.2.3 installed"
        result, counts = anonymize_content(content, matcher)
        # Should match 10.0.0.1, not the whole string
        assert counts["internal_ip"] == 1


class TestPasswordPattern:
    """Tests for password detection in various formats."""

    def test_password_equals(self, matcher):
        content = "password=secretvalue123"
        result, counts = anonymize_content(content, matcher)
        assert "secretvalue123" not in result
        assert "PASSWORD_REDACTED" in result
        assert counts["password"] == 1

    def test_password_colon(self, matcher):
        content = "password: mysecretpassword"
        result, counts = anonymize_content(content, matcher)
        assert "mysecretpassword" not in result
        assert counts["password"] == 1

    def test_pwd_variant(self, matcher):
        content = "pwd=abc123xyz"
        result, counts = anonymize_content(content, matcher)
        assert "abc123xyz" not in result
        assert counts["password"] == 1

    def test_passwd_variant(self, matcher):
        content = "passwd: hunter2"
        result, counts = anonymize_content(content, matcher)
        assert "hunter2" not in result
        assert counts["password"] == 1

    def test_secret_variant(self, matcher):
        content = "secret=my_secret_value"
        result, counts = anonymize_content(content, matcher)
        assert "my_secret_value" not in result
        assert counts["password"] == 1

    def test_json_password(self, matcher):
        content = '{"password": "topsecret123"}'
        result, counts = anonymize_content(content, matcher)
        assert "topsecret123" not in result
        assert counts["password"] == 1

    def test_case_insensitive(self, matcher):
        content = "PASSWORD=CaseSensitiveValue"
        result, counts = anonymize_content(content, matcher)
        assert "CaseSensitiveValue" not in result
        assert counts["password"] == 1


class TestAPIKeyPattern:
    """Tests for API key and token detection."""

    def test_api_key_equals(self, matcher):
        content = "api_key=abcdefghij1234567890abcd"
        result, counts = anonymize_content(content, matcher)
        assert "abcdefghij1234567890abcd" not in result
        assert counts["api_key"] == 1

    def test_apikey_no_underscore(self, matcher):
        content = "apikey: xyz789abc123def456ghi789"
        result, counts = anonymize_content(content, matcher)
        assert "xyz789abc123def456ghi789" not in result
        assert counts["api_key"] == 1

    def test_token_equals(self, matcher):
        content = "token=a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
        result, counts = anonymize_content(content, matcher)
        assert "a1b2c3d4e5f6g7h8i9j0k1l2m3n4" not in result
        assert counts["api_key"] == 1

    def test_json_api_key(self, matcher):
        content = '{"api_key": "verylongapikey1234567890abcdefghij"}'
        result, counts = anonymize_content(content, matcher)
        assert "verylongapikey1234567890abcdefghij" not in result
        assert counts["api_key"] == 1

    def test_short_value_not_matched(self, matcher):
        """Values less than 20 chars should not match."""
        content = "api_key=short"
        result, counts = anonymize_content(content, matcher)
        # Short values should not be matched
        assert counts.get("api_key", 0) == 0


class TestAuthHeaderPattern:
    """Tests for Authorization header detection."""

    def test_bearer_token(self, matcher):
        content = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result, counts = anonymize_content(content, matcher)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "AUTH_TOKEN_REDACTED" in result
        assert counts["auth_header"] == 1

    def test_basic_auth(self, matcher):
        content = "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
        result, counts = anonymize_content(content, matcher)
        assert "dXNlcm5hbWU6cGFzc3dvcmQ=" not in result
        assert counts["auth_header"] == 1

    def test_digest_auth(self, matcher):
        content = "Authorization: Digest username=admin,realm=test"
        result, counts = anonymize_content(content, matcher)
        assert "username=admin,realm=test" not in result
        assert counts["auth_header"] == 1

    def test_case_insensitive(self, matcher):
        content = "authorization: bearer token123456789"
        result, counts = anonymize_content(content, matcher)
        assert "token123456789" not in result
        assert counts["auth_header"] == 1


class TestDBConnectionPattern:
    """Tests for database connection string detection."""

    def test_jdbc_mysql(self, matcher):
        content = "jdbc:mysql://localhost:3306/mydb?user=admin&password=secret"
        result, counts = anonymize_content(content, matcher)
        assert "localhost:3306/mydb" not in result
        assert counts["db_connection"] >= 1

    def test_jdbc_postgresql(self, matcher):
        content = "jdbc:postgresql://db.server.com:5432/production"
        result, counts = anonymize_content(content, matcher)
        assert "db.server.com" not in result
        assert counts["db_connection"] == 1

    def test_server_equals(self, matcher):
        content = "Server=mydbserver.domain.com"
        result, counts = anonymize_content(content, matcher)
        assert "mydbserver.domain.com" not in result
        assert counts["db_connection"] == 1

    def test_data_source(self, matcher):
        content = "Data Source=192.168.1.100"
        result, counts = anonymize_content(content, matcher)
        assert "Data Source=192.168.1.100" not in result
        assert counts["db_connection"] >= 1

    def test_user_id(self, matcher):
        content = "User ID=dbadmin"
        result, counts = anonymize_content(content, matcher)
        assert "dbadmin" not in result
        assert counts["db_connection"] == 1


class TestUNCPathPattern:
    """Tests for UNC path detection."""

    def test_simple_unc(self, matcher):
        content = r"File located at \\server\share"
        result, counts = anonymize_content(content, matcher)
        assert r"\\server\share" not in result
        assert "REDACTED_SERVER" in result
        assert counts["unc_path"] == 1

    def test_unc_with_subfolder(self, matcher):
        content = r"Path: \\fileserver\department\reports\2024"
        result, counts = anonymize_content(content, matcher)
        assert "fileserver" not in result
        assert counts["unc_path"] == 1

    def test_unc_with_special_chars(self, matcher):
        content = r"\\server-01\share_name$\folder"
        result, counts = anonymize_content(content, matcher)
        assert "server-01" not in result
        assert counts["unc_path"] == 1


class TestHostnamePattern:
    """Tests for internal hostname detection."""

    def test_local_domain(self, matcher):
        content = "Server myserver.local is down"
        result, counts = anonymize_content(content, matcher)
        assert "myserver.local" not in result
        assert ".redacted" in result
        assert counts["hostname"] == 1

    def test_internal_domain(self, matcher):
        content = "API at api.internal responded"
        result, counts = anonymize_content(content, matcher)
        assert "api.internal" not in result
        assert counts["hostname"] == 1

    def test_corp_domain(self, matcher):
        content = "mail.company.corp is the mail server"
        result, counts = anonymize_content(content, matcher)
        assert "mail.company.corp" not in result
        assert counts["hostname"] == 1

    def test_lan_domain(self, matcher):
        content = "printer.office.lan is offline"
        result, counts = anonymize_content(content, matcher)
        assert "printer.office.lan" not in result
        assert counts["hostname"] == 1

    def test_intranet_domain(self, matcher):
        content = "portal.intranet has new content"
        result, counts = anonymize_content(content, matcher)
        assert "portal.intranet" not in result
        assert counts["hostname"] == 1

    def test_private_domain(self, matcher):
        content = "db.cluster.private connection failed"
        result, counts = anonymize_content(content, matcher)
        assert "db.cluster.private" not in result
        assert counts["hostname"] == 1


class TestMACAddressPattern:
    """Tests for MAC address detection."""

    def test_colon_format(self, matcher):
        content = "MAC: 00:1A:2B:3C:4D:5E"
        result, counts = anonymize_content(content, matcher)
        assert "00:1A:2B:3C:4D:5E" not in result
        assert "MAC_REDACTED" in result
        assert counts["mac_address"] == 1

    def test_hyphen_format(self, matcher):
        content = "Device: 00-1A-2B-3C-4D-5E"
        result, counts = anonymize_content(content, matcher)
        assert "00-1A-2B-3C-4D-5E" not in result
        assert counts["mac_address"] == 1

    def test_lowercase(self, matcher):
        content = "Interface mac: aa:bb:cc:dd:ee:ff"
        result, counts = anonymize_content(content, matcher)
        assert "aa:bb:cc:dd:ee:ff" not in result
        assert counts["mac_address"] == 1

    def test_multiple_macs(self, matcher):
        content = "Source: 11:22:33:44:55:66, Dest: AA:BB:CC:DD:EE:FF"
        result, counts = anonymize_content(content, matcher)
        assert "11:22:33:44:55:66" not in result
        assert "AA:BB:CC:DD:EE:FF" not in result
        assert counts["mac_address"] == 2


class TestUsernamePattern:
    """Tests for username detection in context."""

    def test_user_equals(self, matcher):
        content = "user=john.smith"
        result, counts = anonymize_content(content, matcher)
        assert "john.smith" not in result
        assert counts["username"] == 1

    def test_username_colon(self, matcher):
        content = "username: admin_user"
        result, counts = anonymize_content(content, matcher)
        assert "admin_user" not in result
        assert counts["username"] == 1

    def test_login_equals(self, matcher):
        content = "login=service_account"
        result, counts = anonymize_content(content, matcher)
        assert "service_account" not in result
        assert counts["username"] == 1

    def test_json_username(self, matcher):
        content = '{"username": "admin@domain.com"}'
        result, counts = anonymize_content(content, matcher)
        assert "admin@domain.com" not in result
        assert counts["username"] == 1

    def test_json_user(self, matcher):
        content = '{"user": "testuser123"}'
        result, counts = anonymize_content(content, matcher)
        assert "testuser123" not in result
        assert counts["username"] == 1


class TestPrivateKeyPattern:
    """Tests for private key detection."""

    def test_rsa_private_key(self, matcher):
        content = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
...key content...
-----END RSA PRIVATE KEY-----"""
        result, counts = anonymize_content(content, matcher)
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "PRIVATE_KEY_REDACTED" in result
        assert counts["private_key"] == 1

    def test_generic_private_key(self, matcher):
        content = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEA
-----END PRIVATE KEY-----"""
        result, counts = anonymize_content(content, matcher)
        assert "BEGIN PRIVATE KEY" not in result
        assert counts["private_key"] == 1

    def test_ec_private_key(self, matcher):
        content = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEICg7E4NN8vzbTaz3YM2NvCAqJxBCRQalEqCaLhAABBaCoAc
-----END EC PRIVATE KEY-----"""
        result, counts = anonymize_content(content, matcher)
        assert "BEGIN EC PRIVATE KEY" not in result
        assert counts["private_key"] == 1


class TestCertificatePattern:
    """Tests for certificate detection."""

    def test_certificate(self, matcher):
        content = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3
...cert content...
-----END CERTIFICATE-----"""
        result, counts = anonymize_content(content, matcher)
        assert "BEGIN CERTIFICATE" not in result
        assert "CERTIFICATE_REDACTED" in result
        assert counts["certificate"] == 1

    def test_multiple_certificates(self, matcher):
        content = """-----BEGIN CERTIFICATE-----
CERT1
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
CERT2
-----END CERTIFICATE-----"""
        result, counts = anonymize_content(content, matcher)
        assert counts["certificate"] == 2


class TestSSNPattern:
    """Tests for Social Security Number detection."""

    def test_standard_ssn(self, matcher):
        content = "SSN: 123-45-6789"
        result, counts = anonymize_content(content, matcher)
        assert "123-45-6789" not in result
        assert "SSN_REDACTED" in result
        assert counts["ssn"] == 1

    def test_ssn_in_text(self, matcher):
        content = "Employee SSN is 987-65-4321 on file"
        result, counts = anonymize_content(content, matcher)
        assert "987-65-4321" not in result
        assert counts["ssn"] == 1

    def test_multiple_ssns(self, matcher):
        content = "Records: 111-22-3333, 444-55-6666"
        result, counts = anonymize_content(content, matcher)
        assert "111-22-3333" not in result
        assert "444-55-6666" not in result
        assert counts["ssn"] == 2


class TestTableauEntityPattern:
    """Tests for Tableau-specific entity detection."""

    def test_site_equals(self, matcher):
        content = "site=CustomerSite"
        result, counts = anonymize_content(content, matcher)
        assert "CustomerSite" not in result
        assert counts["tableau_entity"] == 1

    def test_workbook_equals(self, matcher):
        content = "workbook=SalesReport2024"
        result, counts = anonymize_content(content, matcher)
        assert "SalesReport2024" not in result
        assert counts["tableau_entity"] == 1

    def test_datasource_colon(self, matcher):
        content = "datasource: FinanceData"
        result, counts = anonymize_content(content, matcher)
        assert "FinanceData" not in result
        assert counts["tableau_entity"] == 1

    def test_project_equals(self, matcher):
        content = "project=Marketing_Analytics"
        result, counts = anonymize_content(content, matcher)
        assert "Marketing_Analytics" not in result
        assert counts["tableau_entity"] == 1


class TestProcessSingleFile:
    """Tests for the file processing function."""

    def test_text_file_processing(self):
        filename = "test.log"
        content = b"user=admin password=secret123"
        result = process_single_file((filename, content))

        assert result.filename == filename
        assert b"admin" not in result.content
        assert b"secret123" not in result.content
        assert result.error is None

    def test_binary_file_passthrough(self):
        filename = "image.png"
        content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        result = process_single_file((filename, content))

        assert result.filename == filename
        assert result.content == content  # Unchanged
        assert result.replacements == {}

    def test_utf8_encoding(self):
        filename = "log.txt"
        content = "user=admin email=test@example.com".encode("utf-8")
        result = process_single_file((filename, content))

        assert b"admin" not in result.content
        assert b"@example.com" not in result.content

    def test_latin1_encoding(self):
        filename = "legacy.log"
        content = "user=admin café".encode("latin-1")
        result = process_single_file((filename, content))

        assert result.error is None


class TestEdgeCases:
    """Tests for edge cases and potential issues."""

    def test_empty_content(self, matcher):
        content = ""
        result, counts = anonymize_content(content, matcher)
        assert result == ""
        assert counts == {}

    def test_no_matches(self, matcher):
        content = "This is plain text with no sensitive data"
        result, counts = anonymize_content(content, matcher)
        assert result == content
        assert counts == {}

    def test_overlapping_patterns(self, matcher):
        """Test content that could match multiple patterns."""
        content = "user=admin@company.local password=secret123"
        result, counts = anonymize_content(content, matcher)
        # Should handle both username and potentially email-like patterns
        assert "admin@company.local" not in result
        assert "secret123" not in result

    def test_multiline_content(self, matcher):
        content = """Line 1: user=admin
Line 2: password=secret
Line 3: email=test@example.com"""
        result, counts = anonymize_content(content, matcher)
        assert "admin" not in result
        assert "secret" not in result
        assert "test@example.com" not in result

    def test_special_characters(self, matcher):
        """Test that regex special chars in content don't break patterns."""
        content = "user=admin$test password=(secret)"
        result, counts = anonymize_content(content, matcher)
        assert "(secret)" not in result

    def test_very_long_line(self, matcher):
        """Test performance with very long lines."""
        content = "email=" + "test@example.com " * 1000
        result, counts = anonymize_content(content, matcher)
        assert "@example.com" not in result
        assert counts["email"] == 1000


class TestOptimizedPatternMatcher:
    """Tests for the optimized pattern matcher."""

    @pytest.fixture
    def opt_matcher(self):
        from pattern_matcher_optimized import OptimizedPatternMatcher
        return OptimizedPatternMatcher()

    def test_content_may_have_matches_positive(self, opt_matcher):
        """Content with keywords should return True."""
        assert opt_matcher.content_may_have_matches("user=admin password=secret")
        assert opt_matcher.content_may_have_matches("email: test@example.com")
        assert opt_matcher.content_may_have_matches("Server=mydb.local")

    def test_content_may_have_matches_negative(self, opt_matcher):
        """Content without keywords should return False."""
        assert not opt_matcher.content_may_have_matches("hello world")
        assert not opt_matcher.content_may_have_matches("just some plain text")
        assert not opt_matcher.content_may_have_matches("numbers 12345")

    def test_get_applicable_patterns_filters(self, opt_matcher):
        """Should only return patterns whose keywords match."""
        # Line with password keyword
        patterns = opt_matcher.get_applicable_patterns("password=secret")
        pattern_names = [p.name for p in patterns]
        assert "password" in pattern_names
        assert "email" not in pattern_names

        # Line with email indicator
        patterns = opt_matcher.get_applicable_patterns("contact@example.com")
        pattern_names = [p.name for p in patterns]
        assert "email" in pattern_names

    def test_get_applicable_patterns_empty_for_plain(self, opt_matcher):
        """Plain text should have no applicable patterns."""
        patterns = opt_matcher.get_applicable_patterns("hello world")
        assert len(patterns) == 0


class TestOptimizedAnonymization:
    """Tests for optimized anonymization functions."""

    @pytest.fixture
    def opt_matcher(self):
        from pattern_matcher_optimized import OptimizedPatternMatcher
        return OptimizedPatternMatcher()

    def test_email_anonymization(self, opt_matcher):
        from pattern_matcher_optimized import anonymize_content_optimized
        content = "Contact: john@example.com"
        result, counts = anonymize_content_optimized(content, opt_matcher)
        assert "john@example.com" not in result
        assert "@redacted.com" in result
        assert counts.get("email", 0) >= 1

    def test_password_anonymization(self, opt_matcher):
        from pattern_matcher_optimized import anonymize_content_optimized
        content = "password=secret123"
        result, counts = anonymize_content_optimized(content, opt_matcher)
        assert "secret123" not in result
        assert "PASSWORD_REDACTED" in result

    def test_internal_ip_anonymization(self, opt_matcher):
        from pattern_matcher_optimized import anonymize_content_optimized
        content = "Server: 192.168.1.100"
        result, counts = anonymize_content_optimized(content, opt_matcher)
        assert "192.168.1.100" not in result
        assert counts.get("internal_ip", 0) >= 1

    def test_no_matches_passthrough(self, opt_matcher):
        from pattern_matcher_optimized import anonymize_content_optimized
        content = "Plain text without sensitive data"
        result, counts = anonymize_content_optimized(content, opt_matcher)
        assert result == content
        assert counts == {}

    def test_multiline_content(self, opt_matcher):
        from pattern_matcher_optimized import anonymize_content_optimized
        content = """Line 1: user=admin
Line 2: password=secret
Line 3: nothing here
Line 4: email=test@example.com"""
        result, counts = anonymize_content_optimized(content, opt_matcher)
        assert "admin" not in result
        assert "secret" not in result
        assert "test@example.com" not in result
        assert "nothing here" in result  # Unchanged

    def test_chunked_processing(self, opt_matcher):
        """Test chunked processing for large content."""
        from pattern_matcher_optimized import anonymize_content_chunked
        # Create large content
        content = ("user=admin password=secret\n" * 1000)
        result, counts = anonymize_content_chunked(content, opt_matcher, chunk_size=1000)
        assert "admin" not in result
        assert "secret" not in result
        assert counts.get("username", 0) >= 1000
        assert counts.get("password", 0) >= 1000

    def test_hybrid_small_content(self, opt_matcher):
        """Hybrid should use optimized for small content."""
        from pattern_matcher_optimized import anonymize_content_hybrid
        content = "user=admin password=secret"
        result, counts = anonymize_content_hybrid(content, opt_matcher)
        assert "admin" not in result
        assert "secret" not in result


class TestOptimizedVsOriginalParity:
    """Tests to ensure optimized produces same results as original."""

    @pytest.fixture
    def both_matchers(self):
        from anonymizer import PatternMatcher
        from pattern_matcher_optimized import OptimizedPatternMatcher
        return PatternMatcher(), OptimizedPatternMatcher()

    def test_email_parity(self, both_matchers):
        """Both implementations should anonymize emails."""
        from anonymizer import anonymize_content
        from pattern_matcher_optimized import anonymize_content_optimized

        orig_matcher, opt_matcher = both_matchers
        content = "Contact: test@example.com and other@domain.org"

        orig_result, orig_counts = anonymize_content(content, orig_matcher)
        opt_result, opt_counts = anonymize_content_optimized(content, opt_matcher)

        # Both should redact emails
        assert "@example.com" not in orig_result
        assert "@example.com" not in opt_result
        assert "@domain.org" not in orig_result
        assert "@domain.org" not in opt_result
        # Counts should match
        assert orig_counts.get("email", 0) == opt_counts.get("email", 0)

    def test_password_parity(self, both_matchers):
        """Both implementations should anonymize passwords."""
        from anonymizer import anonymize_content
        from pattern_matcher_optimized import anonymize_content_optimized

        orig_matcher, opt_matcher = both_matchers
        content = "password=secret123 passwd: hunter2"

        orig_result, orig_counts = anonymize_content(content, orig_matcher)
        opt_result, opt_counts = anonymize_content_optimized(content, opt_matcher)

        assert "secret123" not in orig_result
        assert "secret123" not in opt_result
        assert "hunter2" not in orig_result
        assert "hunter2" not in opt_result

    def test_internal_ip_parity(self, both_matchers):
        """Both implementations should anonymize internal IPs."""
        from anonymizer import anonymize_content
        from pattern_matcher_optimized import anonymize_content_optimized

        orig_matcher, opt_matcher = both_matchers
        content = "Server 10.0.0.1 and 192.168.1.100"

        orig_result, orig_counts = anonymize_content(content, orig_matcher)
        opt_result, opt_counts = anonymize_content_optimized(content, opt_matcher)

        assert "10.0.0.1" not in orig_result
        assert "10.0.0.1" not in opt_result
        assert "192.168.1.100" not in orig_result
        assert "192.168.1.100" not in opt_result
        assert orig_counts.get("internal_ip", 0) == opt_counts.get("internal_ip", 0)

    def test_mixed_content_parity(self, both_matchers):
        """Both should handle mixed sensitive data."""
        from anonymizer import anonymize_content
        from pattern_matcher_optimized import anonymize_content_optimized

        orig_matcher, opt_matcher = both_matchers
        content = """
        user=admin@company.local
        password=secret123
        Server=192.168.1.50
        jdbc:mysql://localhost:3306/db
        """

        orig_result, _ = anonymize_content(content, orig_matcher)
        opt_result, _ = anonymize_content_optimized(content, opt_matcher)

        # Both should redact sensitive data
        for sensitive in ["admin@company.local", "secret123", "192.168.1.50", "localhost:3306"]:
            assert sensitive not in orig_result, f"Original failed to redact: {sensitive}"
            assert sensitive not in opt_result, f"Optimized failed to redact: {sensitive}"


class TestPreFilteringEffectiveness:
    """Tests to verify pre-filtering reduces work."""

    @pytest.fixture
    def opt_matcher(self):
        from pattern_matcher_optimized import OptimizedPatternMatcher
        return OptimizedPatternMatcher()

    def test_plain_text_no_patterns_applied(self, opt_matcher):
        """Plain text should skip all pattern matching."""
        lines = [
            "This is plain text",
            "No sensitive data here",
            "Just regular log output",
        ]
        for line in lines:
            applicable = opt_matcher.get_applicable_patterns(line)
            assert len(applicable) == 0, f"Unexpected patterns for: {line}"

    def test_keyword_filtering_reduces_patterns(self, opt_matcher):
        """Lines with specific keywords should only match relevant patterns."""
        # Password line should not trigger email pattern
        pw_patterns = opt_matcher.get_applicable_patterns("password=test")
        pw_names = [p.name for p in pw_patterns]
        assert "password" in pw_names
        assert "email" not in pw_names

        # Email line should not trigger password pattern
        email_patterns = opt_matcher.get_applicable_patterns("user@example.com")
        email_names = [p.name for p in email_patterns]
        assert "email" in email_names
        assert "password" not in email_names


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
