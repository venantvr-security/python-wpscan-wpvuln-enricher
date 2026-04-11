#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests unitaires pour WPScan Parser.
"""

import json
import os
import sys
import tempfile

import pytest

from parser import (
    Finding,
    parse_wpscan_results,
    parse_version,
    parse_plugin,
    parse_theme,
    parse_user,
    parse_vulnerability,
    parse_config_backup,
    parse_db_export,
    parse_interesting,
    new_uuid,
    main as parser_main,
)


# =============================================================================
# Test Data: Sample WPScan JSON output
# =============================================================================

SAMPLE_WPSCAN_OUTPUT = """{
  "banner": {"description": "WordPress Security Scanner"},
  "start_time": 1712851200,
  "target_url": "https://example.com/",
  "target_ip": "93.184.216.34",
  "effective_url": "https://example.com/",
  "interesting_findings": [
    {
      "url": "https://example.com/readme.html",
      "to_s": "WordPress readme found: https://example.com/readme.html",
      "type": "readme",
      "interesting_entries": []
    }
  ],
  "version": {
    "number": "6.4.3",
    "status": "latest",
    "interesting_entries": [],
    "vulnerabilities": [],
    "found_by": "Meta Generator",
    "confidence": 100
  },
  "plugins": {
    "contact-form-7": {
      "slug": "contact-form-7",
      "location": "https://example.com/wp-content/plugins/contact-form-7/",
      "latest_version": "5.9.3",
      "outdated": true,
      "directory_listing": false,
      "vulnerabilities": [
        {
          "title": "Contact Form 7 < 5.8.4 - Reflected XSS",
          "fixed_in": "5.8.4",
          "references": {
            "cve": ["2024-12345"],
            "url": ["https://wpscan.com/vulnerability/cf7-xss"]
          },
          "cvss": {
            "score": 6.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
          }
        }
      ],
      "version": {
        "number": "5.8.0",
        "confidence": 80,
        "found_by": "Readme - Stable Tag"
      },
      "found_by": "Urls In Homepage",
      "confidence": 100
    },
    "elementor": {
      "slug": "elementor",
      "location": "https://example.com/wp-content/plugins/elementor/",
      "latest_version": "3.20.0",
      "outdated": false,
      "vulnerabilities": [],
      "version": {
        "number": "3.20.0",
        "confidence": 100
      }
    }
  },
  "themes": {
    "twentytwentyfour": {
      "slug": "twentytwentyfour",
      "location": "https://example.com/wp-content/themes/twentytwentyfour/",
      "latest_version": "1.0",
      "outdated": false,
      "style_name": "Twenty Twenty-Four",
      "style_uri": "https://wordpress.org/themes/twentytwentyfour/",
      "author": "the WordPress team",
      "vulnerabilities": [],
      "version": {
        "number": "1.0",
        "confidence": 100
      }
    }
  },
  "main_theme": {
    "slug": "twentytwentyfour",
    "style_name": "Twenty Twenty-Four"
  },
  "users": {
    "admin": {
      "id": 1,
      "slug": "admin",
      "description": "",
      "found_by": "Author Id Brute Forcing",
      "confidence": 100
    },
    "editor": {
      "id": 2,
      "slug": "editor",
      "found_by": "Wp Json Api",
      "confidence": 100
    }
  },
  "config_backups": [],
  "db_exports": [],
  "stop_time": 1712851260,
  "elapsed": 60.5,
  "requests_done": 1234
}"""

SAMPLE_WPSCAN_WITH_BACKUPS = """{
  "target_url": "https://vulnerable.com/",
  "effective_url": "https://vulnerable.com/",
  "interesting_findings": [],
  "version": {
    "number": "5.0.0",
    "status": "insecure",
    "vulnerabilities": [
      {
        "title": "WordPress 5.0.0 - RCE",
        "fixed_in": "5.0.1",
        "references": {"cve": ["2019-8942"]},
        "cvss": {"score": 9.8}
      }
    ]
  },
  "plugins": {},
  "themes": {},
  "users": {},
  "config_backups": [
    {"url": "https://vulnerable.com/wp-config.php.bak"}
  ],
  "db_exports": [
    {"url": "https://vulnerable.com/backup.sql"}
  ]
}"""


# =============================================================================
# Test: parse_wpscan_results function
# =============================================================================

class TestParseWPScanResults:
    """Test the main parse function."""

    def test_parse_basic(self):
        """Basic parsing should return findings."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        assert len(findings) > 0

    def test_parse_finding_count(self):
        """Should have: version + interesting + 2 plugins + 1 theme + 2 users."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        # At least 7 findings expected
        assert len(findings) >= 7

    def test_parse_categories(self):
        """All expected categories should be present."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        categories = {f["category"] for f in findings}

        expected = {
            "WordPress Version",
            "WordPress Plugin",
            "WordPress Theme",
            "WordPress User",
            "WordPress Interesting Finding",
        }
        for cat in expected:
            assert cat in categories, f"Missing category: {cat}"


class TestParseVersion:
    """Test version parsing."""

    def test_parse_latest_version(self):
        """Latest version should be INFORMATIONAL."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        version_findings = [f for f in findings if f["category"] == "WordPress Version"]

        assert len(version_findings) >= 1
        assert "6.4.3" in version_findings[0]["name"]
        assert version_findings[0]["severity"] == "INFORMATIONAL"

    def test_parse_insecure_version(self):
        """Insecure version should be HIGH."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_WITH_BACKUPS)
        version_findings = [f for f in findings if f["category"] == "WordPress Version"]

        assert len(version_findings) >= 1
        assert version_findings[0]["severity"] == "HIGH"

    def test_parse_version_with_vulnerabilities(self):
        """Vulnerabilities in version should create separate findings."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_WITH_BACKUPS)
        vuln_findings = [f for f in findings if f["category"] == "WordPress Vulnerability"]

        assert len(vuln_findings) >= 1


class TestParsePlugins:
    """Test plugin parsing."""

    def test_parse_plugin_count(self):
        """Should find 2 plugins."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        plugin_findings = [f for f in findings if f["category"] == "WordPress Plugin"]

        assert len(plugin_findings) == 2

    def test_parse_outdated_plugin(self):
        """Outdated plugin should have LOW severity."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        cf7_findings = [
            f for f in findings
            if f["category"] == "WordPress Plugin" and "contact-form-7" in f["name"]
        ]

        assert len(cf7_findings) == 1
        assert cf7_findings[0]["severity"] == "LOW"

    def test_parse_plugin_attributes(self):
        """Plugin attributes should be set correctly."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        cf7_findings = [
            f for f in findings
            if f["category"] == "WordPress Plugin" and "contact-form-7" in f["name"]
        ]

        assert cf7_findings[0]["attributes"]["slug"] == "contact-form-7"
        assert cf7_findings[0]["attributes"]["version"] == "5.8.0"

    def test_parse_plugin_vulnerabilities(self):
        """Plugin vulnerabilities should create separate findings."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        vuln_findings = [f for f in findings if f["category"] == "WordPress Vulnerability"]

        assert len(vuln_findings) >= 1


class TestParseUsers:
    """Test user parsing."""

    def test_parse_user_count(self):
        """Should find 2 users."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        user_findings = [f for f in findings if f["category"] == "WordPress User"]

        assert len(user_findings) == 2

    def test_parse_user_attributes(self):
        """User attributes should be correct."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        admin_findings = [
            f for f in findings
            if f["category"] == "WordPress User" and "admin" in f["name"]
        ]

        assert len(admin_findings) == 1
        assert admin_findings[0]["attributes"]["user_id"] == 1
        assert admin_findings[0]["attributes"]["username"] == "admin"


class TestParseThemes:
    """Test theme parsing."""

    def test_parse_theme_count(self):
        """Should find at least 1 theme."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        theme_findings = [f for f in findings if f["category"] == "WordPress Theme"]

        assert len(theme_findings) >= 1


class TestParseBackups:
    """Test backup parsing."""

    def test_parse_config_backup(self):
        """Config backup should be HIGH severity."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_WITH_BACKUPS)
        backup_findings = [
            f for f in findings
            if f["category"] == "WordPress Backup" and "Configuration" in f["name"]
        ]

        assert len(backup_findings) == 1
        assert backup_findings[0]["severity"] == "HIGH"

    def test_parse_db_export(self):
        """DB export should be HIGH severity."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_WITH_BACKUPS)
        db_findings = [
            f for f in findings
            if f["category"] == "WordPress Backup" and "Database" in f["name"]
        ]

        assert len(db_findings) == 1
        assert db_findings[0]["severity"] == "HIGH"


class TestParseInteresting:
    """Test interesting findings parsing."""

    def test_parse_interesting_count(self):
        """Should find at least 1 interesting finding."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)
        interesting_findings = [
            f for f in findings if f["category"] == "WordPress Interesting Finding"
        ]

        assert len(interesting_findings) >= 1


# =============================================================================
# Test: Error handling
# =============================================================================

class TestErrorHandling:
    """Test error handling."""

    def test_parse_invalid_json(self):
        """Invalid JSON should raise ValueError."""
        with pytest.raises(ValueError):
            parse_wpscan_results("not valid json")

    def test_parse_empty_json(self):
        """Empty JSON should return empty list."""
        findings = parse_wpscan_results("{}")
        assert findings == []


# =============================================================================
# Test: Finding structure
# =============================================================================

class TestFindingStructure:
    """Test Finding dataclass."""

    def test_finding_to_dict(self):
        """Finding should convert to dict correctly."""
        finding = Finding(
            id="test-uuid",
            name="Test Finding",
            description="A test",
            category="Test Category",
            location="https://example.com",
            severity="HIGH",
            attributes={"key": "value"},
        )

        d = finding.to_dict()
        assert d["id"] == "test-uuid"
        assert d["name"] == "Test Finding"
        assert d["severity"] == "HIGH"
        assert d["attributes"]["key"] == "value"

    def test_new_uuid_format(self):
        """UUID should be valid format."""
        uuid = new_uuid()
        assert len(uuid) == 36
        assert uuid.count("-") == 4


# =============================================================================
# Test: Main function
# =============================================================================

class TestMainFunction:
    """Test parser main function."""

    def test_main_with_file(self):
        """Main should read from READ_FILE and write to WRITE_FILE."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as infile:
            infile.write(SAMPLE_WPSCAN_OUTPUT)
            input_path = infile.name

        output_path = tempfile.mktemp(suffix=".json")

        try:
            os.environ["READ_FILE"] = input_path
            os.environ["WRITE_FILE"] = output_path

            result = parser_main()
            assert result == 0

            # Verify output
            with open(output_path, "r") as f:
                findings = json.load(f)
            assert len(findings) >= 7

        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)
            os.environ.pop("READ_FILE", None)
            os.environ.pop("WRITE_FILE", None)

    def test_main_missing_file(self):
        """Main should return 1 for missing file."""
        os.environ["READ_FILE"] = "/nonexistent/file.json"
        os.environ.pop("WRITE_FILE", None)

        try:
            result = parser_main()
            assert result == 1
        finally:
            os.environ.pop("READ_FILE", None)


# =============================================================================
# Test: Location extraction
# =============================================================================

class TestLocationExtraction:
    """Test location extraction."""

    def test_effective_url_used(self):
        """Findings should use effective_url as location."""
        findings = parse_wpscan_results(SAMPLE_WPSCAN_OUTPUT)

        # Most findings should have the effective_url
        for f in findings:
            if f["category"] not in ["WordPress Interesting Finding"]:
                assert f["location"] == "https://example.com/"


# =============================================================================
# Test: Vulnerability severity mapping
# =============================================================================

class TestVulnerabilitySeverity:
    """Test vulnerability severity mapping based on CVSS."""

    def test_critical_cvss(self):
        """CVSS >= 9.0 should be HIGH."""
        vuln = {
            "title": "Test",
            "cvss": {"score": 9.8}
        }
        finding = parse_vulnerability(vuln, "test", "https://example.com")
        assert finding.severity == "HIGH"

    def test_high_cvss(self):
        """CVSS >= 7.0 should be HIGH."""
        vuln = {
            "title": "Test",
            "cvss": {"score": 7.5}
        }
        finding = parse_vulnerability(vuln, "test", "https://example.com")
        assert finding.severity == "HIGH"

    def test_medium_cvss(self):
        """CVSS >= 4.0 should be MEDIUM."""
        vuln = {
            "title": "Test",
            "cvss": {"score": 5.0}
        }
        finding = parse_vulnerability(vuln, "test", "https://example.com")
        assert finding.severity == "MEDIUM"

    def test_low_cvss(self):
        """CVSS < 4.0 should be LOW."""
        vuln = {
            "title": "Test",
            "cvss": {"score": 2.5}
        }
        finding = parse_vulnerability(vuln, "test", "https://example.com")
        assert finding.severity == "LOW"

    def test_no_cvss(self):
        """No CVSS should default to MEDIUM."""
        vuln = {"title": "Test"}
        finding = parse_vulnerability(vuln, "test", "https://example.com")
        assert finding.severity == "MEDIUM"


# =============================================================================
# Test: is_parser_mode function
# =============================================================================

class TestIsParserMode:
    """Test is_parser_mode() function from main.py."""

    def test_parser_mode_env_var(self):
        """PARSER_MODE=true should enable parser mode."""
        from main import is_parser_mode

        os.environ["PARSER_MODE"] = "true"
        try:
            assert is_parser_mode() is True
        finally:
            os.environ.pop("PARSER_MODE", None)

    def test_parser_mode_default(self):
        """Default should be False."""
        from main import is_parser_mode

        os.environ.pop("PARSER_MODE", None)
        # Save and reset sys.argv
        old_argv = sys.argv
        sys.argv = ["test"]
        try:
            assert is_parser_mode() is False
        finally:
            sys.argv = old_argv

    def test_parser_mode_flag(self):
        """--parser flag should enable parser mode."""
        from main import is_parser_mode

        os.environ.pop("PARSER_MODE", None)
        old_argv = sys.argv
        sys.argv = ["test", "--parser"]
        try:
            assert is_parser_mode() is True
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
