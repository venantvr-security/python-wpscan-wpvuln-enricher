#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests unitaires pour WPScan WPVuln Enricher.
Port des 15 tests Go vers pytest.
"""

import json
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest
import requests

from main import (
    Finding,
    WPVulnResponse,
    WPVulnPlugin,
    WPVulnEntry,
    WPVulnOperator,
    WPVulnSource,
    WPVulnImpact,
    WPVulnCVSS,
    WPVulnCWE,
    extract_plugin_slugs,
    map_severity,
    vuln_to_finding,
    extract_location,
    check_api_health,
)


# =============================================================================
# Test data: Real WPVulnerability API response
# =============================================================================

SAMPLE_API_RESPONSE = """{
  "error": 0,
  "message": null,
  "data": {
    "name": "Contact Form 7",
    "plugin": "contact-form-7",
    "vulnerability": [
      {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "Contact Form 7 < 5.8.4 - Reflected XSS",
        "description": "The plugin does not sanitize input properly.",
        "operator": {
          "max_version": "5.8.4",
          "unfixed": "0"
        },
        "source": [
          {
            "id": "CVE-2024-12345",
            "name": "CVE",
            "link": "https://www.cve.org/CVERecord?id=CVE-2024-12345",
            "date": "2024-03-15"
          }
        ],
        "impact": {
          "cvss": {
            "score": "6.1",
            "severity": "MEDIUM"
          },
          "cwe": [
            {
              "cwe": "CWE-79",
              "name": "Cross-site Scripting"
            }
          ]
        }
      },
      {
        "uuid": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
        "name": "Contact Form 7 < 5.3.2 - Unrestricted File Upload",
        "description": "Allows malicious file uploads.",
        "operator": {
          "max_version": "5.3.2",
          "unfixed": "0"
        },
        "source": [
          {
            "id": "CVE-2020-35489",
            "name": "CVE",
            "link": "https://www.cve.org/CVERecord?id=CVE-2020-35489",
            "date": "2020-12-17"
          }
        ],
        "impact": {
          "cvss": {
            "score": "9.8",
            "severity": "CRITICAL"
          },
          "cwe": [
            {
              "cwe": "CWE-434",
              "name": "Unrestricted Upload"
            }
          ]
        }
      }
    ]
  }
}"""


# =============================================================================
# Test: API Response Parsing
# =============================================================================

class TestWPVulnResponseParsing:
    """Test 1: TestWPVulnResponseParsing"""

    def test_parse_api_response(self):
        """Verify JSON schema parsing."""
        data = json.loads(SAMPLE_API_RESPONSE)
        resp = WPVulnResponse.from_dict(data)

        assert resp.error == 0
        assert resp.data is not None
        assert resp.data.name == "Contact Form 7"
        assert len(resp.data.vulnerabilities) == 2


class TestVulnerabilityFieldMapping:
    """Test 2: TestVulnerabilityFieldMapping"""

    def test_vulnerability_field_mapping(self):
        """Check field extraction (UUID, CVE, CVSS)."""
        data = json.loads(SAMPLE_API_RESPONSE)
        resp = WPVulnResponse.from_dict(data)
        vuln = resp.data.vulnerabilities[0]

        # UUID
        assert vuln.uuid == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"

        # Name
        assert vuln.name == "Contact Form 7 < 5.8.4 - Reflected XSS"

        # Operator (fixed_in)
        assert vuln.operator.max_version == "5.8.4"

        # Sources (CVE)
        assert len(vuln.sources) == 1
        assert vuln.sources[0].id == "CVE-2024-12345"

        # Impact (CVSS)
        assert vuln.impact.has_data is True
        assert vuln.impact.cvss.severity == "MEDIUM"

        # CWE
        assert len(vuln.impact.cwes) == 1
        assert vuln.impact.cwes[0].cwe == "CWE-79"


# =============================================================================
# Test: Severity Mapping
# =============================================================================

class TestMapSeverity:
    """Tests 3-7: TestMapSeverity (various cases)"""

    def test_map_severity_critical(self):
        """Test 3: CRITICAL maps to HIGH."""
        entry = WPVulnEntry(
            impact=WPVulnImpact(
                cvss=WPVulnCVSS(severity="CRITICAL"),
                has_data=True
            )
        )
        assert map_severity(entry) == "HIGH"

    def test_map_severity_high(self):
        """Test 4: HIGH maps to HIGH."""
        entry = WPVulnEntry(
            impact=WPVulnImpact(
                cvss=WPVulnCVSS(severity="HIGH"),
                has_data=True
            )
        )
        assert map_severity(entry) == "HIGH"

    def test_map_severity_medium(self):
        """Test 5: MEDIUM maps to MEDIUM."""
        entry = WPVulnEntry(
            impact=WPVulnImpact(
                cvss=WPVulnCVSS(severity="MEDIUM"),
                has_data=True
            )
        )
        assert map_severity(entry) == "MEDIUM"

    def test_map_severity_low(self):
        """Test 6: LOW maps to LOW."""
        entry = WPVulnEntry(
            impact=WPVulnImpact(
                cvss=WPVulnCVSS(severity="LOW"),
                has_data=True
            )
        )
        assert map_severity(entry) == "LOW"

    def test_map_severity_empty(self):
        """Test 6b: Empty defaults to MEDIUM."""
        entry = WPVulnEntry(
            impact=WPVulnImpact(
                cvss=WPVulnCVSS(severity=""),
                has_data=True
            )
        )
        assert map_severity(entry) == "MEDIUM"

    def test_map_severity_unknown(self):
        """Test 6c: Unknown defaults to MEDIUM."""
        entry = WPVulnEntry(
            impact=WPVulnImpact(
                cvss=WPVulnCVSS(severity="UNKNOWN"),
                has_data=True
            )
        )
        assert map_severity(entry) == "MEDIUM"

    def test_map_severity_no_impact(self):
        """Test 7: TestMapSeverityNoImpact - default handling."""
        entry = WPVulnEntry(impact=WPVulnImpact(has_data=False))
        assert map_severity(entry) == "MEDIUM"


# =============================================================================
# Test: vulnToFinding Conversion
# =============================================================================

class TestVulnToFinding:
    """Tests 8-9: TestVulnToFinding"""

    def test_vuln_to_finding(self):
        """Test 8: Full conversion."""
        entry = WPVulnEntry(
            uuid="test-uuid-123",
            name="Test Vuln - XSS",
            description="A test vulnerability",
            operator=WPVulnOperator(max_version="1.2.3", unfixed="0"),
            sources=[
                WPVulnSource(id="CVE-2024-99999", name="CVE", link="https://cve.org/CVE-2024-99999")
            ],
            impact=WPVulnImpact(
                cvss=WPVulnCVSS(score="7.5", severity="HIGH"),
                cwes=[WPVulnCWE(cwe="CWE-79", name="XSS")],
                has_data=True
            )
        )

        finding = vuln_to_finding("test-plugin", "Test Plugin", entry, "https://example.com")

        # Verify basic fields
        assert finding.category == "WordPress Plugin Vulnerability"
        assert finding.location == "https://example.com"
        assert finding.severity == "HIGH"
        assert finding.osi_layer == "APPLICATION"

        # Verify attributes
        assert finding.attributes["plugin_slug"] == "test-plugin"
        assert finding.attributes["fixed_in"] == "1.2.3"
        assert finding.attributes["cvss_score"] == "7.5"

        # Verify CVE extraction
        cves = finding.attributes.get("cve")
        assert cves is not None
        assert len(cves) == 1
        assert cves[0] == "CVE-2024-99999"

        # Verify CWE extraction
        cwes = finding.attributes.get("cwe")
        assert cwes is not None
        assert len(cwes) == 1
        assert cwes[0] == "CWE-79"

    def test_vuln_to_finding_unfixed(self):
        """Test 9: Unfixed vulnerability handling."""
        entry = WPVulnEntry(
            uuid="unfixed-uuid",
            name="Unfixed Vuln",
            operator=WPVulnOperator(max_version="99.0.0", unfixed="1"),
        )

        finding = vuln_to_finding("plugin", "Plugin", entry, "https://example.com")

        # fixed_in should not be set for unfixed vulnerabilities
        assert "fixed_in" not in finding.attributes


# =============================================================================
# Test: Plugin Slug Extraction from WPScan
# =============================================================================

class TestExtractPluginSlugs:
    """Tests 10-12: TestExtractPluginSlugs"""

    def test_extract_plugin_slugs(self):
        """Test 10: Basic extraction."""
        findings = [
            Finding(
                id="1",
                name="Plugin: contact-form-7",
                description="",
                category="WordPress Plugin",
                location="",
                osi_layer="",
                severity="",
                attributes={"slug": "contact-form-7"},
            ),
            Finding(
                id="2",
                name="Plugin: elementor",
                description="",
                category="WordPress Plugin",
                location="",
                osi_layer="",
                severity="",
                attributes={"plugin": "elementor"},
            ),
            Finding(
                id="3",
                name="Plugin: yoast-seo",
                description="",
                category="WordPress Plugin",
                location="",
                osi_layer="",
                severity="",
                attributes={},  # slug from name
            ),
            Finding(
                id="4",
                name="WordPress Core",
                description="",
                category="WordPress Core",  # Should be ignored
                location="",
                osi_layer="",
                severity="",
                attributes={},
            ),
        ]

        slugs = extract_plugin_slugs(findings)

        assert len(slugs) == 3
        expected = {"contact-form-7", "elementor", "yoast-seo"}
        for slug in slugs:
            assert slug in expected

    def test_extract_plugin_slugs_case_insensitive(self):
        """Test 11: Case handling."""
        findings = [
            Finding(
                id="1",
                name="Plugin: Test",
                description="",
                category="wordpress plugin",  # lowercase
                location="",
                osi_layer="",
                severity="",
                attributes={"slug": "TEST"},  # uppercase
            ),
        ]

        slugs = extract_plugin_slugs(findings)
        assert len(slugs) == 1
        assert slugs[0] == "test"

    def test_extract_plugin_slugs_dedup(self):
        """Test 12: Deduplication."""
        findings = [
            Finding(
                id="1", name="", description="", category="WordPress Plugin",
                location="", osi_layer="", severity="",
                attributes={"slug": "test"},
            ),
            Finding(
                id="2", name="", description="", category="WordPress Plugin",
                location="", osi_layer="", severity="",
                attributes={"slug": "test"},
            ),
            Finding(
                id="3", name="", description="", category="WordPress Plugin",
                location="", osi_layer="", severity="",
                attributes={"slug": "TEST"},
            ),
        ]

        slugs = extract_plugin_slugs(findings)
        assert len(slugs) == 1


# =============================================================================
# Test: API Version Check (Integration)
# =============================================================================

class TestCheckAPIHealth:
    """Tests 13: TestCheckAPIVersionMock"""

    @patch('main.requests.get')
    def test_check_api_health_success(self, mock_get):
        """Test 13: API response parsing."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"error": 0, "data": None}
        mock_get.return_value = mock_response

        # Should not raise
        check_api_health()

    @patch('main.requests.get')
    def test_check_api_health_deprecated(self, mock_get):
        """Test 13b: 410 handling."""
        mock_response = MagicMock()
        mock_response.status_code = 410
        mock_get.return_value = mock_response

        with pytest.raises(SystemExit) as exc_info:
            check_api_health()
        assert "410" in str(exc_info.value) or "DEPRECATED" in str(exc_info.value)


# =============================================================================
# Test: Extract Location
# =============================================================================

class TestExtractLocation:
    """Tests 14-15: TestExtractLocation"""

    def test_extract_location(self):
        """Test 14: Location extraction."""
        findings = [
            Finding(
                id="1", name="", description="", category="",
                location="", osi_layer="", severity="", attributes={}
            ),
            Finding(
                id="2", name="", description="", category="",
                location="https://example.com", osi_layer="", severity="", attributes={}
            ),
        ]
        assert extract_location(findings) == "https://example.com"

    def test_extract_location_empty(self):
        """Test 15: Default 'unknown' handling."""
        findings = [
            Finding(
                id="1", name="", description="", category="",
                location="", osi_layer="", severity="", attributes={}
            ),
        ]
        assert extract_location(findings) == "unknown"


# =============================================================================
# Test: Full Pipeline (E2E)
# =============================================================================

class TestFullPipelineE2E:
    """Test: Full Pipeline E2E with mock data."""

    def test_full_pipeline_e2e(self):
        """End-to-end integration test."""
        # Create temp input file
        input_findings = """[{
            "id": "test-1",
            "name": "Plugin: contact-form-7",
            "description": "",
            "category": "WordPress Plugin",
            "location": "https://test.com",
            "osi_layer": "",
            "severity": "",
            "attributes": {"slug": "contact-form-7"},
            "false_positive": false
        }]"""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write(input_findings)
            input_file = f.name

        try:
            # Read and parse
            with open(input_file, 'r') as f:
                data = json.load(f)
            findings = [Finding.from_dict(fd) for fd in data]

            # Extract slugs
            slugs = extract_plugin_slugs(findings)
            assert len(slugs) == 1
            assert slugs[0] == "contact-form-7"

            # Simulate API call (using our mock response)
            resp_data = json.loads(SAMPLE_API_RESPONSE)
            resp = WPVulnResponse.from_dict(resp_data)

            # Convert to findings
            enriched = []
            for vuln in resp.data.vulnerabilities:
                enriched.append(vuln_to_finding(
                    "contact-form-7", resp.data.name, vuln, "https://test.com"
                ))

            assert len(enriched) == 2

            # Verify first finding
            f = enriched[0]
            assert f.severity == "MEDIUM"
            assert f.attributes["fixed_in"] == "5.8.4"

        finally:
            os.unlink(input_file)


# =============================================================================
# Test: WPVulnImpact flexible parsing
# =============================================================================

class TestWPVulnImpactFlexible:
    """Test flexible impact parsing (handles [], null, object)."""

    def test_impact_empty_array(self):
        """Impact as empty array []."""
        impact = WPVulnImpact.from_dict([])
        assert impact.has_data is False

    def test_impact_null(self):
        """Impact as null."""
        impact = WPVulnImpact.from_dict(None)
        assert impact.has_data is False

    def test_impact_valid_object(self):
        """Impact as valid object."""
        data = {
            "cvss": {"score": "7.5", "severity": "HIGH"},
            "cwe": [{"cwe": "CWE-79", "name": "XSS"}]
        }
        impact = WPVulnImpact.from_dict(data)
        assert impact.has_data is True
        assert impact.cvss.score == "7.5"
        assert impact.cvss.severity == "HIGH"
        assert len(impact.cwes) == 1
        assert impact.cwes[0].cwe == "CWE-79"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
