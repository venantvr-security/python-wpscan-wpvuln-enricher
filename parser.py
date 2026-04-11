#!/usr/bin/env python3
"""
WPScan Parser pour secureCodeBox

Ce parser convertit la sortie JSON brute de WPScan en format Finding secureCodeBox.

Usage:
    READ_FILE=/path/to/wpscan-results.json WRITE_FILE=/path/to/findings.json python parser.py

Ou en mode stdin/stdout:
    cat wpscan-results.json | python parser.py > findings.json
"""

import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

VERSION = "1.0.0"


# =============================================================================
# STRUCTURES DE DONNÉES
# =============================================================================

@dataclass
class Finding:
    """Représente un finding au format secureCodeBox"""
    id: str
    name: str
    description: str
    category: str
    location: str
    osi_layer: str = "APPLICATION"
    severity: str = "INFORMATIONAL"
    attributes: dict = field(default_factory=dict)
    false_positive: bool = False

    def to_dict(self) -> dict:
        """Convertit en dictionnaire pour JSON"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "location": self.location,
            "osi_layer": self.osi_layer,
            "severity": self.severity,
            "attributes": self.attributes,
            "false_positive": self.false_positive,
        }


def new_uuid() -> str:
    """Génère un UUID v4"""
    return str(uuid.uuid4())


# =============================================================================
# PARSING DES DIFFÉRENTS ÉLÉMENTS
# =============================================================================

def parse_version(version_data: dict, location: str) -> list[Finding]:
    """Parse la version WordPress détectée"""
    findings = []

    if not version_data:
        return findings

    number = version_data.get("number", "unknown")
    status = version_data.get("status", "unknown")

    # Déterminer la sévérité
    if status == "insecure":
        severity = "HIGH"
    elif status == "outdated":
        severity = "MEDIUM"
    else:
        severity = "INFORMATIONAL"

    findings.append(Finding(
        id=new_uuid(),
        name=f"WordPress Version {number}",
        description=f"WordPress version {number} detected (status: {status})",
        category="WordPress Version",
        location=location,
        severity=severity,
        attributes={
            "version": number,
            "status": status,
            "found_by": version_data.get("found_by", ""),
            "confidence": version_data.get("confidence", 0),
        }
    ))

    # Vulnérabilités de la version
    for vuln in version_data.get("vulnerabilities", []):
        findings.append(parse_vulnerability(vuln, "WordPress Core", location))

    return findings


def parse_interesting(item: dict, location: str) -> Finding:
    """Parse un finding intéressant"""
    return Finding(
        id=new_uuid(),
        name=item.get("to_s", "Interesting Finding"),
        description=f"Interesting finding: {item.get('to_s', '')}",
        category="WordPress Interesting Finding",
        location=item.get("url", location),
        severity="INFORMATIONAL",
        attributes={
            "type": item.get("type", ""),
            "interesting_entries": item.get("interesting_entries", []),
        }
    )


def parse_plugin(slug: str, plugin_data: dict, location: str) -> list[Finding]:
    """Parse un plugin détecté"""
    findings = []

    # Info du plugin
    version_info = plugin_data.get("version", {})
    version_num = version_info.get("number", "") if version_info else ""
    outdated = plugin_data.get("outdated", False)

    severity = "INFORMATIONAL"
    desc = f"Plugin {slug} detected"

    if version_num:
        desc = f"Plugin {slug} version {version_num} detected"
    if outdated:
        severity = "LOW"
        desc += " (outdated)"

    attrs = {
        "slug": slug,
        "plugin": slug,
        "location": plugin_data.get("location", ""),
    }

    if version_num:
        attrs["version"] = version_num
        attrs["confidence"] = version_info.get("confidence", 0)

    if plugin_data.get("latest_version"):
        attrs["latest_version"] = plugin_data["latest_version"]

    if plugin_data.get("directory_listing"):
        attrs["directory_listing"] = True

    findings.append(Finding(
        id=new_uuid(),
        name=f"Plugin: {slug}",
        description=desc,
        category="WordPress Plugin",
        location=location,
        severity=severity,
        attributes=attrs,
    ))

    # Vulnérabilités du plugin
    for vuln in plugin_data.get("vulnerabilities", []):
        findings.append(parse_vulnerability(vuln, slug, location))

    return findings


def parse_theme(slug: str, theme_data: dict, location: str) -> list[Finding]:
    """Parse un thème détecté"""
    findings = []

    if not slug:
        slug = theme_data.get("style_name", "")
    if not slug:
        return findings

    version_info = theme_data.get("version", {})
    version_num = version_info.get("number", "") if version_info else ""
    outdated = theme_data.get("outdated", False)

    severity = "INFORMATIONAL"
    desc = f"Theme {slug} detected"

    if version_num:
        desc = f"Theme {slug} version {version_num} detected"
    if outdated:
        severity = "LOW"
        desc += " (outdated)"

    attrs = {
        "slug": slug,
        "location": theme_data.get("location", ""),
    }

    if version_num:
        attrs["version"] = version_num
    if theme_data.get("author"):
        attrs["author"] = theme_data["author"]

    findings.append(Finding(
        id=new_uuid(),
        name=f"Theme: {slug}",
        description=desc,
        category="WordPress Theme",
        location=location,
        severity=severity,
        attributes=attrs,
    ))

    # Vulnérabilités du thème
    for vuln in theme_data.get("vulnerabilities", []):
        findings.append(parse_vulnerability(vuln, slug, location))

    return findings


def parse_user(username: str, user_data: dict, location: str) -> Finding:
    """Parse un utilisateur détecté"""
    user_id = user_data.get("id", 0)

    return Finding(
        id=new_uuid(),
        name=f"User: {username}",
        description=f"WordPress user '{username}' enumerated (ID: {user_id})",
        category="WordPress User",
        location=location,
        severity="INFORMATIONAL",
        attributes={
            "username": username,
            "user_id": user_id,
            "slug": user_data.get("slug", ""),
            "found_by": user_data.get("found_by", ""),
            "confidence": user_data.get("confidence", 0),
        }
    )


def parse_vulnerability(vuln: dict, component: str, location: str) -> Finding:
    """Parse une vulnérabilité"""
    cvss = vuln.get("cvss", {})
    cvss_score = cvss.get("score", 0) if cvss else 0

    # Déterminer la sévérité
    if cvss_score >= 9.0:
        severity = "HIGH"
    elif cvss_score >= 7.0:
        severity = "HIGH"
    elif cvss_score >= 4.0:
        severity = "MEDIUM"
    elif cvss_score > 0:
        severity = "LOW"
    else:
        severity = "MEDIUM"  # Par défaut si pas de CVSS

    title = vuln.get("title", "Unknown Vulnerability")
    fixed_in = vuln.get("fixed_in", "")

    desc = title
    if fixed_in:
        desc += f" (fixed in {fixed_in})"

    refs = vuln.get("references", {})

    attrs = {
        "component": component,
        "title": title,
    }

    if fixed_in:
        attrs["fixed_in"] = fixed_in
    if refs.get("cve"):
        attrs["cve"] = refs["cve"]
    if refs.get("url"):
        attrs["references"] = refs["url"]
    if refs.get("wpvulndb"):
        attrs["wpvulndb"] = refs["wpvulndb"]
    if cvss:
        attrs["cvss_score"] = cvss_score
        if cvss.get("vector"):
            attrs["cvss_vector"] = cvss["vector"]

    return Finding(
        id=new_uuid(),
        name=f"[Vulnerability] {component} — {title}",
        description=desc,
        category="WordPress Vulnerability",
        location=location,
        severity=severity,
        attributes=attrs,
    )


def parse_config_backup(backup: dict, location: str) -> Finding:
    """Parse un fichier de backup de configuration"""
    url = backup.get("url", location)

    return Finding(
        id=new_uuid(),
        name="Configuration Backup Found",
        description=f"WordPress configuration backup file found at {url}",
        category="WordPress Backup",
        location=url,
        severity="HIGH",
        attributes={
            "type": "config_backup",
            "url": url,
        }
    )


def parse_db_export(export: dict, location: str) -> Finding:
    """Parse un export de base de données"""
    url = export.get("url", location)

    return Finding(
        id=new_uuid(),
        name="Database Export Found",
        description=f"WordPress database export file found at {url}",
        category="WordPress Backup",
        location=url,
        severity="HIGH",
        attributes={
            "type": "db_export",
            "url": url,
        }
    )


# =============================================================================
# FONCTION PRINCIPALE DE PARSING
# =============================================================================

def parse_wpscan_results(raw_json: str) -> list[dict]:
    """
    Parse la sortie JSON brute de WPScan en findings secureCodeBox.

    Args:
        raw_json: JSON brut de WPScan

    Returns:
        Liste de findings au format dict
    """
    try:
        result = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    findings: list[Finding] = []

    # Déterminer l'URL de base
    location = result.get("effective_url") or result.get("target_url", "unknown")

    # 1. Version WordPress
    if result.get("version"):
        findings.extend(parse_version(result["version"], location))

    # 2. Interesting Findings
    for item in result.get("interesting_findings", []):
        findings.append(parse_interesting(item, location))

    # 3. Plugins
    for slug, plugin_data in result.get("plugins", {}).items():
        findings.extend(parse_plugin(slug, plugin_data, location))

    # 4. Themes
    for slug, theme_data in result.get("themes", {}).items():
        findings.extend(parse_theme(slug, theme_data, location))

    # 5. Main Theme
    if result.get("main_theme"):
        main_theme = result["main_theme"]
        slug = main_theme.get("slug", main_theme.get("style_name", ""))
        findings.extend(parse_theme(slug, main_theme, location))

    # 6. Users
    for username, user_data in result.get("users", {}).items():
        findings.append(parse_user(username, user_data, location))

    # 7. Config Backups
    for backup in result.get("config_backups", []):
        findings.append(parse_config_backup(backup, location))

    # 8. DB Exports
    for export in result.get("db_exports", []):
        findings.append(parse_db_export(export, location))

    # Convertir en dicts
    return [f.to_dict() for f in findings]


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

def main():
    """Point d'entrée du parser"""
    logger.info(f"WPScan Parser v{VERSION} starting...")

    # Lire l'entrée
    read_file = os.environ.get("READ_FILE", "")

    try:
        if read_file:
            logger.info(f"Reading from file: {read_file}")
            with open(read_file, "r", encoding="utf-8") as f:
                raw_json = f.read()
        else:
            logger.info("Reading from stdin...")
            raw_json = sys.stdin.read()

        if not raw_json.strip():
            raise ValueError("Empty input")

        # Parser
        logger.info("Parsing WPScan results...")
        findings = parse_wpscan_results(raw_json)
        logger.info(f"Generated {len(findings)} finding(s)")

        # Écrire la sortie
        output = json.dumps(findings, indent=2, ensure_ascii=False)

        write_file = os.environ.get("WRITE_FILE", "")
        if write_file:
            logger.info(f"Writing to file: {write_file}")
            with open(write_file, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)

        logger.info("Parser completed successfully")
        return 0

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1
    except ValueError as e:
        logger.error(f"Parse error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
