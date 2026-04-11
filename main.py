#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Package main - Point d'entrée de l'application
Ce programme est un "hook" secureCodeBox qui enrichit les résultats de WPScan
avec des données de vulnérabilités provenant de l'API WPVulnerability.

Flux de données:
  WPScan findings (JSON) -> Extraction des plugins -> API WPVulnerability -> Findings enrichis
"""

# =============================================================================
# IMPORTS
# En Python, on importe les modules nécessaires au début du fichier.
# On utilise principalement la bibliothèque standard + requests pour HTTP.
# =============================================================================
from __future__ import annotations

import json
import logging
import os
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

# =============================================================================
# CONFIGURATION DU LOGGING
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y/%m/%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION & CONSTANTES
# Les constantes sont définies en majuscules par convention Python.
# =============================================================================

# Version de cet enrichisseur - à incrémenter à chaque release
VERSION = "1.0.0"

# Version de l'API WPVulnerability avec laquelle ce code est compatible
# Si l'API change, ce code pourrait ne plus fonctionner
API_VERSION = "2024-01"

# URL de base pour récupérer les vulnérabilités d'un plugin
# Usage: WPVULN_BASE_URL + "contact-form-7" -> vulnérabilités du plugin
WPVULN_BASE_URL = "https://www.wpvulnerability.net/plugin/"

# URL pour vérifier que l'API est accessible et compatible
# On utilise un plugin connu (updraftplus) pour le health check
WPVULN_HEALTH_URL = "https://www.wpvulnerability.net/plugin/updraftplus"

# Nombre maximum de tentatives pour une requête HTTP
MAX_RETRIES = 3

# Délai entre chaque tentative en cas d'échec (en secondes)
RETRY_DELAY = 2

# Timeout pour les requêtes HTTP (évite de bloquer indéfiniment)
REQUEST_TIMEOUT = 15


# =============================================================================
# STRUCTURES DE DONNÉES - Format secureCodeBox
# En Python, on utilise des dataclasses pour représenter des objets JSON.
# =============================================================================

@dataclass
class Finding:
    """
    Représente un résultat de scan au format secureCodeBox.
    C'est le format standard utilisé par tous les scanners et hooks secureCodeBox.
    Documentation: https://www.securecodebox.io/docs/api/finding
    """
    # ID unique du finding (UUID v4)
    id: str

    # Nom court et descriptif du finding
    name: str

    # Description détaillée de la vulnérabilité
    description: str

    # Catégorie du finding (ex: "WordPress Plugin", "WordPress Plugin Vulnerability")
    category: str

    # URL ou chemin où la vulnérabilité a été trouvée
    location: str

    # Couche OSI concernée (généralement "APPLICATION" pour les vulnérabilités web)
    osi_layer: str

    # Niveau de sévérité: "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
    severity: str

    # Attributs supplémentaires (CVE, version, etc.)
    attributes: dict[str, Any]

    # Indique si c'est un faux positif
    false_positive: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convertit en dictionnaire pour sérialisation JSON."""
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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Crée un Finding depuis un dictionnaire (parsing JSON)."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            category=data.get("category", ""),
            location=data.get("location", ""),
            osi_layer=data.get("osi_layer", ""),
            severity=data.get("severity", ""),
            attributes=data.get("attributes", {}),
            false_positive=data.get("false_positive", False),
        )


# =============================================================================
# STRUCTURES DE DONNÉES - Format API WPVulnerability
# Ces structures correspondent exactement au JSON retourné par l'API.
# Documentation: https://www.wpvulnerability.net/api/plugins/
# =============================================================================

@dataclass
class WPVulnCVSS:
    """Contient le score CVSS."""
    # Score numérique (ex: "6.1", "9.8")
    score: str = ""

    # Sévérité textuelle: "CRITICAL", "HIGH", "MEDIUM", "LOW"
    severity: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> WPVulnCVSS:
        """Crée depuis un dictionnaire."""
        if not data:
            return cls()
        return cls(
            score=data.get("score", ""),
            severity=data.get("severity", ""),
        )


@dataclass
class WPVulnCWE:
    """Représente une faiblesse CWE (Common Weakness Enumeration)."""
    # Identifiant CWE (ex: "CWE-79" pour XSS)
    cwe: str = ""

    # Nom de la faiblesse
    name: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WPVulnCWE:
        """Crée depuis un dictionnaire."""
        return cls(
            cwe=data.get("cwe", ""),
            name=data.get("name", ""),
        )


@dataclass
class WPVulnImpact:
    """
    Gère l'inconsistance de l'API où "impact" peut être:
    - Un objet: {"cvss": {...}, "cwe": [...]}
    - Un tableau vide: []
    - Un tableau d'objets: [{"cwe": "...", ...}]
    """
    # Score CVSS (Common Vulnerability Scoring System)
    cvss: WPVulnCVSS = field(default_factory=WPVulnCVSS)

    # Faiblesses CWE associées
    cwes: list[WPVulnCWE] = field(default_factory=list)

    # Indique si des données d'impact sont présentes
    has_data: bool = False

    @classmethod
    def from_dict(cls, data: Any) -> WPVulnImpact:
        """
        Parse l'impact depuis les données JSON.
        Gère les différents formats possibles de l'API.
        """
        # Cas 1: Tableau vide [] ou null/None
        if data is None or data == [] or data == "null":
            return cls(has_data=False)

        # Cas 2: Objet valide
        if isinstance(data, dict):
            cvss = WPVulnCVSS.from_dict(data.get("cvss"))
            cwes = [WPVulnCWE.from_dict(c) for c in data.get("cwe", [])]
            return cls(cvss=cvss, cwes=cwes, has_data=True)

        # Cas 3: Tableau d'objets (rare, on ignore)
        return cls(has_data=False)


@dataclass
class WPVulnSource:
    """Représente une source externe (CVE, JVNDB, etc.)."""
    # Identifiant (ex: "CVE-2024-12345")
    id: str = ""

    # Type de source (ex: "CVE", "JVNDB")
    name: str = ""

    # Lien vers la source
    link: str = ""

    # Date de publication (format YYYY-MM-DD)
    date: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WPVulnSource:
        """Crée depuis un dictionnaire."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            link=data.get("link", ""),
            date=data.get("date", ""),
        )


@dataclass
class WPVulnOperator:
    """Indique quelles versions sont vulnérables."""
    # Version maximum affectée (la vulnérabilité est corrigée dans cette version)
    max_version: str = ""

    # "1" si la vulnérabilité n'est pas encore corrigée, "0" sinon
    unfixed: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> WPVulnOperator:
        """Crée depuis un dictionnaire."""
        if not data:
            return cls()
        return cls(
            max_version=data.get("max_version", ""),
            unfixed=data.get("unfixed", ""),
        )


@dataclass
class WPVulnEntry:
    """Représente une vulnérabilité individuelle."""
    # Identifiant unique de la vulnérabilité dans WPVulnerability
    uuid: str = ""

    # Titre de la vulnérabilité (ex: "Contact Form 7 < 5.8.4 - Reflected XSS")
    name: str = ""

    # Description détaillée (peut être vide)
    description: str = ""

    # Informations sur les versions affectées
    operator: WPVulnOperator = field(default_factory=WPVulnOperator)

    # Sources externes (CVE, JVNDB, etc.)
    sources: list[WPVulnSource] = field(default_factory=list)

    # Informations d'impact (CVSS, CWE)
    impact: WPVulnImpact = field(default_factory=WPVulnImpact)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WPVulnEntry:
        """Crée depuis un dictionnaire."""
        return cls(
            uuid=data.get("uuid", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            operator=WPVulnOperator.from_dict(data.get("operator")),
            sources=[WPVulnSource.from_dict(s) for s in data.get("source", [])],
            impact=WPVulnImpact.from_dict(data.get("impact")),
        )


@dataclass
class WPVulnPlugin:
    """Contient les informations d'un plugin WordPress."""
    # Nom affiché du plugin (ex: "Contact Form 7")
    name: str = ""

    # Slug du plugin (ex: "contact-form-7") - identifiant unique
    plugin: str = ""

    # Liste des vulnérabilités connues pour ce plugin
    vulnerabilities: list[WPVulnEntry] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WPVulnPlugin:
        """Crée depuis un dictionnaire."""
        return cls(
            name=data.get("name", ""),
            plugin=data.get("plugin", ""),
            # Note: le champ JSON s'appelle "vulnerability" (singulier) mais c'est un tableau
            vulnerabilities=[WPVulnEntry.from_dict(v) for v in data.get("vulnerability", [])],
        )


@dataclass
class WPVulnResponse:
    """Enveloppe de la réponse API."""
    # Code d'erreur: 0 = succès, autre = erreur
    error: int = 0

    # Message d'erreur (si Error != 0)
    message: str = ""

    # Données du plugin (None si erreur ou plugin non trouvé)
    data: Optional[WPVulnPlugin] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WPVulnResponse:
        """Crée depuis un dictionnaire."""
        plugin_data = data.get("data")
        return cls(
            error=data.get("error", 0),
            message=data.get("message") or "",
            data=WPVulnPlugin.from_dict(plugin_data) if plugin_data else None,
        )


# =============================================================================
# VÉRIFICATION DE SANTÉ DE L'API
# Appelée au démarrage pour détecter rapidement si l'API est indisponible ou dépréciée.
# =============================================================================

def check_api_health() -> None:
    """
    Vérifie que l'API WPVulnerability est accessible et compatible.
    Lève une exception si:
    - L'API retourne 410 Gone (dépréciée)
    - La structure de réponse a changé (incompatible)
    - L'API est inaccessible
    """
    # Afficher la version au démarrage
    logger.info(f"WPVuln Enricher v{VERSION} (API version: {API_VERSION})")
    logger.info("Checking WPVulnerability API health...")

    try:
        # Faire une requête GET vers l'endpoint de test
        response = requests.get(WPVULN_HEALTH_URL, timeout=REQUEST_TIMEOUT)

        # 410 Gone = L'API a été retirée ou cette version n'est plus supportée
        if response.status_code == 410:
            raise SystemExit(
                f"API DEPRECATED: WPVulnerability API returned 410 Gone. "
                f"This enricher version ({VERSION}) is no longer compatible. "
                "Please update to a newer version"
            )

        # 404 peut indiquer que l'endpoint a changé
        if response.status_code == 404:
            logger.warning("API endpoint may have changed (404). Proceeding with caution...")
            return

        # Tout autre code que 200 est suspect
        if response.status_code != 200:
            raise SystemExit(f"API health check returned unexpected status: {response.status_code}")

        # Essayer de parser la réponse avec notre structure
        # Si ça échoue, c'est que le schéma JSON a changé
        try:
            data = response.json()
            test_resp = WPVulnResponse.from_dict(data)
        except (json.JSONDecodeError, Exception) as e:
            raise SystemExit(
                f"API SCHEMA CHANGED: Cannot parse response. "
                f"This enricher version ({VERSION}) may be incompatible. Error: {e}"
            )

        # Vérifier si le message contient "deprecated"
        if test_resp.error != 0 and "deprecat" in test_resp.message.lower():
            raise SystemExit(f"API DEPRECATED: {test_resp.message}")

        logger.info("API health check passed")

    except requests.exceptions.RequestException as e:
        raise SystemExit(f"API health check failed: {e}")


# =============================================================================
# CLIENT HTTP AVEC RETRY
# Implémente une logique de retry automatique en cas d'échec réseau.
# =============================================================================

def fetch_with_retry(url: str) -> Optional[bytes]:
    """
    Effectue une requête GET avec retry automatique.
    Retourne:
    - bytes si succès
    - None si le plugin n'existe pas (404)
    Lève une exception si erreur après tous les retries
    """
    last_error: Optional[str] = None

    # Boucle de retry
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT)

            # 404 = Plugin non trouvé dans la base WPVulnerability
            # Ce n'est pas une erreur, juste un plugin inconnu
            if response.status_code == 404:
                return None

            if response.status_code == 200:
                return response.content

            # Autre code HTTP - on réessaie
            last_error = f"attempt {attempt}: unexpected status {response.status_code}"
            logger.warning(f"{last_error} - retry in {RETRY_DELAY}s")

        except requests.exceptions.RequestException as e:
            last_error = f"attempt {attempt}: {e}"
            logger.warning(f"{last_error} - retry in {RETRY_DELAY}s")

        time.sleep(RETRY_DELAY)

    # Tous les retries ont échoué
    raise Exception(f"all {MAX_RETRIES} attempts failed for {url}: {last_error}")


# =============================================================================
# EXTRACTION DES SLUGS DE PLUGINS
# Parcourt les findings WPScan pour trouver les plugins à enrichir.
# =============================================================================

def extract_plugin_slugs(findings: list[Finding]) -> list[str]:
    """
    Extrait les identifiants uniques (slugs) des plugins WordPress
    trouvés dans les findings WPScan.

    Stratégie d'extraction (dans l'ordre de priorité):
    1. Attribut "slug" explicite
    2. Attribut "plugin"
    3. Extraction depuis le nom (format "Plugin: nom-du-plugin")
    """
    # Set pour dédupliquer les slugs
    seen: set[str] = set()

    # Liste pour stocker les slugs uniques (préserve l'ordre)
    slugs: list[str] = []

    # Parcourir tous les findings
    for f in findings:
        # Ignorer les findings qui ne sont pas des plugins WordPress
        if f.category.lower() != "wordpress plugin":
            continue

        slug = ""

        # Essai 1: Chercher l'attribut "slug"
        if "slug" in f.attributes:
            slug = str(f.attributes.get("slug", ""))

        # Essai 2: Chercher l'attribut "plugin" (si slug est vide)
        if not slug and "plugin" in f.attributes:
            slug = str(f.attributes.get("plugin", ""))

        # Essai 3: Extraire depuis le nom du finding (ex: "Plugin: contact-form-7")
        if not slug and ": " in f.name:
            parts = f.name.split(": ", 1)
            if len(parts) == 2:
                slug = parts[1].strip()

        # Si on n'a pas trouvé de slug, passer au suivant
        if not slug:
            continue

        # Normaliser en minuscules (les slugs WordPress sont toujours en minuscules)
        slug = slug.lower()

        # Ajouter seulement si pas déjà vu (déduplication)
        if slug not in seen:
            seen.add(slug)
            slugs.append(slug)

    return slugs


# =============================================================================
# MAPPING DE SÉVÉRITÉ
# Convertit la sévérité CVSS vers le format secureCodeBox.
# =============================================================================

def map_severity(entry: WPVulnEntry) -> str:
    """
    Convertit la sévérité CVSS en sévérité secureCodeBox.
    CVSS utilise: CRITICAL, HIGH, MEDIUM, LOW, NONE
    secureCodeBox utilise: HIGH, MEDIUM, LOW, INFORMATIONAL
    """
    # Vérifier qu'on a des données d'impact
    if entry.impact.has_data and entry.impact.cvss.severity:
        severity = entry.impact.cvss.severity.upper()
        if severity in ("CRITICAL", "HIGH"):
            return "HIGH"  # CRITICAL et HIGH -> HIGH
        elif severity == "MEDIUM":
            return "MEDIUM"
        elif severity == "LOW":
            return "LOW"

    # Par défaut, on considère MEDIUM (principe de prudence)
    return "MEDIUM"


# =============================================================================
# CONVERSION: WPVulnEntry -> Finding secureCodeBox
# Transforme une vulnérabilité de l'API en finding secureCodeBox.
# =============================================================================

def vuln_to_finding(slug: str, plugin_name: str, entry: WPVulnEntry, location: str) -> Finding:
    """
    Convertit une entrée WPVulnerability en Finding secureCodeBox.
    Paramètres:
    - slug: identifiant du plugin (ex: "contact-form-7")
    - plugin_name: nom affiché du plugin (ex: "Contact Form 7")
    - entry: données de vulnérabilité de l'API
    - location: URL du site scanné
    """
    # Extraire les CVE et les liens de référence
    cves: list[str] = []
    refs: list[str] = []

    # Parcourir toutes les sources de la vulnérabilité
    for src in entry.sources:
        if src.name == "CVE":
            cves.append(src.id)
        if src.link:
            refs.append(src.link)

    # Extraire les CWE (faiblesses)
    cwes: list[str] = []
    if entry.impact.has_data:
        for cwe in entry.impact.cwes:
            cwes.append(cwe.cwe)

    # Déterminer si la vulnérabilité est corrigée
    fixed_in = entry.operator.max_version
    if entry.operator.unfixed == "1":
        fixed_in = ""  # Pas encore de correctif disponible

    # Construire les attributs
    attrs: dict[str, Any] = {
        "plugin_slug": slug,
        "plugin_name": plugin_name,
        "wpvuln_id": entry.uuid,
        "references": refs,
    }

    # Ajouter les attributs optionnels seulement s'ils ont une valeur
    if fixed_in:
        attrs["fixed_in"] = fixed_in
    if cves:
        attrs["cve"] = cves
    if cwes:
        attrs["cwe"] = cwes
    if entry.impact.has_data and entry.impact.cvss.score:
        attrs["cvss_score"] = entry.impact.cvss.score

    # Construire la description
    desc = entry.description
    if not desc:
        desc = entry.name  # Utiliser le titre si pas de description
    if fixed_in:
        desc += f" (fixed in {fixed_in})"

    # Retourner le Finding complet
    return Finding(
        id=str(uuid.uuid4()),  # Générer un nouvel UUID
        name=f"[WPVuln] {plugin_name} - {entry.name}",
        description=desc,
        category="WordPress Plugin Vulnerability",
        location=location,
        osi_layer="APPLICATION",  # Vulnérabilités web = couche application
        severity=map_severity(entry),
        attributes=attrs,
        false_positive=False,
    )


# =============================================================================
# WORKER: Récupération des vulnérabilités pour un plugin
# Fonction appelée en parallèle pour chaque plugin détecté.
# =============================================================================

def fetch_vulns_for_slug(slug: str, location: str) -> tuple[list[Finding], Optional[Exception]]:
    """
    Récupère les vulnérabilités d'un plugin depuis l'API.
    C'est un "worker" qui sera exécuté en parallèle via ThreadPoolExecutor.
    Retourne (findings, error) - un tuple similaire au pattern Go.
    """
    # Construire l'URL de l'API
    url = WPVULN_BASE_URL + slug
    logger.info(f"Fetching vulnerabilities for plugin: {slug}")

    try:
        # Faire la requête avec retry
        body = fetch_with_retry(url)

        # body == None signifie que le plugin n'existe pas dans la base
        if body is None:
            logger.info(f"Plugin {slug} not found in WPVulnerability database")
            return ([], None)

        # Parser la réponse JSON
        data = json.loads(body)
        resp = WPVulnResponse.from_dict(data)

        # Vérifier si l'API a retourné une erreur ou pas de données
        if resp.error != 0 or resp.data is None:
            logger.info(f"Plugin {slug}: API returned error or no data")
            return ([], None)

        plugin = resp.data

        # Vérifier s'il y a des vulnérabilités
        if not plugin.vulnerabilities:
            logger.info(f"No vulnerabilities found for plugin: {slug}")
            return ([], None)

        logger.info(f"Found {len(plugin.vulnerabilities)} vulnerability(ies) for plugin: {slug}")

        # Convertir chaque vulnérabilité en Finding
        findings: list[Finding] = []
        for vuln in plugin.vulnerabilities:
            findings.append(vuln_to_finding(slug, plugin.name, vuln, location))

        return (findings, None)

    except Exception as e:
        return ([], Exception(f"plugin {slug}: {e}"))


# =============================================================================
# UTILITAIRE: Extraction de la location
# =============================================================================

def extract_location(findings: list[Finding]) -> str:
    """
    Trouve l'URL du site scanné à partir des findings existants.
    Retourne "unknown" si aucune location n'est trouvée.
    """
    for f in findings:
        if f.location:
            return f.location
    return "unknown"


# =============================================================================
# ÉCRITURE DU RÉSULTAT
# =============================================================================

def write_output(findings: list[Finding], write_file: str) -> None:
    """Écrit les findings en JSON dans un fichier ou sur stdout."""
    # Convertir en liste de dictionnaires pour JSON
    output = [f.to_dict() for f in findings]

    # Générer du JSON formaté (lisible)
    out = json.dumps(output, indent=2, ensure_ascii=False)

    if write_file:
        # Écrire dans le fichier spécifié
        with open(write_file, "w", encoding="utf-8") as f:
            f.write(out)
        logger.info(f"Results written to {write_file} ({len(findings)} finding(s) total)")
    else:
        # Fallback: écrire sur la sortie standard
        print(out)


# =============================================================================
# FONCTION PRINCIPALE (POINT D'ENTRÉE)
# C'est la première fonction exécutée quand le programme démarre.
# =============================================================================

def main() -> None:
    """Point d'entrée principal du programme."""

    # =========================================================================
    # ÉTAPE 1: Vérification de l'API au démarrage
    # =========================================================================
    check_api_health()

    # =========================================================================
    # ÉTAPE 2: Lecture des variables d'environnement
    # secureCodeBox injecte ces variables automatiquement
    # =========================================================================
    read_file = os.environ.get("READ_FILE", "")
    write_file = os.environ.get("WRITE_FILE", "")

    if not read_file:
        logger.error("READ_FILE environment variable is not set")
        sys.exit(1)

    # =========================================================================
    # ÉTAPE 3: Lecture et parsing du fichier de findings WPScan
    # =========================================================================
    try:
        with open(read_file, "r", encoding="utf-8") as f:
            raw = f.read()
    except IOError as e:
        logger.error(f"Cannot read findings file {read_file}: {e}")
        sys.exit(1)

    try:
        findings_data = json.loads(raw)
        findings = [Finding.from_dict(f) for f in findings_data]
    except json.JSONDecodeError as e:
        logger.error(f"Cannot parse findings JSON: {e}")
        sys.exit(1)

    logger.info(f"Loaded {len(findings)} finding(s) from {read_file}")

    # =========================================================================
    # ÉTAPE 4: Extraction des slugs de plugins
    # =========================================================================
    slugs = extract_plugin_slugs(findings)
    if not slugs:
        logger.info("No WordPress plugin findings detected - nothing to enrich")
        write_output(findings, write_file)
        return

    logger.info(f"Plugins to check: {slugs}")

    # Récupérer l'URL du site scanné (pour l'ajouter aux nouveaux findings)
    location = extract_location(findings)

    # =========================================================================
    # ÉTAPE 5: Appels API en parallèle via ThreadPoolExecutor
    # ThreadPoolExecutor est l'équivalent Python des goroutines Go.
    # On lance un thread par plugin pour paralléliser les appels API.
    # =========================================================================
    enriched: list[Finding] = []

    with ThreadPoolExecutor(max_workers=len(slugs)) as executor:
        # Soumettre toutes les tâches
        future_to_slug = {
            executor.submit(fetch_vulns_for_slug, slug, location): slug
            for slug in slugs
        }

        # Collecter les résultats au fur et à mesure
        for future in as_completed(future_to_slug):
            slug = future_to_slug[future]
            try:
                findings_result, error = future.result()
                if error:
                    logger.warning(str(error))
                    continue
                enriched.extend(findings_result)
            except Exception as e:
                logger.warning(f"Plugin {slug}: {e}")

    logger.info(f"{len(enriched)} new vulnerability finding(s) generated")

    # =========================================================================
    # ÉTAPE 6: Fusion et écriture des résultats
    # =========================================================================
    merged = findings + enriched
    write_output(merged, write_file)


if __name__ == "__main__":
    main()
