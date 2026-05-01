#!/usr/bin/env python3
"""
Feedly_CyberAttacks_Agent_OpenCTI.py - Feedly Cyber Attacks Agent to OpenCTI Integration

Fetches cyber attack intelligence from Feedly's Cyber Attacks Agent and imports
it into OpenCTI as STIX2 objects (Incidents, Threat Actors, Malware, Attack Patterns,
Locations) with full relationship mapping.

Supports:
  - Paginated retrieval via POST /v3/ml/relationships/cyber-attacks/dashboard/table
  - Filtering by attack type, threat actor, malware family, victim country/industry/continent
  - Time period filtering (Last24Hours through LastYear)
  - Daemon mode for automated scheduled pulls
  - Incremental sync via persisted state

© 2025 Feedly, Inc. All rights reserved.

DISCLAIMERS. THE API SCRIPTS ARE PROVIDED "AS IS" FOR YOUR INTERNAL BUSINESS
USE ONLY. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE API SCRIPTS
IS WITH YOU. YOU AGREE THAT YOUR USE OF THE API SCRIPTS WILL BE AT YOUR SOLE
RISK. TO THE FULLEST EXTENT PERMITTED BY LAW, FEEDLY DISCLAIMS ALL WARRANTIES,
EXPRESS OR IMPLIED, IN CONNECTION WITH THE API SCRIPTS AND YOUR USE THEREOF,
INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT. FEEDLY MAKES NO
WARRANTIES OR REPRESENTATIONS ABOUT THE ACCURACY OR COMPLETENESS OF THE API
SCRIPTS AND NO REPRESENTATIONS THAT THE API SCRIPTS ARE NOT OTHERWISE
ENCUMBERED BY ANY THIRD PARTY LICENSE, INCLUDING ANY OPEN-SOURCE LICENSE.
FEEDLY ASSUMES NO LIABILITY OR RESPONSIBILITY FOR ANY: (1) ERRORS, MISTAKES,
OR INACCURACIES; (2) PERSONAL INJURY OR PROPERTY DAMAGE, OF ANY NATURE
WHATSOEVER, RESULTING FROM YOUR USE OF THE API SCRIPTS; (3) ANY UNAUTHORIZED
ACCESS TO OR USE OF API SCRIPTS; (4) ANY INTERRUPTION OR CESSATION OF
TRANSMISSION TO OR FROM THE API SCRIPTS; (5) ANY BUGS, VIRUSES, TROJAN HORSES,
OR THE LIKE WHICH MAY BE TRANSMITTED TO OR THROUGH THE API SCRIPTS BY ANY
THIRD PARTY; OR (6) ANY ERRORS OR OMISSIONS IN THE API SCRIPTS OR FOR ANY LOSS
OR DAMAGE OF ANY KIND INCURRED AS A RESULT OF THE USE OF THE API SCRIPTS.

LIMITATION OF LIABILITY. IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY DAMAGES.
FURTHER, IN NO EVENT SHALL FEEDLY BE LIABLE FOR ANY CONSEQUENTIAL, INCIDENTAL
OR INDIRECT DAMAGES, INCLUDING, WITHOUT LIMITATION, ANY LOSS OF DATA, OR LOSS
OF PROFITS OR LOST SAVINGS, ARISING OUT OF USE OF OR INABILITY TO USE THE
LICENSED PRODUCT, EVEN IF FEEDLY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH
DAMAGES, OR FOR ANY CLAIM BY ANY THIRD PARTY.

YOU ACKNOWLEDGE THAT YOU HAVE READ AND UNDERSTAND THESE TERMS AND AGREE TO BE
BOUND BY THEM. YOU FURTHER AGREE THAT THESE TERMS ARE THE COMPLETE AND
EXCLUSIVE STATEMENT OF THE AGREEMENT BETWEEN YOU AND FEEDLY FOR THE USE OF THE
API SCRIPTS, AND THESE TERMS SUPERSEDE ANY PRIOR AGREEMENT, ORAL OR WRITTEN,
AND ANY OTHER COMMUNICATIONS RELATING TO THE SUBJECT MATTER HEREOF.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print("Error: 'requests' library is required. Install with: pip install requests")
    sys.exit(1)

try:
    from pycti import OpenCTIApiClient
except ImportError:
    print("Error: 'pycti' library is required. Install with: pip install pycti")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None
    print("WARNING: PyYAML not installed. Config file loading disabled.")


# =============================================================================
# CONFIGURATION
# =============================================================================

def load_api_key() -> str:
    """
    Load Feedly API key from environment variable or .env file.
    Priority: FEEDLY_API_KEY env var > .env file > fallback placeholder
    """
    api_key = os.environ.get("FEEDLY_API_KEY")
    if api_key:
        return api_key

    env_locations = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]

    for env_path in env_locations:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("FEEDLY_API_KEY=") and not line.startswith("#"):
                            key = line.split("=", 1)[1].strip()
                            if (key.startswith('"') and key.endswith('"')) or \
                               (key.startswith("'") and key.endswith("'")):
                                key = key[1:-1]
                            if key:
                                return key
            except Exception:
                pass

    return "APIKEYHERE"


def load_opencti_credentials() -> Tuple[str, str]:
    """
    Load OpenCTI URL and token from environment variables or .env file.
    Priority: env vars > .env file > fallback placeholders
    """
    url = os.environ.get("OPENCTI_URL", "")
    token = os.environ.get("OPENCTI_TOKEN", "")

    if url and token:
        return url, token

    env_locations = [
        os.path.join(os.getcwd(), ".env"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"),
    ]

    for env_path in env_locations:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#"):
                            continue
                        if line.startswith("OPENCTI_URL=") and not url:
                            val = line.split("=", 1)[1].strip().strip("\"'")
                            if val:
                                url = val
                        elif line.startswith("OPENCTI_TOKEN=") and not token:
                            val = line.split("=", 1)[1].strip().strip("\"'")
                            if val:
                                token = val
            except Exception:
                pass

    return url or "http://localhost:8080", token or "OPENCTI_TOKEN_HERE"


def load_yaml_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from YAML file, returning empty dict on failure."""
    if yaml is None:
        return {}
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        logging.warning(f"Could not load config file {config_path}: {e}")
        return {}


FEEDLY_API_KEY = load_api_key()
OPENCTI_URL, OPENCTI_TOKEN = load_opencti_credentials()

FEEDLY_BASE_URL = "https://api.feedly.com"
CYBER_ATTACKS_ENDPOINT = "/v3/ml/relationships/cyber-attacks/dashboard/table"
MAX_RETRIES = 3
RETRY_DELAY = 2       # seconds between retry attempts
RATE_LIMIT_DELAY = 1  # seconds between successful API calls
MAX_RESULTS_PER_PAGE = 100

STATE_FILE = "feedly_opencti_cyber_attacks_state.json"

PERIOD_CHOICES = [
    "Last24Hours",
    "Last7Days",
    "Last30Days",
    "Last3Months",
    "Last6Months",
    "LastYear",
]

# Human-readable labels for Feedly attack type identifiers
ATTACK_TYPE_LABELS: Dict[str, str] = {
    "Ransomware":                   "Ransomware",
    "DataBreachesAndExfiltration":  "Data Breach and Exfiltration",
    "DenialOfService":              "Denial of Service",
    "PhishingAndSocialEngineering": "Phishing and Social Engineering",
    "SupplyChainAttack":            "Supply Chain Attack",
    "ZeroDay":                      "Zero-Day Exploit",
    "APT":                          "Advanced Persistent Threat",
    "Cryptojacking":                "Cryptojacking",
    "Espionage":                    "Cyber Espionage",
    "Sabotage":                     "Cyber Sabotage",
    "Wiper":                        "Wiper Attack",
    "BEC":                          "Business Email Compromise",
}


# =============================================================================
# LOGGING
# =============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("feedly_opencti_cyber_attacks.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)


# =============================================================================
# FEEDLY CLIENT
# =============================================================================

class FeedlyClient:
    """Client for the Feedly Enterprise API (Cyber Attacks Agent)."""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        body: Optional[Dict] = None,
        retries: int = MAX_RETRIES,
    ) -> Optional[Dict]:
        """Make an API request with retry logic and rate limiting."""
        url = f"{FEEDLY_BASE_URL}{endpoint}"

        for attempt in range(retries):
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    json=body,
                    timeout=30,
                )

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", RETRY_DELAY * (attempt + 1)))
                    logger.warning(f"Rate limited. Waiting {retry_after}s...")
                    time.sleep(retry_after)
                    continue

                if response.status_code == 401:
                    logger.error("Authentication failed. Check your Feedly API key.")
                    return None

                if response.status_code == 403:
                    logger.error(
                        "Access forbidden. Ensure your account has Cyber Attacks Agent access."
                    )
                    return None

                if response.status_code == 404:
                    logger.error(f"Endpoint not found: {url}")
                    return None

                if response.status_code >= 400:
                    if attempt < retries - 1:
                        logger.warning(
                            f"HTTP {response.status_code} on attempt {attempt + 1}/{retries}, retrying..."
                        )
                        time.sleep(RETRY_DELAY * (attempt + 1))
                        continue
                    logger.error(f"API error {response.status_code}: {response.text[:300]}")
                    return None

                time.sleep(RATE_LIMIT_DELAY)
                return response.json()

            except requests.exceptions.ConnectionError:
                if attempt < retries - 1:
                    logger.warning(f"Connection error, retrying ({attempt + 1}/{retries})...")
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                logger.error(f"Connection failed after {retries} attempts.")
                return None

            except requests.exceptions.Timeout:
                if attempt < retries - 1:
                    logger.warning(f"Request timed out, retrying ({attempt + 1}/{retries})...")
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                logger.error("Request timed out after all retries.")
                return None

            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                logger.error(f"Request failed: {e}")
                return None

        return None

    def fetch_cyber_attacks(
        self,
        period: str = "Last7Days",
        filters: Optional[List[Dict]] = None,
        continuation: Optional[str] = None,
    ) -> Optional[Dict]:
        """Fetch one page of cyber attack records from the Cyber Attacks Agent."""
        body: Dict[str, Any] = {
            "period": {"type": period, "label": period},
        }
        if filters:
            body["layers"] = [{"filters": filters}]
        if continuation:
            body["continuation"] = continuation

        return self._request("POST", CYBER_ATTACKS_ENDPOINT, body=body)

    def fetch_all_cyber_attacks(
        self,
        period: str = "Last7Days",
        filters: Optional[List[Dict]] = None,
        max_results: int = 1000,
    ) -> List[Dict]:
        """Fetch all cyber attack records, following pagination via continuation tokens."""
        attacks: List[Dict] = []
        continuation = None
        page = 1

        logger.info(f"Fetching cyber attacks (period: {period})")
        while len(attacks) < max_results:
            logger.debug(f"  Page {page} (fetched so far: {len(attacks)})")
            response = self.fetch_cyber_attacks(
                period=period,
                filters=filters,
                continuation=continuation,
            )
            if not response:
                break

            # API may use different top-level keys for the records list
            items = (
                response.get("items")
                or response.get("attacks")
                or response.get("results")
                or []
            )
            if not items:
                logger.info("  No items in response – end of results.")
                break

            attacks.extend(items)
            logger.info(f"  Fetched {len(items)} records (total: {len(attacks)})")

            continuation = response.get("continuation")
            if not continuation:
                break

            page += 1

        return attacks[:max_results]


# =============================================================================
# DATA PARSING
# =============================================================================

def _safe_str(val: Any, max_len: int = 0) -> str:
    """Safely convert a value to string, optionally truncating."""
    s = str(val) if val is not None else ""
    return s[:max_len] if max_len else s


def _extract_list(data: Dict, *keys: str) -> List:
    """Extract a list from a dict by trying multiple key names."""
    for key in keys:
        val = data.get(key)
        if isinstance(val, list):
            return val
    return []


def _extract_label(entity: Any) -> str:
    """Extract a human-readable label from an entity object or bare string."""
    if isinstance(entity, str):
        return entity
    if isinstance(entity, dict):
        return (
            entity.get("label")
            or entity.get("name")
            or entity.get("title")
            or entity.get("id", "")
        )
    return ""


def parse_attack(attack: Dict) -> Dict:
    """
    Normalise a raw Feedly Cyber Attacks Agent record into a standardised dict.

    Handles multiple possible key names in the API response to stay robust
    across API version changes.

    Returns keys:
      attack_id, title, description, date_iso, attack_types, threat_actors,
      malware_families, victims, source_articles
    """
    title = attack.get("title") or attack.get("name") or "Untitled Cyber Attack"

    description = (
        attack.get("description")
        or attack.get("summary")
        or attack.get("content")
        or title
    )
    if isinstance(description, dict):
        description = description.get("content") or description.get("text") or title

    # Published timestamp in milliseconds
    date_ms = attack.get("date") or attack.get("published") or attack.get("timestamp") or 0
    try:
        date_iso = datetime.fromtimestamp(int(date_ms) / 1000, tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        date_iso = datetime.now(timezone.utc).isoformat()

    # Attack types — may be a list of strings/objects or a single value
    raw_types = _extract_list(attack, "attackTypes", "attack_types", "types", "categories")
    attack_types: List[str] = []
    for at in raw_types:
        label = _extract_label(at)
        if label:
            attack_types.append(ATTACK_TYPE_LABELS.get(label, label))
    if not attack_types and attack.get("attackType"):
        raw = _extract_label(attack["attackType"])
        attack_types.append(ATTACK_TYPE_LABELS.get(raw, raw))

    # Threat actors
    raw_actors = _extract_list(attack, "actors", "threatActors", "threat_actors", "attackers")
    threat_actors: List[Dict] = []
    seen_actors: set = set()
    for actor in raw_actors:
        label = _extract_label(actor)
        if label and label not in seen_actors:
            seen_actors.add(label)
            threat_actors.append({
                "id":          actor.get("id", "") if isinstance(actor, dict) else "",
                "name":        label,
                "type":        actor.get("type", "threat-actor") if isinstance(actor, dict) else "threat-actor",
                "description": actor.get("description", "") if isinstance(actor, dict) else "",
            })

    # Malware families
    raw_malware = _extract_list(attack, "malware", "malwareFamilies", "malware_families", "tools")
    malware_families: List[Dict] = []
    seen_malware: set = set()
    for mw in raw_malware:
        label = _extract_label(mw)
        if label and label not in seen_malware:
            seen_malware.add(label)
            malware_families.append({
                "id":   mw.get("id", "") if isinstance(mw, dict) else "",
                "name": label,
            })

    # Victims (organisations, countries, industries)
    raw_victims = _extract_list(attack, "victims", "targets", "affected")
    victims: List[Dict] = []
    for victim in raw_victims:
        if not isinstance(victim, dict):
            continue
        country_raw = victim.get("country") or {}
        if isinstance(country_raw, str):
            country_name, country_code = country_raw, ""
        elif isinstance(country_raw, dict):
            country_name = country_raw.get("label") or country_raw.get("name", "")
            country_code = country_raw.get("code") or country_raw.get("id", "")
        else:
            country_name, country_code = "", ""

        industry_raw = victim.get("industry") or victim.get("sector") or {}
        industry_name = _extract_label(industry_raw) if isinstance(industry_raw, (dict, str)) else ""

        org_name = (
            victim.get("name")
            or victim.get("organization")
            or victim.get("company")
            or ""
        )

        victims.append({
            "organization": org_name,
            "country_name": country_name,
            "country_code": country_code,
            "industry":     industry_name,
        })

    # Source articles / references
    raw_articles = _extract_list(attack, "sourceArticles", "articles", "sources", "references")
    source_articles: List[Dict] = []
    for art in raw_articles:
        if isinstance(art, dict):
            url = art.get("url") or art.get("href") or art.get("canonicalUrl", "")
            art_title = art.get("title") or art.get("name", "")
            if url:
                source_articles.append({"url": url, "title": art_title})
        elif isinstance(art, str) and art.startswith("http"):
            source_articles.append({"url": art, "title": ""})

    return {
        "attack_id":        attack.get("id", ""),
        "title":            title,
        "description":      _safe_str(description, max_len=10000),
        "date_iso":         date_iso,
        "attack_types":     attack_types,
        "threat_actors":    threat_actors,
        "malware_families": malware_families,
        "victims":          victims,
        "source_articles":  source_articles,
    }


# =============================================================================
# OPENCTI INTEGRATION
# =============================================================================

class OpenCTIIntegration:
    """Wrapper around pycti for creating cyber attack objects in OpenCTI."""

    def __init__(self, url: str, token: str):
        logger.info(f"Connecting to OpenCTI at {url} ...")
        self.client = OpenCTIApiClient(url=url, token=token)
        logger.info("OpenCTI connection established.")
        # In-memory caches to deduplicate objects within a sync run
        self._actor_cache:    Dict[str, str] = {}
        self._malware_cache:  Dict[str, str] = {}
        self._pattern_cache:  Dict[str, str] = {}
        self._location_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # External references
    # ------------------------------------------------------------------

    def _make_ext_ref(
        self, source_name: str, url: str, description: str = ""
    ) -> Optional[str]:
        """Create an external reference and return its OpenCTI ID."""
        try:
            kwargs: Dict[str, Any] = {"source_name": source_name, "url": url}
            if description:
                kwargs["description"] = description
            ref = self.client.external_reference.create(**kwargs)
            return ref.get("id") if ref else None
        except Exception as e:
            logger.warning(f"Could not create external reference ({url}): {e}")
            return None

    # ------------------------------------------------------------------
    # Threat Actors
    # ------------------------------------------------------------------

    def get_or_create_threat_actor(
        self, name: str, description: str = "", dry_run: bool = False
    ) -> Optional[str]:
        """Create or retrieve a Threat Actor in OpenCTI."""
        key = name.lower().strip()
        if key in self._actor_cache:
            return self._actor_cache[key]

        if dry_run:
            fid = f"dry-actor-{key}"
            self._actor_cache[key] = fid
            return fid

        try:
            actor = self.client.threat_actor.create(
                name=name,
                description=(
                    description
                    or f"Threat actor identified by Feedly Cyber Attacks Agent: {name}"
                ),
                confidence=70,
            )
            if actor:
                aid = actor.get("id", "")
                self._actor_cache[key] = aid
                logger.debug(f"    Threat actor: {name} | {aid[:16]}...")
                return aid
        except Exception as e:
            logger.warning(f"Could not create threat actor '{name}': {e}")
        return None

    # ------------------------------------------------------------------
    # Malware
    # ------------------------------------------------------------------

    def get_or_create_malware(
        self, name: str, dry_run: bool = False
    ) -> Optional[str]:
        """Create or retrieve a Malware object in OpenCTI."""
        key = name.lower().strip()
        if key in self._malware_cache:
            return self._malware_cache[key]

        if dry_run:
            fid = f"dry-malware-{key}"
            self._malware_cache[key] = fid
            return fid

        try:
            malware = self.client.malware.create(
                name=name,
                description=f"Malware family identified by Feedly Cyber Attacks Agent: {name}",
                confidence=70,
            )
            if malware:
                mid = malware.get("id", "")
                self._malware_cache[key] = mid
                logger.debug(f"    Malware: {name} | {mid[:16]}...")
                return mid
        except Exception as e:
            logger.warning(f"Could not create malware '{name}': {e}")
        return None

    # ------------------------------------------------------------------
    # Attack Patterns
    # ------------------------------------------------------------------

    def get_or_create_attack_pattern(
        self, name: str, dry_run: bool = False
    ) -> Optional[str]:
        """Create or retrieve an Attack Pattern in OpenCTI."""
        key = name.lower().strip()
        if key in self._pattern_cache:
            return self._pattern_cache[key]

        if dry_run:
            fid = f"dry-pattern-{key}"
            self._pattern_cache[key] = fid
            return fid

        try:
            pattern = self.client.attack_pattern.create(
                name=name,
                description=f"Attack pattern identified by Feedly Cyber Attacks Agent: {name}",
                confidence=70,
            )
            if pattern:
                pid = pattern.get("id", "")
                self._pattern_cache[key] = pid
                logger.debug(f"    Attack pattern: {name} | {pid[:16]}...")
                return pid
        except Exception as e:
            logger.warning(f"Could not create attack pattern '{name}': {e}")
        return None

    # ------------------------------------------------------------------
    # Locations
    # ------------------------------------------------------------------

    def get_or_create_location(
        self, country_name: str, country_code: str = "", dry_run: bool = False
    ) -> Optional[str]:
        """Create or retrieve a Location (country) in OpenCTI."""
        key = (country_code or country_name).lower().strip()
        if not key:
            return None
        if key in self._location_cache:
            return self._location_cache[key]

        if dry_run:
            fid = f"dry-location-{key}"
            self._location_cache[key] = fid
            return fid

        try:
            location = self.client.location.create(
                name=country_name,
                description=f"Country: {country_name}",
                country=country_code.upper() if country_code else None,
                x_opencti_location_type="Country",
                confidence=75,
            )
            if location:
                lid = location.get("id", "")
                self._location_cache[key] = lid
                logger.debug(f"    Location: {country_name} | {lid[:16]}...")
                return lid
        except Exception as e:
            logger.warning(f"Could not create location '{country_name}': {e}")
        return None

    # ------------------------------------------------------------------
    # Incidents
    # ------------------------------------------------------------------

    def create_incident(
        self,
        parsed: Dict,
        ext_ref_ids: List[str],
        dry_run: bool = False,
    ) -> Optional[str]:
        """Create an Incident in OpenCTI representing a cyber attack record."""
        title = parsed["title"]
        attack_types_str = ", ".join(parsed["attack_types"]) if parsed["attack_types"] else "Unknown"

        if dry_run:
            logger.info(f"  [DRY RUN] Incident: {title[:70]} | Types: {attack_types_str}")
            return f"dry-incident-{parsed['attack_id']}"

        try:
            description = parsed["description"]
            if parsed["attack_types"]:
                description = f"Attack Types: {attack_types_str}\n\n{description}"

            victim_countries = [v["country_name"] for v in parsed["victims"] if v["country_name"]]
            if victim_countries:
                description += f"\n\nVictim Countries: {', '.join(victim_countries[:10])}"

            victim_industries = list({v["industry"] for v in parsed["victims"] if v["industry"]})
            if victim_industries:
                description += f"\nVictim Industries: {', '.join(victim_industries[:10])}"

            kwargs: Dict[str, Any] = {
                "name":          title[:512],
                "description":   description[:10000],
                "incident_type": parsed["attack_types"][0] if parsed["attack_types"] else "other",
                "first_seen":    parsed["date_iso"],
                "last_seen":     parsed["date_iso"],
                "confidence":    70,
            }
            if ext_ref_ids:
                kwargs["externalReferences"] = ext_ref_ids

            incident = self.client.incident.create(**kwargs)
            if incident:
                iid = incident.get("id", "")
                logger.info(f"  Incident: {title[:70]} | {iid[:16]}...")
                return iid
            logger.warning(f"  No response creating incident: {title[:60]}")
        except Exception as e:
            logger.error(f"  Error creating incident '{title[:60]}': {e}")
        return None

    # ------------------------------------------------------------------
    # Relationships
    # ------------------------------------------------------------------

    def _create_relationship(
        self,
        from_id: str,
        to_id: str,
        relationship_type: str,
        description: str = "",
        dry_run: bool = False,
    ) -> Optional[str]:
        """Create a STIX core relationship between two objects."""
        if dry_run:
            return f"dry-rel-{relationship_type}"
        try:
            rel = self.client.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                description=description,
                confidence=65,
            )
            return rel.get("id") if rel else None
        except Exception as e:
            logger.warning(f"Could not create relationship '{relationship_type}': {e}")
            return None

    def create_relationships(
        self,
        incident_id: str,
        actor_ids: List[str],
        malware_ids: List[str],
        location_ids: List[str],
        pattern_ids: List[str],
        dry_run: bool = False,
    ) -> int:
        """Create all STIX relationships for a cyber attack incident."""
        count = 0

        # Incident ← attributed-to → Threat Actor
        for actor_id in actor_ids:
            if self._create_relationship(
                incident_id, actor_id, "attributed-to",
                "Incident attributed to threat actor", dry_run=dry_run,
            ):
                count += 1

            # Threat Actor → uses → Malware
            for malware_id in malware_ids:
                if self._create_relationship(
                    actor_id, malware_id, "uses",
                    "Threat actor uses malware family", dry_run=dry_run,
                ):
                    count += 1

        # Incident → uses → Malware
        for malware_id in malware_ids:
            if self._create_relationship(
                incident_id, malware_id, "uses",
                "Incident involved malware", dry_run=dry_run,
            ):
                count += 1

        # Incident → targets → Location (victim country)
        for location_id in location_ids:
            if self._create_relationship(
                incident_id, location_id, "targets",
                "Incident targeted this country", dry_run=dry_run,
            ):
                count += 1

        # Incident → uses → Attack Pattern
        for pattern_id in pattern_ids:
            if self._create_relationship(
                incident_id, pattern_id, "uses",
                "Incident used this attack pattern", dry_run=dry_run,
            ):
                count += 1

        return count

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------

    def create_report(
        self,
        title: str,
        description: str,
        published: str,
        object_ids: List[str],
    ) -> Optional[str]:
        """Create a Report in OpenCTI bundling all imported cyber attack objects."""
        if not object_ids:
            return None
        try:
            report = self.client.report.create(
                name=title[:512],
                description=description[:10000],
                published=published,
                report_types=["threat-report"],
                confidence=70,
                objectRefs=object_ids,
            )
            if report:
                rid = report.get("id", "")
                logger.info(f"Created report: {title[:70]} | {rid[:16]}...")
                return rid
        except Exception as e:
            logger.error(f"Error creating report: {e}")
        return None


# =============================================================================
# STATE MANAGEMENT
# =============================================================================

def load_state(state_file: str) -> Dict:
    """Load persisted sync state from a JSON file."""
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                state = json.load(f)
            logger.debug(f"Loaded sync state from {state_file}")
            return state
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Could not load state file {state_file}: {e}")
    return {}


def save_state(state_file: str, state: Dict) -> None:
    """Persist sync state to a JSON file."""
    try:
        with open(state_file, "w") as f:
            json.dump(state, f, indent=2)
        logger.debug(f"Saved sync state to {state_file}")
    except IOError as e:
        logger.warning(f"Could not save state file {state_file}: {e}")


# =============================================================================
# SYNC LOGIC
# =============================================================================

def build_filters(args: argparse.Namespace) -> Optional[List[Dict]]:
    """Build the Feedly filter list from CLI arguments."""
    filters: List[Dict] = []

    if getattr(args, "attack_type", None):
        filters.append({"field": "attackType", "value": args.attack_type})
    if getattr(args, "threat_actor", None):
        filters.append({"field": "threatActor", "value": args.threat_actor})
    if getattr(args, "malware_family", None):
        filters.append({"field": "malwareFamily", "value": args.malware_family})
    if getattr(args, "victim_country", None):
        filters.append({"field": "victimCountry", "value": args.victim_country})
    if getattr(args, "victim_industry", None):
        filters.append({"field": "victimIndustry", "value": args.victim_industry})
    if getattr(args, "victim_continent", None):
        filters.append({"field": "victimContinent", "value": args.victim_continent})

    return filters if filters else None


def run_sync(args: argparse.Namespace) -> None:
    """Execute one sync cycle: Feedly Cyber Attacks Agent → OpenCTI."""
    feedly = FeedlyClient(api_key=args.feedly_api_key)

    opencti: Optional[OpenCTIIntegration] = None
    if not args.dry_run:
        opencti = OpenCTIIntegration(url=args.opencti_url, token=args.opencti_token)

    state = load_state(args.state_file)
    filters = build_filters(args)

    # Resolve period: CLI flag > last saved period > default
    period = args.period
    if not period:
        period = state.get("last_period", "Last7Days")
        logger.info(f"No --period specified; using '{period}'")

    # Fetch attack records
    attacks = feedly.fetch_all_cyber_attacks(
        period=period,
        filters=filters,
        max_results=args.max_results,
    )

    if not attacks:
        logger.info("No cyber attack records found for the specified period/filters.")
        return

    logger.info(f"Processing {len(attacks)} cyber attack records...")

    stats: Dict[str, int] = {
        "processed":     0,
        "failed":        0,
        "incidents":     0,
        "threat_actors": 0,
        "malware":       0,
        "locations":     0,
        "relationships": 0,
    }

    all_object_ids: List[str] = []

    for i, attack in enumerate(attacks, 1):
        try:
            parsed = parse_attack(attack)

            actors_str = ", ".join(a["name"] for a in parsed["threat_actors"]) or "Unknown"
            types_str = ", ".join(parsed["attack_types"]) or "Unknown"
            logger.info(
                f"[{i}/{len(attacks)}] {parsed['title'][:60]}"
                + (f" | {types_str} | Actors: {actors_str}" if args.verbose else "")
            )

            stats["processed"] += 1

            # Build external references from source articles
            ext_ref_ids: List[str] = []
            if opencti and not args.dry_run:
                for art in parsed["source_articles"][:5]:
                    rid = opencti._make_ext_ref(
                        source_name="Feedly Cyber Attacks Agent",
                        url=art["url"],
                        description=art.get("title", "")[:200],
                    )
                    if rid:
                        ext_ref_ids.append(rid)

            # Create incident
            incident_id: Optional[str] = None
            if opencti:
                incident_id = opencti.create_incident(parsed, ext_ref_ids, dry_run=args.dry_run)
            elif args.dry_run:
                logger.info(f"  [DRY RUN] Incident: {parsed['title'][:70]} | {types_str}")
                incident_id = f"dry-{parsed['attack_id'] or i}"

            if incident_id:
                all_object_ids.append(incident_id)
                stats["incidents"] += 1

            # Create threat actor objects
            actor_ids: List[str] = []
            for actor in parsed["threat_actors"]:
                if opencti:
                    aid = opencti.get_or_create_threat_actor(
                        name=actor["name"],
                        description=actor.get("description", ""),
                        dry_run=args.dry_run,
                    )
                    if aid:
                        actor_ids.append(aid)
                        if aid not in all_object_ids:
                            all_object_ids.append(aid)
                            stats["threat_actors"] += 1
                elif args.dry_run:
                    logger.info(f"  [DRY RUN] Threat actor: {actor['name']}")

            # Create malware objects
            malware_ids: List[str] = []
            for mw in parsed["malware_families"]:
                if opencti:
                    mid = opencti.get_or_create_malware(
                        name=mw["name"],
                        dry_run=args.dry_run,
                    )
                    if mid:
                        malware_ids.append(mid)
                        if mid not in all_object_ids:
                            all_object_ids.append(mid)
                            stats["malware"] += 1
                elif args.dry_run:
                    logger.info(f"  [DRY RUN] Malware: {mw['name']}")

            # Create attack pattern objects (one per attack type)
            pattern_ids: List[str] = []
            for at in parsed["attack_types"]:
                if opencti:
                    pid = opencti.get_or_create_attack_pattern(
                        name=at,
                        dry_run=args.dry_run,
                    )
                    if pid:
                        pattern_ids.append(pid)
                        if pid not in all_object_ids:
                            all_object_ids.append(pid)
                elif args.dry_run:
                    logger.info(f"  [DRY RUN] Attack pattern: {at}")

            # Create location objects (victim countries, deduplicated)
            location_ids: List[str] = []
            seen_countries: set = set()
            for victim in parsed["victims"]:
                country_key = (victim["country_code"] or victim["country_name"]).lower()
                if country_key and country_key not in seen_countries:
                    seen_countries.add(country_key)
                    if opencti:
                        lid = opencti.get_or_create_location(
                            country_name=victim["country_name"],
                            country_code=victim["country_code"],
                            dry_run=args.dry_run,
                        )
                        if lid:
                            location_ids.append(lid)
                            if lid not in all_object_ids:
                                all_object_ids.append(lid)
                                stats["locations"] += 1
                    elif args.dry_run:
                        logger.info(f"  [DRY RUN] Location: {victim['country_name']}")

            # Create all relationships
            if incident_id and opencti:
                rel_count = opencti.create_relationships(
                    incident_id=incident_id,
                    actor_ids=actor_ids,
                    malware_ids=malware_ids,
                    location_ids=location_ids,
                    pattern_ids=pattern_ids,
                    dry_run=args.dry_run,
                )
                stats["relationships"] += rel_count

        except Exception as e:
            logger.error(f"Error processing attack '{attack.get('title', '')[:60]}': {e}")
            stats["failed"] += 1

    # Optional summary report
    if args.create_report and all_object_ids and opencti and not args.dry_run:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        report_title = f"Feedly Cyber Attack Intelligence – {now_str}"
        report_desc = (
            f"Cyber attack intelligence report synced from Feedly Cyber Attacks Agent "
            f"(period: {period}). "
            f"Contains {stats['incidents']} incidents from {stats['processed']} attack records."
        )
        rid = opencti.create_report(
            title=report_title,
            description=report_desc,
            published=datetime.now(timezone.utc).isoformat(),
            object_ids=all_object_ids,
        )
        if rid:
            logger.info(f"Summary report created: {rid[:16]}...")

    # Persist state
    if not args.dry_run:
        state["last_sync_iso"] = datetime.now(timezone.utc).isoformat()
        state["last_period"] = period
        save_state(args.state_file, state)

    # Summary
    logger.info("")
    logger.info("=" * 60)
    logger.info("SYNC COMPLETE")
    logger.info("=" * 60)
    logger.info(f"  Attack records processed: {stats['processed']}")
    logger.info(f"  Records failed:           {stats['failed']}")
    logger.info(f"  Incidents created:        {stats['incidents']}")
    logger.info(f"  Threat actors upserted:   {stats['threat_actors']}")
    logger.info(f"  Malware objects upserted: {stats['malware']}")
    logger.info(f"  Locations upserted:       {stats['locations']}")
    logger.info(f"  Relationships created:    {stats['relationships']}")
    if args.dry_run:
        logger.info("  (Dry run – no changes written to OpenCTI)")
    logger.info("=" * 60)


# =============================================================================
# CLI
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Feedly_CyberAttacks_Agent_OpenCTI.py",
        description="Sync Feedly Cyber Attacks Agent intelligence into OpenCTI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run to preview what would be imported (default: last 7 days)
  python Feedly_CyberAttacks_Agent_OpenCTI.py --dry-run

  # Sync last 30 days of ransomware attacks
  python Feedly_CyberAttacks_Agent_OpenCTI.py --period Last30Days --attack-type Ransomware

  # Filter by victim country and create a summary report
  python Feedly_CyberAttacks_Agent_OpenCTI.py --victim-country US --create-report

  # Filter by a specific threat actor
  python Feedly_CyberAttacks_Agent_OpenCTI.py --threat-actor "LockBit" --period Last3Months

  # Filter by victim continent (Europe)
  python Feedly_CyberAttacks_Agent_OpenCTI.py --victim-continent "nlp/f/entity/gz:loc:46"

  # Automated pull every 24 hours in daemon mode
  python Feedly_CyberAttacks_Agent_OpenCTI.py --daemon --interval 1440

  # Verbose dry run for debugging
  python Feedly_CyberAttacks_Agent_OpenCTI.py --dry-run -v
        """,
    )

    # ---- Feedly ----
    feedly = parser.add_argument_group("Feedly")
    feedly.add_argument(
        "--feedly-api-key",
        default=FEEDLY_API_KEY,
        metavar="KEY",
        help="Feedly API key (default: FEEDLY_API_KEY env var or .env)",
    )
    feedly.add_argument(
        "--period",
        choices=PERIOD_CHOICES,
        default=None,
        help="Time period for fetching attacks (default: Last7Days)",
    )
    feedly.add_argument(
        "--attack-type",
        default=None,
        metavar="TYPE",
        help=(
            "Filter by attack type. Options: Ransomware, DataBreachesAndExfiltration, "
            "DenialOfService, PhishingAndSocialEngineering, SupplyChainAttack"
        ),
    )
    feedly.add_argument(
        "--threat-actor",
        default=None,
        metavar="ACTOR",
        help="Filter by threat actor name or Feedly entity ID",
    )
    feedly.add_argument(
        "--malware-family",
        default=None,
        metavar="MALWARE",
        help="Filter by malware family name or Feedly entity ID",
    )
    feedly.add_argument(
        "--victim-country",
        default=None,
        metavar="CODE",
        help="Filter by victim country (ISO 3166-1 alpha-2 code, e.g. US, GB, DE)",
    )
    feedly.add_argument(
        "--victim-industry",
        default=None,
        metavar="INDUSTRY",
        help="Filter by victim industry (Feedly entity ID or label)",
    )
    feedly.add_argument(
        "--victim-continent",
        default=None,
        metavar="ENTITY_ID",
        help=(
            "Filter by victim continent (Feedly entity ID, "
            "e.g. nlp/f/entity/gz:loc:46 for Europe)"
        ),
    )
    feedly.add_argument(
        "--max-results",
        type=int,
        default=500,
        metavar="N",
        help="Maximum attack records to fetch per sync cycle (default: 500)",
    )

    # ---- OpenCTI ----
    octi = parser.add_argument_group("OpenCTI")
    octi.add_argument(
        "--opencti-url",
        default=OPENCTI_URL,
        metavar="URL",
        help="OpenCTI platform URL (default: OPENCTI_URL env var)",
    )
    octi.add_argument(
        "--opencti-token",
        default=OPENCTI_TOKEN,
        metavar="TOKEN",
        help="OpenCTI API token (default: OPENCTI_TOKEN env var or .env)",
    )
    octi.add_argument(
        "--create-report",
        action="store_true",
        help="Create a summary threat-report in OpenCTI linking all imported objects",
    )

    # ---- Automation ----
    auto = parser.add_argument_group("Automation")
    auto.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously, repeating the sync on a fixed interval",
    )
    auto.add_argument(
        "--interval",
        type=int,
        default=1440,
        metavar="MINUTES",
        help="Interval between daemon sync cycles in minutes (default: 1440 = 24h)",
    )

    # ---- General ----
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be imported without writing anything to OpenCTI",
    )
    parser.add_argument(
        "--state-file",
        default=STATE_FILE,
        metavar="FILE",
        help=f"Path to sync state JSON file (default: {STATE_FILE})",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        metavar="FILE",
        help="Optional YAML config file (default: config.yaml)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )

    return parser


def apply_yaml_config(args: argparse.Namespace) -> None:
    """
    Overlay YAML config values onto parsed args, only for fields still at
    their defaults (i.e. not explicitly set on the command line).
    """
    cfg = load_yaml_config(args.config)
    if not cfg:
        return

    feedly_cfg = cfg.get("feedly") or {}
    opencti_cfg = cfg.get("opencti") or {}
    sync_cfg = cfg.get("sync") or {}

    if feedly_cfg.get("api_key") and args.feedly_api_key == "APIKEYHERE":
        args.feedly_api_key = feedly_cfg["api_key"]
    if feedly_cfg.get("period") and args.period is None:
        args.period = feedly_cfg["period"]
    if feedly_cfg.get("attack_type") and not args.attack_type:
        args.attack_type = feedly_cfg["attack_type"]
    if feedly_cfg.get("threat_actor") and not args.threat_actor:
        args.threat_actor = feedly_cfg["threat_actor"]
    if feedly_cfg.get("malware_family") and not args.malware_family:
        args.malware_family = feedly_cfg["malware_family"]
    if feedly_cfg.get("victim_country") and not args.victim_country:
        args.victim_country = feedly_cfg["victim_country"]
    if feedly_cfg.get("victim_industry") and not args.victim_industry:
        args.victim_industry = feedly_cfg["victim_industry"]
    if feedly_cfg.get("victim_continent") and not args.victim_continent:
        args.victim_continent = feedly_cfg["victim_continent"]
    if feedly_cfg.get("max_results") and args.max_results == 500:
        args.max_results = int(feedly_cfg["max_results"])

    if opencti_cfg.get("url") and args.opencti_url == "http://localhost:8080":
        args.opencti_url = opencti_cfg["url"]
    if opencti_cfg.get("token") and args.opencti_token == "OPENCTI_TOKEN_HERE":
        args.opencti_token = opencti_cfg["token"]
    if opencti_cfg.get("create_report") and not args.create_report:
        args.create_report = bool(opencti_cfg["create_report"])

    if sync_cfg.get("interval") and args.interval == 1440:
        args.interval = int(sync_cfg["interval"])
    if sync_cfg.get("daemon") and not args.daemon:
        args.daemon = bool(sync_cfg["daemon"])


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    apply_yaml_config(args)

    if args.daemon:
        interval_secs = args.interval * 60
        logger.info(
            f"Daemon mode enabled – syncing every {args.interval} minute(s). "
            "Press Ctrl+C to stop."
        )
        cycle = 0
        while True:
            cycle += 1
            logger.info(f"--- Daemon cycle #{cycle} ---")
            try:
                run_sync(args)
            except SystemExit:
                raise
            except Exception as e:
                logger.error(f"Sync cycle failed: {e}", exc_info=args.verbose)

            next_run = datetime.now(timezone.utc) + timedelta(seconds=interval_secs)
            logger.info(
                f"Next sync at {next_run.strftime('%Y-%m-%d %H:%M:%S UTC')} "
                f"(in {args.interval} minute(s))."
            )
            time.sleep(interval_secs)
    else:
        run_sync(args)


if __name__ == "__main__":
    main()
