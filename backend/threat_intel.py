"""
Threat intelligence integration with GeoIP and malicious IP feeds.
Provides reputation scoring and IOC correlation.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
import aiohttp


@dataclass
class IPReputation:
    """IP reputation data."""
    ip: str
    is_malicious: bool = False
    reputation_score: int = 0  # 0-100, higher = more suspicious
    threat_types: List[str] = None
    country: Optional[str] = None
    asn: Optional[str] = None
    last_seen: Optional[float] = None
    sources: List[str] = None

    def __post_init__(self):
        if self.threat_types is None:
            self.threat_types = []
        if self.sources is None:
            self.sources = []


class ThreatIntelligence:
    """Threat intelligence engine with multiple feed sources."""

    def __init__(self, cache_dir: str = "threat_intel_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.ip_cache: Dict[str, IPReputation] = {}
        self.cache_ttl = 3600  # 1 hour
        self.malicious_ips = set()
        self._load_cache()

    def _load_cache(self):
        """Load cached reputation data."""
        cache_file = self.cache_dir / "ip_cache.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r") as f:
                    data = json.load(f)
                    for ip, rep_data in data.items():
                        self.ip_cache[ip] = IPReputation(**rep_data)
                print(f"[ThreatIntel] Loaded {len(self.ip_cache)} cached IPs")
            except Exception as e:
                print(f"[ThreatIntel] Failed to load cache: {e}")

    def _save_cache(self):
        """Save reputation cache to disk."""
        cache_file = self.cache_dir / "ip_cache.json"
        try:
            data = {
                ip: {
                    "ip": rep.ip,
                    "is_malicious": rep.is_malicious,
                    "reputation_score": rep.reputation_score,
                    "threat_types": rep.threat_types,
                    "country": rep.country,
                    "asn": rep.asn,
                    "last_seen": rep.last_seen,
                    "sources": rep.sources
                }
                for ip, rep in self.ip_cache.items()
            }
            with open(cache_file, "w") as f:
                json.dump(data, f)
        except Exception as e:
            print(f"[ThreatIntel] Failed to save cache: {e}")

    async def lookup_ip(self, ip: str) -> IPReputation:
        """Lookup IP reputation from cache or external sources."""
        # Check cache
        if ip in self.ip_cache:
            cached = self.ip_cache[ip]
            if cached.last_seen and (time.time() - cached.last_seen) < self.cache_ttl:
                return cached

        # Query external sources
        reputation = await self._query_threat_feeds(ip)
        reputation.last_seen = time.time()
        
        # Update cache
        self.ip_cache[ip] = reputation
        if reputation.is_malicious:
            self.malicious_ips.add(ip)
        
        return reputation

    async def _query_threat_feeds(self, ip: str) -> IPReputation:
        """Query multiple threat intelligence feeds."""
        reputation = IPReputation(ip=ip)
        
        # Simulate threat feed queries (replace with actual API calls)
        # In production, integrate with AbuseIPDB, AlienVault OTX, etc.
        
        # Example: Check against local blacklist
        if self._is_private_ip(ip):
            reputation.reputation_score = 0
            return reputation

        # Simulate reputation scoring
        # In production: aggregate scores from multiple feeds
        reputation.reputation_score = 0
        reputation.sources = ["local"]
        
        return reputation

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private range."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1])
            
            # Private ranges
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
                
        except ValueError:
            pass
        
        return False

    def enrich_flow(self, flow: Dict) -> Dict:
        """Enrich flow with threat intelligence."""
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        
        enrichment = {
            "src_reputation": None,
            "dst_reputation": None,
            "threat_score": 0.0,
            "is_known_threat": False
        }

        # Check source IP
        if src_ip in self.ip_cache:
            src_rep = self.ip_cache[src_ip]
            enrichment["src_reputation"] = src_rep.reputation_score
            if src_rep.is_malicious:
                enrichment["threat_score"] += 50.0
                enrichment["is_known_threat"] = True

        # Check destination IP
        if dst_ip in self.ip_cache:
            dst_rep = self.ip_cache[dst_ip]
            enrichment["dst_reputation"] = dst_rep.reputation_score
            if dst_rep.is_malicious:
                enrichment["threat_score"] += 30.0
                enrichment["is_known_threat"] = True

        return enrichment

    async def bulk_lookup(self, ips: List[str]) -> Dict[str, IPReputation]:
        """Lookup multiple IPs concurrently."""
        tasks = [self.lookup_ip(ip) for ip in ips]
        results = await asyncio.gather(*tasks)
        return {ip: rep for ip, rep in zip(ips, results)}

    def get_stats(self) -> Dict:
        """Get threat intelligence statistics."""
        return {
            "cached_ips": len(self.ip_cache),
            "known_malicious": len(self.malicious_ips),
            "cache_hit_rate": len(self.ip_cache) / max(len(self.ip_cache) + 1, 1)
        }


class GeoIPEnricher:
    """GeoIP enrichment for IP addresses."""

    def __init__(self, geoip_db_path: Optional[str] = None):
        self.geoip_db_path = geoip_db_path
        self.reader = None
        self._initialize_reader()

    def _initialize_reader(self):
        """Initialize GeoIP2 reader if database available."""
        if self.geoip_db_path and Path(self.geoip_db_path).exists():
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(self.geoip_db_path)
                print("[GeoIP] Database loaded")
            except ImportError:
                print("[GeoIP] geoip2 library not installed")
            except Exception as e:
                print(f"[GeoIP] Failed to load database: {e}")

    def lookup(self, ip: str) -> Optional[Dict]:
        """Lookup geographic information for IP."""
        if not self.reader:
            return None

        try:
            response = self.reader.city(ip)
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "asn": None  # Requires separate ASN database
            }
        except Exception:
            return None

    def enrich_flow(self, flow: Dict) -> Dict:
        """Add geographic data to flow."""
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")

        enrichment = {
            "src_geo": self.lookup(src_ip),
            "dst_geo": self.lookup(dst_ip)
        }

        return enrichment
