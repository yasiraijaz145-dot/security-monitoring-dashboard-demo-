import json, os

class IOCEngine:
    """
    Correlates observed IPs/hashes/domains against known IOC database.
    In production: integrate with VirusTotal, Shodan, AbuseIPDB APIs.
    """
    def __init__(self):
        self.iocs = {"ips": set(), "domains": set(), "hashes": set()}
        self._load()

    def _load(self):
        path = "data/ioc_samples.json"
        if os.path.exists(path):
            with open(path) as f:
                data = json.load(f)
                self.iocs["ips"] = set(data.get("ips", []))
                self.iocs["domains"] = set(data.get("domains", []))
                self.iocs["hashes"] = set(data.get("hashes", []))

    def check_ip(self, ip: str) -> dict:
        is_known_bad = ip in self.iocs["ips"]
        return {
            "ip": ip,
            "is_ioc": is_known_bad,
            "threat_type": "Known C2 / Botnet" if is_known_bad else None,
            "sources": ["AlienVault OTX", "EmergingThreats"] if is_known_bad else [],
        }

    def check_hash(self, hash_val: str) -> dict:
        return {
            "hash": hash_val,
            "is_ioc": hash_val in self.iocs["hashes"],
            "malware_family": "Emotet" if hash_val in self.iocs["hashes"] else None,
        }

ioc_engine = IOCEngine()