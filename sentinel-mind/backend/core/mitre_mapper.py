import json, os

TECHNIQUE_MAP = {
    "brute_force":   [("T1110", "Brute Force",             "Credential Access"),  ("T1078", "Valid Accounts",    "Defense Evasion")],
    "exfiltration":  [("T1041", "Exfil Over C2",           "Exfiltration"),        ("T1048", "Exfil Alt Protocol","Exfiltration")],
    "c2_beacon":     [("T1071", "App Layer Protocol",       "Command and Control"), ("T1105", "Ingress Tool Transfer","Command and Control")],
    "recon_scan":    [("T1046", "Network Service Discovery","Discovery"),           ("T1018", "Remote System Discovery","Discovery")],
    "lateral_move":  [("T1021", "Remote Services",         "Lateral Movement"),    ("T1563", "Remote Service Session Hijack","Lateral Movement")],
}

class MitreMapper:
    def classify(self, features: list[float], anomaly_score: float) -> list[dict]:
        """
        In production: use ml/mitre_classifier.py (trained multi-label model).
        Here we use feature heuristics for demo transparency.
        """
        port = features[0] * 65535
        
        if port == 22 or port == 3389:
            key = "brute_force"
        elif port == 4444 or port == 8080:
            key = "c2_beacon"
        elif port == 443 and features[1] > 0.3:
            key = "exfiltration"
        elif port == 80:
            key = "recon_scan"
        else:
            key = "lateral_move"
        
        techniques = TECHNIQUE_MAP.get(key, TECHNIQUE_MAP["recon_scan"])
        return [
            {"id": t[0], "name": t[1], "tactic": t[2], "confidence": round(anomaly_score * 0.9, 2)}
            for t in techniques
        ]