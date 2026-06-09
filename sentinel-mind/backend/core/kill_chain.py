TACTIC_TO_STAGE = {
    "Reconnaissance":       {"stage": 1, "name": "Reconnaissance"},
    "Resource Development": {"stage": 2, "name": "Weaponization"},
    "Initial Access":       {"stage": 3, "name": "Delivery"},
    "Execution":            {"stage": 4, "name": "Exploitation"},
    "Persistence":          {"stage": 4, "name": "Exploitation"},
    "Privilege Escalation": {"stage": 4, "name": "Exploitation"},
    "Defense Evasion":      {"stage": 5, "name": "Installation"},
    "Credential Access":    {"stage": 5, "name": "Installation"},
    "Discovery":            {"stage": 5, "name": "Installation"},
    "Lateral Movement":     {"stage": 6, "name": "C2"},
    "Command and Control":  {"stage": 6, "name": "C2"},
    "Collection":           {"stage": 7, "name": "Exfiltration"},
    "Exfiltration":         {"stage": 7, "name": "Exfiltration"},
    "Impact":               {"stage": 7, "name": "Exfiltration"},
}

class KillChainMapper:
    def map(self, techniques: list[dict]) -> dict:
        stages = [TACTIC_TO_STAGE.get(t["tactic"], {"stage": 1, "name": "Reconnaissance"}) for t in techniques]
        return max(stages, key=lambda s: s["stage"]) if stages else {"stage": 1, "name": "Reconnaissance"}