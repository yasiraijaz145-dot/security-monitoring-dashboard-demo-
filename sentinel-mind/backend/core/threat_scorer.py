class ThreatScorer:
    TACTIC_WEIGHTS = {
        "Exfiltration": 1.0,
        "Command and Control": 0.95,
        "Lateral Movement": 0.85,
        "Credential Access": 0.80,
        "Defense Evasion": 0.75,
        "Discovery": 0.50,
        "Reconnaissance": 0.40,
    }

    def calculate(self, anomaly_score: float, techniques: list[dict]) -> dict:
        tactic_weight = max(
            (self.TACTIC_WEIGHTS.get(t["tactic"], 0.5) for t in techniques),
            default=0.5
        )
        score = round((anomaly_score * 0.6 + tactic_weight * 0.4) * 100)
        
        if score >= 80:   level = "CRITICAL"
        elif score >= 60: level = "HIGH"
        elif score >= 40: level = "MEDIUM"
        else:             level = "LOW"
        
        return {"score": score, "level": level}