from fastapi import APIRouter
from datetime import datetime, timedelta
import random

router = APIRouter()

@router.get("/events")
def get_events(limit: int = 50):
    """Return recent security events for dashboard initialization."""
    events = []
    base_time = datetime.utcnow()
    event_types = ["brute_force","recon_scan","c2_beacon","exfiltration","lateral_move"]
    risk_levels = ["LOW","LOW","MEDIUM","HIGH","CRITICAL"]
    countries = ["RU","CN","KP","IR","UA","BR","IN"]
    
    for i in range(limit):
        etype = random.choice(event_types)
        risk = random.choice(risk_levels)
        events.append({
            "id": f"evt_{i:04d}",
            "timestamp": (base_time - timedelta(minutes=i*2)).isoformat(),
            "src_ip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "dst_port": random.choice([22,80,443,3389,4444,8080]),
            "event_type": etype,
            "risk_level": risk,
            "risk_score": {"LOW":20,"MEDIUM":50,"HIGH":75,"CRITICAL":92}[risk] + random.randint(-10,10),
            "country": random.choice(countries),
            "mitre_techniques": [{"id":"T1110","name":"Brute Force","tactic":"Credential Access"}],
            "kill_chain_stage": {"stage": random.randint(1,7), "name": "Discovery"},
        })
    return {"events": events, "total": len(events)}

@router.get("/events/stats")
def get_stats():
    return {
        "total_events_24h": random.randint(1200, 2800),
        "critical_alerts": random.randint(3, 18),
        "unique_attackers": random.randint(40, 120),
        "top_targeted_port": 22,
        "detection_rate": round(random.uniform(94.2, 99.1), 1),
        "mean_time_to_detect_ms": random.randint(180, 420),
    }