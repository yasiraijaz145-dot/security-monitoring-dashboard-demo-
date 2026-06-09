from fastapi import APIRouter
import random

router = APIRouter()

@router.get("/threats/active")
def get_active_threats():
    threats = [
        {"id":"THR-001","name":"APT-29 Campaign","severity":"CRITICAL","stage":"Exfiltration","iocs":14,"first_seen":"2026-06-05","last_seen":"2026-06-07","techniques":["T1041","T1071"]},
        {"id":"THR-002","name":"Cobalt Strike Beacon","severity":"HIGH","stage":"C2","iocs":7,"first_seen":"2026-06-06","last_seen":"2026-06-07","techniques":["T1105","T1021"]},
        {"id":"THR-003","name":"SSH Brute Force Campaign","severity":"MEDIUM","stage":"Initial Access","iocs":31,"first_seen":"2026-06-04","last_seen":"2026-06-07","techniques":["T1110","T1078"]},
    ]
    return {"threats": threats}