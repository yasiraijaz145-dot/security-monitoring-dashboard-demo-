from fastapi import APIRouter
from backend.honeypot.simulator import honeypot
import random

router = APIRouter()

@router.get("/honeypot/sessions")
def get_sessions(limit: int = 20):
    return {"sessions": [honeypot.generate_ssh_attempt() for _ in range(limit)]}

@router.get("/honeypot/http-probes")
def get_http_probes(limit: int = 20):
    return {"probes": [honeypot.generate_http_probe() for _ in range(limit)]}

@router.get("/honeypot/stats")
def get_honeypot_stats():
    return {
        "total_interactions_today": random.randint(800, 3000),
        "unique_ips": random.randint(50, 200),
        "top_username": "admin",
        "top_password": "123456",
        "top_path_probed": "/wp-admin",
        "commands_captured": random.randint(10, 80),
    }