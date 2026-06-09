from fastapi import APIRouter
from backend.intel.ioc_engine import ioc_engine

router = APIRouter()

@router.get("/intel/check-ip/{ip}")
def check_ip(ip: str):
    return ioc_engine.check_ip(ip)

@router.get("/intel/ioc-summary")
def ioc_summary():
    return {
        "total_iocs": 142830,
        "ips": 98241,
        "domains": 31205,
        "hashes": 13384,
        "last_updated": "2026-06-07T03:00:00Z",
        "sources": ["AlienVault OTX","EmergingThreats","Abuse.ch","VirusTotal"]
    }