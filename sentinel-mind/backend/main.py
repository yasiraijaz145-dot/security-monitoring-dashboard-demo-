from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio, json, random
from datetime import datetime

from backend.api import events, threats, honeypot, intel
from backend.core.detector import AnomalyDetector
from backend.core.mitre_mapper import MitreMapper
from backend.core.threat_scorer import ThreatScorer
from backend.core.kill_chain import KillChainMapper

detector = AnomalyDetector()
mitre = MitreMapper()
scorer = ThreatScorer()
kill_chain = KillChainMapper()

connected_clients: list[WebSocket] = []

@asynccontextmanager
async def lifespan(app: FastAPI):
    detector.load()
    asyncio.create_task(event_broadcaster())
    yield

app = FastAPI(title="SentinelMind", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(events.router, prefix="/api")
app.include_router(threats.router, prefix="/api")
app.include_router(honeypot.router, prefix="/api")
app.include_router(intel.router, prefix="/api")
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")

@app.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    await ws.accept()
    connected_clients.append(ws)
    try:
        while True:
            await ws.receive_text()  # keep-alive ping
    except WebSocketDisconnect:
        connected_clients.remove(ws)

async def event_broadcaster():
    """Continuously simulate and broadcast threat events."""
    while True:
        event = generate_synthetic_event()
        features = extract_features(event)
        anomaly_score = detector.score(features)
        
        if anomaly_score > 0.45:
            techniques = mitre.classify(features, anomaly_score)
            risk = scorer.calculate(anomaly_score, techniques)
            stage = kill_chain.map(techniques)
            event.update({
                "anomaly_score": round(anomaly_score, 3),
                "risk_level": risk["level"],
                "risk_score": risk["score"],
                "mitre_techniques": techniques[:3],
                "kill_chain_stage": stage,
                "timestamp": datetime.utcnow().isoformat(),
            })
            payload = json.dumps(event)
            for ws in connected_clients.copy():
                try:
                    await ws.send_text(payload)
                except Exception:
                    connected_clients.remove(ws)
        
        await asyncio.sleep(random.uniform(0.8, 3.2))

def generate_synthetic_event():
    """Generate realistic-looking network event for demo."""
    attack_types = [
        {"src_ip": f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}", "dst_port": 22,   "protocol": "TCP", "bytes": random.randint(200,800),   "packets": random.randint(5,40),   "flags": "SYN", "event_type": "brute_force", "country": "RU"},
        {"src_ip": f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",  "dst_port": 443,  "protocol": "TCP", "bytes": random.randint(5000,50000),"packets": random.randint(20,200), "flags": "ACK", "event_type": "exfiltration","country": "CN"},
        {"src_ip": f"91.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",  "dst_port": 4444, "protocol": "TCP", "bytes": random.randint(100,400),   "packets": random.randint(3,15),   "flags": "PSH", "event_type": "c2_beacon",   "country": "IR"},
        {"src_ip": f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}","dst_port": 80,   "protocol": "TCP", "bytes": random.randint(800,3000),  "packets": random.randint(8,60),   "flags": "GET", "event_type": "recon_scan",  "country": "KP"},
        {"src_ip": f"5.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",   "dst_port": 3389, "protocol": "TCP", "bytes": random.randint(300,900),   "packets": random.randint(10,50),  "flags": "SYN", "event_type": "lateral_move","country": "UA"},
    ]
    return random.choice(attack_types)

def extract_features(event):
    return [
        event["dst_port"] / 65535,
        event["bytes"] / 100000,
        event["packets"] / 500,
        1 if event["protocol"] == "TCP" else 0,
        1 if event["flags"] in ["SYN"] else 0,
    ]