# SentinelMind — AI Threat Intelligence Platform

Real-time behavioral threat detection with MITRE ATT&CK mapping, ML anomaly scoring, and adaptive honeypot simulation.

## Architecture
```
Network Events → Feature Engineering → Isolation Forest + Autoencoder
                                              ↓
                                    Anomaly Score (0-1)
                                              ↓
                              MITRE ATT&CK Technique Classifier
                                              ↓
                              Kill Chain Stage + Risk Score
                                              ↓
                              Live SOC Dashboard + Alerts
```

## Stack
- **ML**: PyTorch (Autoencoder) + scikit-learn (Isolation Forest)
- **Backend**: FastAPI + WebSockets
- **Frontend**: Vanilla JS + D3.js (zero framework bloat)
- **Deploy**: Vercel (frontend) + Railway/Render (backend)

## Setup
```bash
pip install -r requirements.txt
python data/synthetic_traffic.py   # generate demo data
python ml/train.py                 # train models
uvicorn backend.main:app --reload  # start API
```

## Key Features
- Zero-day anomaly detection without signature databases
- MITRE ATT&CK T-code classification (14 tactics, 196 techniques)
- Kill chain stage visualization (Reconnaissance → Exfiltration)
- Honeypot SSH/HTTP simulation with attacker behavior logging
- IOC correlation against known bad IPs/hashes/domains
- Real-time WebSocket event streaming to dashboard