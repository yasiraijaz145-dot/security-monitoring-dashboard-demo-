"""
Generates synthetic labeled network traffic CSV for model training/testing.
Run: python data/synthetic_traffic.py
"""
import pandas as pd
import numpy as np
import os

os.makedirs("data/generated", exist_ok=True)
np.random.seed(42)
N = 10000

normal = pd.DataFrame({
    "dst_port": np.random.choice([80,443,53,25,110], N//2),
    "flow_duration": np.random.exponential(5e6, N//2),
    "fwd_bytes": np.random.lognormal(7, 1, N//2),
    "bwd_bytes": np.random.lognormal(8, 1.2, N//2),
    "flow_packets_per_sec": np.random.exponential(50, N//2),
    "syn_flag_count": np.random.poisson(1, N//2),
    "label": "NORMAL"
})

attacks = pd.DataFrame({
    "dst_port": np.random.choice([22,4444,3389,1337,8080], N//2),
    "flow_duration": np.random.exponential(2e5, N//2),
    "fwd_bytes": np.random.lognormal(4, 2, N//2),
    "bwd_bytes": np.random.lognormal(3, 2, N//2),
    "flow_packets_per_sec": np.random.exponential(500, N//2),
    "syn_flag_count": np.random.poisson(8, N//2),
    "label": np.random.choice(["BRUTE_FORCE","PORTSCAN","C2_BEACON","EXFILTRATION"], N//2),
})

df = pd.concat([normal, attacks]).sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv("data/generated/synthetic_traffic.csv", index=False)
print(f"✓ Generated {len(df)} samples → data/generated/synthetic_traffic.csv")