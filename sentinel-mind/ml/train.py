"""
Training script — run once to produce saved_models/isolation_forest.pkl
and saved_models/autoencoder.pt

Uses CICIDS2017 dataset (download from: https://www.unb.ca/cic/datasets/ids-2017.html)
or runs with synthetic normal traffic for demo.
"""
import numpy as np
import pickle, os, torch

os.makedirs("ml/saved_models", exist_ok=True)

def train_isolation_forest(X_normal: np.ndarray):
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(n_estimators=300, contamination=0.05, random_state=42)
    model.fit(X_normal)
    with open("ml/saved_models/isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    print("✓ IsolationForest saved")
    return model

def train_autoencoder_model(X_normal: np.ndarray):
    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ml.autoencoder import train_autoencoder
    model = train_autoencoder(X_normal, epochs=100)
    torch.save(model.state_dict(), "ml/saved_models/autoencoder.pt")
    print("✓ Autoencoder saved")

if __name__ == "__main__":
    print("Generating synthetic normal traffic for demo...")
    X_normal = np.random.normal(
        loc=[0.3,0.1,0.05,0.05,0.1,0.05,0.05,0.02,0.1,0.1,0.1,0.5,0.05,0.02,0.3,0.2,0.2,0.1,0.1,1.0],
        scale=0.05, size=(5000, 20)
    )
    X_normal = np.clip(X_normal, 0, 1)
    print(f"Training on {len(X_normal)} normal traffic samples...")
    train_isolation_forest(X_normal)
    train_autoencoder_model(X_normal)
    print("\nDone. Run: uvicorn backend.main:app --reload")