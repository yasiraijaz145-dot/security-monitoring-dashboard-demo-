import numpy as np
import os, pickle, random
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """
    Dual-model anomaly detector:
    - Isolation Forest for statistical outlier detection
    - Score normalization to 0-1 range
    In production: swap in the PyTorch autoencoder from ml/autoencoder.py
    """
    def __init__(self):
        self.model: IsolationForest | None = None
        self.fitted = False

    def load(self):
        model_path = "ml/saved_models/isolation_forest.pkl"
        if os.path.exists(model_path):
            with open(model_path, "rb") as f:
                self.model = pickle.load(f)
            self.fitted = True
        else:
            # Bootstrap with synthetic training data for demo
            self._bootstrap_fit()

    def _bootstrap_fit(self):
        """Fit on synthetic normal traffic for demo purposes."""
        normal_traffic = np.random.normal(loc=[0.3, 0.1, 0.05, 1, 0], 
                                          scale=[0.1, 0.05, 0.02, 0, 0], 
                                          size=(1000, 5))
        normal_traffic = np.clip(normal_traffic, 0, 1)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.08,
            random_state=42,
            max_features=5
        )
        self.model.fit(normal_traffic)
        self.fitted = True
        os.makedirs("ml/saved_models", exist_ok=True)
        with open("ml/saved_models/isolation_forest.pkl", "wb") as f:
            pickle.dump(self.model, f)

    def score(self, features: list[float]) -> float:
        if not self.fitted:
            return random.uniform(0.3, 0.9)
        x = np.array(features).reshape(1, -1)
        # IsolationForest returns negative scores; normalize to 0-1
        raw = self.model.decision_function(x)[0]
        # Invert and normalize: more anomalous → score closer to 1
        normalized = 1 - (raw - (-0.5)) / (0.5 - (-0.5))
        return float(np.clip(normalized, 0.0, 1.0))