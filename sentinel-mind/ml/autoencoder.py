import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np

class NetworkAutoencoder(nn.Module):
    """
    Autoencoder for network traffic anomaly detection.
    Trained on normal traffic; high reconstruction error = anomaly.
    Input: 20-dim feature vector extracted from network flows.
    """
    def __init__(self, input_dim=20, latent_dim=8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.BatchNorm1d(16),
            nn.Linear(16, 12),
            nn.ReLU(),
            nn.Linear(12, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 12),
            nn.ReLU(),
            nn.Linear(12, 16),
            nn.ReLU(),
            nn.BatchNorm1d(16),
            nn.Linear(16, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

    def reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """Returns per-sample MSE — proxy for anomaly score."""
        with torch.no_grad():
            recon = self.forward(x)
            return ((x - recon) ** 2).mean(dim=1)


def train_autoencoder(X_normal: np.ndarray, epochs=50, lr=1e-3) -> NetworkAutoencoder:
    """Train on normal traffic only. Anomalies will have high recon error."""
    X = torch.tensor(X_normal, dtype=torch.float32)
    model = NetworkAutoencoder(input_dim=X.shape[1])
    optimizer = optim.Adam(model.parameters(), lr=lr)
    loss_fn = nn.MSELoss()
    
    model.train()
    for epoch in range(epochs):
        optimizer.zero_grad()
        recon = model(X)
        loss = loss_fn(recon, X)
        loss.backward()
        optimizer.step()
        if epoch % 10 == 0:
            print(f"Epoch {epoch}/{epochs} | Loss: {loss.item():.6f}")
    
    return model