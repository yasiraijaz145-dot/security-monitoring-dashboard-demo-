from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "SentinelMind"
    MODEL_PATH: str = "ml/saved_models/"
    MITRE_DATA_PATH: str = "data/mitre_techniques.json"
    IOC_DATA_PATH: str = "data/ioc_samples.json"
    ANOMALY_THRESHOLD: float = 0.45
    HIGH_RISK_THRESHOLD: float = 0.75
    
    class Config:
        env_file = ".env"

settings = Settings()