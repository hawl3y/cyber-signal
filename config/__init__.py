import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    AUTOMATION_ENABLED = os.getenv("AUTOMATION_ENABLED", "false").lower() == "true"
    AUTOMATION_INTERVAL_MINUTES = int(os.getenv("AUTOMATION_INTERVAL_MINUTES", "60"))

    AI_ENRICHMENT_ENABLED = os.getenv("AI_ENRICHMENT_ENABLED", "false").lower() == "true"
    XAI_API_KEY = os.getenv("XAI_API_KEY")
    XAI_BASE_URL = os.getenv("XAI_BASE_URL", "https://api.x.ai/v1")
    XAI_MODEL = os.getenv("XAI_MODEL", "grok-4-1-fast-non-reasoning")

    SEC_USER_AGENT = os.getenv(
        "SEC_USER_AGENT", "Cyber Signal cyber-signal@example.com"
    )