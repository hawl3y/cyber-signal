import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    AUTOMATION_ENABLED = os.getenv("AUTOMATION_ENABLED", "false").lower() == "true"
    AUTOMATION_INTERVAL_MINUTES = int(os.getenv("AUTOMATION_INTERVAL_MINUTES", "60"))

    SEC_USER_AGENT = os.getenv(
        "SEC_USER_AGENT", "Cyber Signal cyber-signal@example.com"
    )