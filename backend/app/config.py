import os
import base64
import hashlib
from pathlib import Path
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

class Settings(BaseModel):
    APP_NAME: str = "PhishGuard"
    APP_VERSION: str = "2.5.0"
    DETECTION_ENGINE_VERSION: str = "3.2.0-ENTERPRISE"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./phishguard.db")
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    MAX_URL_LENGTH: int = 4096
    MAX_EMAIL_BODY_LENGTH: int = 100000

    # Security & Encryption for OAuth tokens
    ENCRYPTION_SECRET: str = os.getenv("ENCRYPTION_SECRET", "phishguard-fernet-secret-key-32bytes!")

    # Google OAuth 2.0 Credentials
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://127.0.0.1:8000/api/gmail/oauth/callback")
    GOOGLE_PUBSUB_TOPIC: str = os.getenv("GOOGLE_PUBSUB_TOPIC", "")
    GMAIL_ADDON_API_KEY: str = os.getenv("GMAIL_ADDON_API_KEY", "")

    # Optional AI Explainer Key
    AI_API_KEY: str = os.getenv("AI_API_KEY", "")

    def get_fernet_key(self) -> bytes:
        """Derive a URL-safe 32-byte key for Fernet AES encryption."""
        digest = hashlib.sha256(self.ENCRYPTION_SECRET.encode()).digest()
        return base64.urlsafe_b64encode(digest)

settings = Settings()
