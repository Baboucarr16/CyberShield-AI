import os
import secrets


class Config:
    DEBUG = os.environ.get("FLASK_DEBUG", "0").lower() in {"1", "true", "yes"}
    SECRET_KEY = os.environ.get("SECRET_KEY", "").strip() or (
        "development-only-change-me" if DEBUG else secrets.token_urlsafe(32)
    )
    TESTING = False
