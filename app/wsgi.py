# ABOUTME: gunicorn entrypoint — builds one app instance (hashes seeds at import time).
from app.store import create_app

app = create_app()
