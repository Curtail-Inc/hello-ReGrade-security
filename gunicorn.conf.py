# ABOUTME: gunicorn config for the security demo. This is a content demo, not a load
# ABOUTME: demo — a small worker/thread count is plenty.
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = 1
threads = 4
timeout = 60
