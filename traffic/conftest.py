# ABOUTME: Provides base_url — the running app to hit. Uses $BASE_URL when set (recording
# ABOUTME: mode: point it at the sensor proxy); otherwise boots an in-process instance.
import os
import threading

import pytest
from werkzeug.serving import make_server

from app.store import create_app


@pytest.fixture(scope="session")
def base_url():
    env = os.environ.get("BASE_URL")
    if env:
        yield env.rstrip("/")
        return
    server = make_server("127.0.0.1", 0, create_app(), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
