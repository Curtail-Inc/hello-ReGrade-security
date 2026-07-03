# ABOUTME: A tiny team-chat API with one planted flaw (added in Task 3). Passwords are
# ABOUTME: bcrypt-hashed inside create_app(), so every instance holds unique salts.
import json
import secrets
from datetime import datetime, timezone

import bcrypt
from flask import Flask, Response, abort, request

# Seed users carry PLAINTEXT demo passwords; create_app() hashes them at boot with a
# fresh random salt, so two instances hold different hashes for the same password.
SEED_USERS = [
    {"id": 1, "username": "alice", "display_name": "Alice Kim", "password": "correct-horse"},
    {"id": 2, "username": "bob", "display_name": "Bob Ortiz", "password": "battery-staple-9"},
    {"id": 3, "username": "carol", "display_name": "Carol Singh", "password": "hunter2-really"},
    {"id": 4, "username": "dave", "display_name": "Dave Nguyen", "password": "tr0ub4dour-x"},
]

SEED_CHANNELS = [
    {"id": 10, "name": "general"},
    {"id": 20, "name": "random"},
    {"id": 30, "name": "engineering"},
]


def _json(obj):
    # sort_keys → deterministic bytes, so clean fields match exactly between instances.
    return Response(json.dumps(obj, sort_keys=True), mimetype="application/json")


def _sanitize(user):
    """Return a copy of the user WITHOUT the password hash."""
    return {k: v for k, v in user.items() if k != "password"}


def create_app():
    app = Flask(__name__)

    # Hash seed passwords fresh at boot → this instance's salts are unique.
    users = {}
    for u in SEED_USERS:
        hashed = bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()).decode()
        users[u["id"]] = {
            "id": u["id"],
            "username": u["username"],
            "display_name": u["display_name"],
            "password": hashed,
        }

    # created_at stamped at boot → legitimately differs between instances (noise to DROP).
    started_at = datetime.now(timezone.utc).isoformat()
    channels = [{**c, "created_at": started_at} for c in SEED_CHANNELS]

    @app.get("/health")
    def health():
        return _json({"ok": True})

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        for u in users.values():
            if u["username"] == body.get("username") and bcrypt.checkpw(
                body.get("password", "").encode(), u["password"].encode()
            ):
                # Random session token → fresh every call (noise to ID-MAP).
                return _json({"token": secrets.token_hex(16), "user_id": u["id"]})
        abort(401)

    @app.get("/users")
    def list_users():
        return _json({"users": [_sanitize(u) for u in users.values()]})

    @app.get("/users/<int:uid>")
    def get_user(uid):
        u = users.get(uid)
        if u is None:
            abort(404)
        return _json(_sanitize(u))  # sanitized — the clean baseline

    @app.get("/channels")
    def list_channels():
        return _json({"channels": channels})

    return app
