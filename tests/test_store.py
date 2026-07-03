# ABOUTME: Tests for the team-chat API — clean reads are sanitized, and every instance
# ABOUTME: hashes seed passwords with a fresh salt (the premise the demo rests on).
from app.store import create_app, _sanitize, SEED_USERS


def _client():
    return create_app().test_client()


def test_health_ok():
    r = _client().get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"ok": True}


def test_get_user_is_sanitized():
    r = _client().get("/users/1")
    assert r.status_code == 200
    body = r.get_json()
    assert body["display_name"] == "Alice Kim"
    assert "password" not in body  # clean baseline


def test_list_users_sanitized():
    r = _client().get("/users")
    assert r.status_code == 200
    users = r.get_json()["users"]
    assert len(users) == len(SEED_USERS)
    assert all("password" not in u for u in users)


def test_missing_user_404():
    assert _client().get("/users/9999").status_code == 404


def test_channels_have_created_at():
    r = _client().get("/channels")
    assert r.status_code == 200
    channels = r.get_json()["channels"]
    assert any(c["name"] == "general" for c in channels)
    assert all("created_at" in c for c in channels)


def test_sanitize_strips_password():
    assert _sanitize({"id": 1, "password": "x", "display_name": "A"}) == {
        "id": 1,
        "display_name": "A",
    }


def test_login_returns_fresh_token():
    c = _client()
    r1 = c.post("/login", json={"username": "alice", "password": "correct-horse"})
    r2 = c.post("/login", json={"username": "alice", "password": "correct-horse"})
    assert r1.status_code == r2.status_code == 200
    assert r1.get_json()["user_id"] == 1
    # Random per call → legitimate noise that must be ID-mapped, not dropped blindly.
    assert r1.get_json()["token"] != r2.get_json()["token"]


def test_login_wrong_password_401():
    r = _client().post("/login", json={"username": "alice", "password": "nope"})
    assert r.status_code == 401


def test_patch_renames_user():
    r = _client().patch("/users/2", json={"display_name": "Bob O."})
    assert r.status_code == 200
    assert r.get_json()["display_name"] == "Bob O."


def test_patch_leaks_password_hash():
    """The planted flaw (CVE-2023-5968 shape): rename echoes the UNsanitized user.
    Asserting the leak is PRESENT so a future refactor can't silently 'fix' the demo."""
    r = _client().patch("/users/3", json={"display_name": "Carol S."})
    assert r.status_code == 200
    body = r.get_json()
    assert "password" in body
    assert body["password"].startswith("$2b$")  # a bcrypt hash in the response body


def test_get_still_sanitized_after_patch():
    """Contrast: the GET path still sanitizes — only PATCH leaks."""
    c = _client()
    c.patch("/users/4", json={"display_name": "Dave N."})
    assert "password" not in c.get("/users/4").get_json()


def test_two_instances_leak_different_hashes():
    """The premise: a fresh instance re-salts, so the SAME user's leaked hash differs.
    Observes each instance's hash via the (planted) leak — no test-only internals."""
    ha = create_app().test_client().patch("/users/1", json={}).get_json()["password"]
    hb = create_app().test_client().patch("/users/1", json={}).get_json()["password"]
    assert ha != hb
    assert ha.startswith("$2b$") and hb.startswith("$2b$")
