# ABOUTME: A plain functional test suite — the "22 standard tests" from the Mattermost
# ABOUTME: story. Asserts normal CRUD ONLY; deliberately NO security assertions.
import requests


def test_login_succeeds(base_url):
    r = requests.post(
        f"{base_url}/login", json={"username": "alice", "password": "correct-horse"}
    )
    assert r.status_code == 200
    assert "token" in r.json()


def test_get_user_returns_display_name(base_url):
    r = requests.get(f"{base_url}/users/1")
    assert r.status_code == 200
    assert r.json()["display_name"] == "Alice Kim"


def test_rename_user(base_url):
    r = requests.patch(f"{base_url}/users/2", json={"display_name": "Bob O."})
    assert r.status_code == 200
    assert r.json()["display_name"] == "Bob O."
    # Deliberately says NOTHING about `password` — that is the whole point.


def test_list_channels(base_url):
    r = requests.get(f"{base_url}/channels")
    assert r.status_code == 200
    assert any(c["name"] == "general" for c in r.json()["channels"])
