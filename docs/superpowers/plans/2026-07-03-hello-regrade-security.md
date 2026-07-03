# hello-ReGrade-security Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a public demo (app + branded video) where ReGrade catches a CVE-2023-5968-class password-hash leak by comparing an app to itself — same version, no security test, the leaked secret's per-instance bcrypt entropy is the signal.

**Architecture:** A tiny Flask team-chat API (`create_app()`) with exactly one planted flaw: `PATCH /users/<id>` returns the full user object including the `password` hash (the missing sanitize). Seed passwords are bcrypt-hashed *inside `create_app()`*, so every instance (and every `create_app()` call) holds different hashes for the same password. `docker-compose` runs two identical instances. Traffic is a passing functional pytest suite with no security assertions, pointed at ReGrade via `BASE_URL`. Record against instance A, replay against instance B; after ID-mapping the session token and dropping the boot timestamp, the surviving delta is `$.password`.

**Tech Stack:** Python 3.12, Flask, `bcrypt`, gunicorn; `requests` for the traffic suite; Remotion/VHS/ElevenLabs for the video (reused from `hello-ReGrade`).

## Global Constraints

- Python 3.12; Flask + `bcrypt` + gunicorn; in-memory only, no persistence/UI.
- `create_app()` takes **no version arg** — the two sides are two instances of one image (NO `v1`/`v2`).
- Passwords are bcrypt-hashed **inside `create_app()`** (fresh salt per call) — this is the premise the whole demo rests on.
- Exactly **one** planted flaw: the `$.password` leak on `PATCH /users/<id>`. No other vulns.
- The traffic suite asserts **functional behavior only** — never the absence of `password`.
- Use `_json(obj)` = `Response(json.dumps(obj, sort_keys=True), mimetype="application/json")` for stable bytes, matching the siblings.
- Files start with two `# ABOUTME:` comment lines.
- Public repo `Curtail-Inc/hello-ReGrade-security`, Apache-2.0, pushed as `slisteraley`.
- Brand red `#E0001F`; reuse the hello-ReGrade video pipeline; cite CVE-2023-5968 as inspiration, no Mattermost code/impersonation.
- On-screen video numbers come from the Task 7 live-validation gate — never invented.

---

### Task 1: App core — seed data, bcrypt-at-boot, sanitize, clean read endpoints

**Files:**
- Create: `requirements.txt`
- Create: `app/__init__.py` (empty)
- Create: `app/store.py`
- Create: `tests/__init__.py` (empty)
- Test: `tests/test_store.py`

**Interfaces:**
- Produces: `app.store.create_app() -> flask.Flask` (no args); module constants `SEED_USERS`, `SEED_CHANNELS`; helpers `_json(obj)`, `_sanitize(user)`. Endpoints so far: `GET /health`, `GET /users`, `GET /users/<int:uid>`, `GET /channels`.

- [ ] **Step 1: Create `requirements.txt`**

```
flask
gunicorn
bcrypt
```

- [ ] **Step 2: Write the failing tests** (`tests/test_store.py`)

```python
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
```

(The premise "two fresh instances hold different hashes" is asserted in Task 3 via the
real leak endpoint — no test-only internals on the app.)

- [ ] **Step 3: Run the tests to verify they fail**

Run: `python -m pytest tests/test_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.store'`.

- [ ] **Step 4: Implement `app/store.py`**

```python
# ABOUTME: A tiny team-chat API with one planted flaw (added in Task 3). Passwords are
# ABOUTME: bcrypt-hashed inside create_app(), so every instance holds unique salts.
import json
from datetime import datetime, timezone

import bcrypt
from flask import Flask, Response, abort

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
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_store.py -v`
Expected: PASS (6 passed).

- [ ] **Step 6: Commit**

```bash
git add requirements.txt app/__init__.py app/store.py tests/__init__.py tests/test_store.py
git commit -m "feat: team-chat API core with bcrypt-at-boot and sanitized reads"
```

---

### Task 2: Login endpoint (session-token noise to ID-map)

**Files:**
- Modify: `app/store.py` (add `POST /login`, import `secrets` and `request`)
- Test: `tests/test_store.py` (append)

**Interfaces:**
- Consumes: `create_app()`, `app.config["USERS"]`.
- Produces: `POST /login` — body `{username, password}` → `200 {token, user_id}` on success (token = `secrets.token_hex(16)`, fresh per call), `401` otherwise.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_store.py`)

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_store.py -k login -v`
Expected: FAIL — `404` (route not defined) instead of `200`/`401`.

- [ ] **Step 3: Implement the login route**

In `app/store.py`, update the imports:

```python
import json
import secrets
from datetime import datetime, timezone

import bcrypt
from flask import Flask, Response, abort, request
```

Add this route inside `create_app()` (after `health`, before `list_users`):

```python
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
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/test_store.py -v`
Expected: PASS (8 passed).

- [ ] **Step 5: Commit**

```bash
git add app/store.py tests/test_store.py
git commit -m "feat: login endpoint issuing fresh session tokens"
```

---

### Task 3: The planted leak — `PATCH /users/<id>` returns the password hash

**Files:**
- Modify: `app/store.py` (add `PATCH /users/<int:uid>`)
- Test: `tests/test_store.py` (append)

**Interfaces:**
- Produces: `PATCH /users/<int:uid>` — body `{display_name}` → updates the name and **returns the full stored user including `password`** (the CVE-shape leak). `404` if unknown.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_store.py`)

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_store.py -k patch -v`
Expected: FAIL — `405`/`404` (PATCH route not defined).

- [ ] **Step 3: Implement the leaky route**

Add inside `create_app()` (after `get_user`):

```python
    @app.patch("/users/<int:uid>")
    def rename_user(uid):
        u = users.get(uid)
        if u is None:
            abort(404)
        body = request.get_json(silent=True) or {}
        if "display_name" in body:
            u["display_name"] = body["display_name"]
        # BUG (CVE-2023-5968 shape): returns the FULL stored user, incl. password hash.
        # The GET paths call _sanitize(); this one forgets to. That single omission is
        # the entire vulnerability.
        return _json(u)
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest tests/test_store.py -v`
Expected: PASS (12 passed).

- [ ] **Step 5: Commit**

```bash
git add app/store.py tests/test_store.py
git commit -m "feat: planted password-hash leak on PATCH /users/<id>"
```

---

### Task 4: Containerization — two identical instances

**Files:**
- Create: `app/wsgi.py`
- Create: `gunicorn.conf.py`
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `.gitignore`
- Create: `LICENSE` (Apache-2.0 full text)

**Interfaces:**
- Produces: `docker compose up` → `instance-a` on `localhost:8001` and `instance-b` on `localhost:8002`, both from the identical image (no version env).

- [ ] **Step 1: Create `app/wsgi.py`**

```python
# ABOUTME: gunicorn entrypoint — builds one app instance (hashes seeds at import time).
from app.store import create_app

app = create_app()
```

- [ ] **Step 2: Create `gunicorn.conf.py`**

```python
# ABOUTME: gunicorn config for the security demo. This is a content demo, not a load
# ABOUTME: demo — a small worker/thread count is plenty.
import os

bind = f"0.0.0.0:{os.environ.get('PORT', '8000')}"
workers = 1
threads = 4
timeout = 60
```

- [ ] **Step 3: Create `Dockerfile`**

```dockerfile
# ABOUTME: Runs the team-chat API under gunicorn. Two containers of this image become
# ABOUTME: instance-a and instance-b — same code, different bcrypt salts at boot.
FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY gunicorn.conf.py .
ENV PORT=8000
EXPOSE 8000
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.wsgi:app"]
```

- [ ] **Step 4: Create `docker-compose.yml`**

```yaml
# ABOUTME: Two IDENTICAL instances — record against instance-a (:8001), replay against
# ABOUTME: instance-b (:8002). Same image, no version: the leak is latent in both.
services:
  instance-a:
    build: .
    container_name: hello-regrade-security-a
    environment:
      PORT: "8000"
    ports:
      - "8001:8000"
  instance-b:
    build: .
    container_name: hello-regrade-security-b
    environment:
      PORT: "8000"
    ports:
      - "8002:8000"
```

- [ ] **Step 5: Create `.gitignore`**

```
__pycache__/
*.pyc
.pytest_cache/
video/out/
video/node_modules/
video/voh_cache/
.venv/
```

- [ ] **Step 6: Create `LICENSE`** — full Apache-2.0 text.

Run: `curl -sSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE` (verify it is the standard Apache-2.0 license text, ~11KB).

- [ ] **Step 7: Validate compose config**

Run: `docker compose config`
Expected: prints the resolved config listing `instance-a` and `instance-b`, both `build: .`, ports `8001:8000` and `8002:8000`, no errors.

- [ ] **Step 8: Commit**

```bash
git add app/wsgi.py gunicorn.conf.py Dockerfile docker-compose.yml .gitignore LICENSE
git commit -m "feat: containerize as two identical instances (a:8001, b:8002)"
```

---

### Task 5: Traffic = a passing functional test suite (the "regular tests")

**Files:**
- Create: `requirements-dev.txt`
- Create: `traffic/conftest.py`
- Create: `traffic/test_api.py`
- Create: `traffic/README.md`

**Interfaces:**
- Consumes: `app.store.create_app()`.
- Produces: a `base_url` pytest fixture (uses `$BASE_URL` if set, else boots an in-process instance); functional tests in `traffic/test_api.py` with **no** security assertions.

- [ ] **Step 1: Create `requirements-dev.txt`**

```
-r requirements.txt
pytest
requests
```

- [ ] **Step 2: Create the live-server fixture** (`traffic/conftest.py`)

```python
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
```

- [ ] **Step 3: Write the functional traffic suite** (`traffic/test_api.py`)

```python
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
```

- [ ] **Step 4: Run the traffic suite in self-test mode**

Run: `python -m pytest traffic/test_api.py -v`
Expected: PASS (4 passed) — the fixture boots an in-process instance since `$BASE_URL` is unset.

- [ ] **Step 5: Create `traffic/README.md`** documenting the "one env var" recording moment

```markdown
# Traffic — the "point your existing tests at ReGrade" step

`test_api.py` is a normal functional test suite. It asserts CRUD behavior and makes
**no security assertions** — it never checks whether `password` leaks.

Run it against the app directly:

    python -m pytest traffic/test_api.py            # boots an in-process instance
    BASE_URL=http://localhost:8001 pytest traffic/test_api.py   # against instance-a

**To record with ReGrade, change one thing** — point `BASE_URL` at the sensor proxy:

    BASE_URL=http://localhost:<proxy-port> pytest traffic/test_api.py

The tests still pass. ReGrade records the traffic. Nothing about the suite changed.
```

- [ ] **Step 6: Commit**

```bash
git add requirements-dev.txt traffic/conftest.py traffic/test_api.py traffic/README.md
git commit -m "feat: functional traffic suite (no security assertions) + recording docs"
```

---

### Task 6: README + CLAUDE.md walkthrough

**Files:**
- Create: `README.md`
- Create: `CLAUDE.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Write `README.md`** — the end-to-end walkthrough.

Must contain, in order:
1. One-paragraph pitch: same version both sides; the leaked hash's per-instance entropy is the signal; models CVE-2023-5968.
2. `docker compose up -d` → two identical instances (a:8001, b:8002).
3. Record: run `regrade proxy` in front of instance-a, then `BASE_URL=http://localhost:<proxy-port> pytest traffic/test_api.py`. Note the tests pass unchanged.
4. Replay the recording against instance-b (`regrade replay`).
5. Reduce noise via profile rules: `create_id_mapping` for the `$.token`, `create_filter_rule` DROP for `$.channels[*].created_at`; `apply_profile_to_replay` until `query_deltas(unlabeled_only=true)` returns only `$.password`.
6. The reveal: `$.password` is a bcrypt hash in a response body — the leak, found with zero prior knowledge and zero security assertions.
7. "Why this is different" box: same version, existing tests, the secret's entropy is the signal.

- [ ] **Step 2: Write `CLAUDE.md`** — tutor notes.

Must contain: the one-flaw rule (only `PATCH /users/<id>` leaks); the bcrypt-at-boot premise (`create_app()` re-salts, so instances differ); traffic suite must stay assertion-free on security; how to run app tests (`pytest tests/`) vs traffic (`pytest traffic/`); "map the token, drop the timestamp, the password survives."

- [ ] **Step 3: Verify the docs reference only real endpoints**

Run: `grep -oE '/(login|users|channels|health)[^ )`]*' README.md CLAUDE.md | sort -u`
Expected: only `/login`, `/users`, `/users/<id>`, `/channels`, `/health` appear — no invented endpoints.

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: walkthrough and tutor notes"
```

---

### Task 7: Live-validation gate (real sensor + alpha) — NON-NEGOTIABLE before the video

**Files:** none (produces validated numbers + recording/replay IDs recorded in memory).

This is an operator task, run by the session owner against the real ReGrade alpha with the real sensor CLI. It gates the video: on-screen numbers are these results.

- [ ] **Step 1: Bring the demo up**

Run: `docker compose up -d --build` (pre-pull `python:3.12-slim` first if the build hits a network DeadlineExceeded — known flake).
Verify: `curl -s localhost:8001/health` and `curl -s localhost:8002/health` both return `{"ok": true}`.

- [ ] **Step 2: Record the functional suite through the sensor**

Start `regrade proxy` in front of `http://localhost:8001`. Then:
`BASE_URL=http://localhost:<proxy-port> python -m pytest traffic/test_api.py -v`
Expected: 4 passed; a recording is captured.

- [ ] **Step 3: Replay against instance-b**

`regrade replay <recording-id>` targeting `http://localhost:8002`.
Expected: replay completes; raw deltas include `$.token`, `$.channels[*].created_at`, and `$.password` (on the PATCH response).

- [ ] **Step 4: Reduce noise via profile rules (MCP)**

- `create_id_mapping` for the login `$.token`.
- `create_filter_rule` DROP for `$.channels[*].created_at` (and any per-boot volatile IDs that appear).
- `apply_profile_to_replay`; repeat until `query_deltas(unlabeled_only=true)` returns **only the `$.password` delta(s)**.

Exit criterion: the sole surviving real finding is `$.password` — a bcrypt hash differing between instances. Record: recording ID, replay ID, raw delta count, post-profile finding = `$.password`.

- [ ] **Step 5: Save the validated numbers to memory**

Update `project_hello_regrade_security.md` with recording/replay IDs, raw→final delta counts, and the confirmed `$.password` finding. These are the video's on-screen numbers.

---

### Task 8: Branded video (reuses the hello-ReGrade pipeline)

**Files:**
- Create: `video/` (copied from `hello-ReGrade/video`, then adapted)
- Modify: `video/script.json`, `video/capture/scenes.sh`, `video/capture/build_clips.sh`, `video/remotion/src/SectionTag.tsx`, `video/remotion/src/BrandCard.tsx`, `video/remotion/src/OutroCard.tsx`, `video/remotion/src/Highlights.tsx`
- Test: `video/tests/test_script.py`

**Interfaces:** none (produces `video/out/hello-regrade.mp4`).

- [ ] **Step 1: Copy the pipeline**

```bash
cp -R ../hello-ReGrade/video ./video
rm -rf video/out video/node_modules
```

- [ ] **Step 2: Write `video/script.json`** — 8 beats from the spec:
`cold-open` · `problem` · `setup` · `noise` · `twist` · `reveal` · `why-tests-miss` · `outro`. Voiceover copy per the spec's video section; on-screen numbers = Task 7 results; reveal beat names CVE-2023-5968 as inspiration.

- [ ] **Step 3: Write the script beat-count test** (`video/tests/test_script.py`)

```python
# ABOUTME: Guards the security video's beat structure.
import json
import pathlib

EXPECTED = [
    "cold-open", "problem", "setup", "noise",
    "twist", "reveal", "why-tests-miss", "outro",
]


def test_eight_beats_in_order():
    script = json.loads((pathlib.Path(__file__).parents[1] / "script.json").read_text())
    assert [b["id"] for b in script["beats"]] == EXPECTED
```

- [ ] **Step 4: Run to verify the test passes** once `script.json` matches

Run: `cd video && python -m pytest tests/test_script.py -v`
Expected: PASS.

- [ ] **Step 5: Adapt Remotion copy** — `BrandCard.tsx` tagline ("catch the vulnerabilities your tests never asserted on"), `SectionTag.tsx` SECTIONS for the 8 beats + a "· Security" suffix, `OutroCard.tsx` link → `github.com/Curtail-Inc/hello-ReGrade-security`, `Highlights.tsx` CONFIG box on the `$.password` reveal line (calibrate after first render).

- [ ] **Step 6: Capture, build, render** — follow `video/README`/`build.sh` (VHS scenes → clips → episode → Remotion render + music mix). Output `video/out/hello-regrade.mp4`.

- [ ] **Step 7: Commit** (rendered mp4 is gitignored; commit sources)

```bash
git add video
git commit -m "feat: branded security demo video"
```

---

## Post-plan (handled outside subagent execution, mirrors hello-ReGrade-perf)

- Create the public GitHub repo `Curtail-Inc/hello-ReGrade-security` (as `slisteraley`), push.
- Upload video assets (`hello-regrade-security-demo.mp4`, `-poster.jpg`, `-demo.en.vtt`) to `s3://curtail-media/` (CloudFront `d1i30i0t92rg2h`), correct content-types; verify with a cache-busted request.
- Add the third entry to curtail.com's `demos[]` array (product page + jump links already support N demos) → MR → run full CI gate incl. `format:check` → deploy → verify live.
