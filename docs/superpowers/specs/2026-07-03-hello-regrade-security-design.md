# hello-ReGrade-security — Design

**Goal:** A public, reproducible demo (app + branded video) showing ReGrade catch a real-CVE-class password-hash leak by comparing an app **to itself** — no version change, no security test, the leaked secret's own per-instance entropy is the detection signal. Third sibling to `hello-ReGrade` (behavioral regression) and `hello-ReGrade-perf` (performance regression).

## Background — the real story

Models **CVE-2023-5968** (Mattermost password-hash disclosure), as told in Curtail's case study "How We Found a 7-Year-Old Vulnerability — On the First Replay":

- When a user updated their username, the server returned the full user object **including the bcrypt `password` hash** in the response body. One missing `Sanitize()` call, in a single code path. The bug shipped in 2017 and survived 7 years of tests, reviews, and audits.
- ReGrade found it by recording **22 standard API tests** (no security assertions) through its proxy, then replaying — **same version on both sides**. A fresh server instance hashes passwords with **different bcrypt salts**, so the leaked hash's *values differ between record and replay*. That entropy is the signal: ReGrade flags `$.password` as an unexplained delta. 3,730 raw deltas → ID mappings + filter rules → **2 findings, both on `$.password`**.

Two properties make this fundamentally different from the other two demos (which both diff v1 vs v2):
1. **Same version both sides** — the vuln is latent in the *current* code; no `v2` needed.
2. **The traffic is a regular functional test suite** — passing tests with no security assertions, pointed at ReGrade via one env var.

## Non-goals (YAGNI)

- Not a general vulnerable-app zoo. Exactly **one** planted flaw (the `$.password` leak), plus enough clean surface to make the noise-reduction arc real.
- No real Mattermost code, no impersonation. A small, generic "team-chat" API that *echoes* Mattermost's domain (users, channels) and cites the CVE as inspiration.
- No `v2`. There is one codebase; the two sides are two **instances** of it.
- No auth hardening, rate limiting, persistence, or UI. In-memory data, like the siblings.

## Architecture

### The app (`app/store.py`, Flask, `create_app()`)

A small team-chat API. In-memory seed data: ~4 users, a couple of channels.

Endpoints:
- `POST /login` — body `{username, password}`; on success returns `{token: <random session token>, user_id}`. The **token is fresh per call/instance** → legitimate noise that must be ID-mapped (echoes hello-ReGrade's token-as-map, reinforces *mapping ≠ noise*).
- `GET /users` — list users, **sanitized** (no password field). Clean volume.
- `GET /users/<id>` — one user, **sanitized**. The clean baseline for the field that will leak.
- `PATCH /users/<id>` — update `display_name`/username. **THE BUG:** returns the full stored user object **including `password`** (the bcrypt hash) — the missing sanitize, faithful to the CVE's "username update" path.
- `GET /channels` — list channels. Clean volume + a timestamp field (`created_at`) → legitimate noise.

Password handling (the crux):
- Seed users carry **plaintext demo passwords in the seed data**; the app **bcrypt-hashes them at startup** with a fresh random salt each boot (`bcrypt.hashpw`). Therefore instance A and instance B hold **different hash strings for the same password**. This is what makes "same version, different values" true — the demo's analog of Mattermost re-salting on a fresh instance.
- A `sanitize(user)` helper strips `password` for the response. `GET` paths call it; the `PATCH` path **forgets to** — the entire bug is that one omission.

### Two identical instances (`docker-compose.yml`)

Runs the **same image twice**: `instance-a` (:8001) and `instance-b` (:8002), identical `APP` code, no version env var. Record traffic against A, replay against B. (Contrast: the siblings run `v1`/`v2`.)

### Traffic = a regular functional test suite (`traffic/test_api.py`, pytest)

The faithful centerpiece. A **passing functional test suite** with **no security assertions** — it asserts normal CRUD behavior only:
- login succeeds and returns a token,
- `GET /users/<id>` returns the expected `display_name`,
- `PATCH /users/<id>` renames and echoes the new name (asserts on `display_name`, **not** on the absence of `password`),
- `GET /channels` lists channels.

Base URL comes from `BASE_URL` (default `http://localhost:8001`, i.e. instance A directly). **Recording = run the same tests with `BASE_URL` pointed at the sensor proxy** — one env var, tests pass unchanged. This is the "point your existing tests at ReGrade" moment.

### Detection flow (the demo's spine)

1. `regrade proxy` in front of `instance-a`; run `traffic/test_api.py` against the proxy → tests pass, HAR recorded.
2. `regrade replay` the recording against `instance-b` (same code, fresh salts).
3. Raw deltas appear on: session `token` (per-instance), `created_at` timestamps, any per-boot IDs — **and** `password` on the `PATCH` response.
4. Noise reduction via **profile rules** (the reusable, correct path): `create_id_mapping` for the session token, `create_filter_rule` (DROP) for timestamps/volatile IDs; `apply_profile_to_replay` until only the real finding remains.
5. **What survives: `$.password`** — a bcrypt hash in a response body. The CVE-class leak, surfaced with zero prior knowledge and zero security assertions.

### The lesson (the differentiator)

Two high-entropy fields differ between the two runs. One is a **session token** — real noise, you map it. One is a **bcrypt password hash** — a **breach**. You cannot tell them apart by "it changed between runs"; you have to look at *what* is differing. Carelessly filtering all high-entropy fields as noise would have hidden the vuln. This is the teaching point neither sibling makes, and it ties directly to the *mapping-is-not-noise* framing.

## Video

Reuse the `hello-ReGrade` pipeline (Remotion + VHS + ElevenLabs, `music_mix.sh`, id-cached voice takes), ~3 min, brand red `#E0001F`. Beats:

1. **Cold-open** — "This bug hid in production for 7 years. Every test passed."
2. **Problem** — tests validate expectations; they cannot find what no one thought to assert.
3. **Setup** — record/replay the **same version**; point the *existing* test suite at ReGrade (one env var), tests pass unchanged.
4. **Noise** — many deltas; map the session token, drop the timestamps (mapping ≠ noise).
5. **The twist** — one high-entropy field is *not* noise.
6. **The reveal** — `$.password` = a bcrypt hash in a response body = CVE-class leak. Cite CVE-2023-5968 as the real-world inspiration.
7. **Why tests miss it** — detecting unknowns ≠ validating expectations.
8. **Outro** — link `github.com/Curtail-Inc/hello-ReGrade-security`, brand card.

On-screen numbers are the demo's own validated results (not Mattermost's), with the CVE cited as inspiration.

## Repo structure (sibling to hello-ReGrade-perf)

```
hello-ReGrade-security/
├── app/
│   ├── store.py            # Flask create_app(); the leak + sanitize + bcrypt-at-boot
│   ├── Dockerfile
│   └── requirements.txt    # flask, bcrypt
├── traffic/
│   └── test_api.py         # passing functional pytest suite = recording traffic
├── tests/
│   └── test_store.py       # app-correctness unit tests (see Testing)
├── docker-compose.yml      # instance-a:8001 + instance-b:8002, identical image
├── video/                  # copied hello-ReGrade pipeline, security script
├── docs/superpowers/       # this spec + the plan
├── README.md               # walkthrough (record→replay→profile→reveal)
├── CLAUDE.md               # tutor notes
└── LICENSE                 # Apache-2.0
```

## Testing

Two distinct test layers (do not conflate):
- **App-correctness unit tests** (`tests/test_store.py`): the demo app behaves as designed —
  - `GET /users/<id>` response has **no** `password` field (sanitized),
  - `PATCH /users/<id>` response **does** include `password` (the planted leak — asserted present, so a future refactor can't silently "fix" the demo),
  - two `create_app()` instances produce **different** `password` hashes for the same seed user (proves the per-instance-entropy premise the whole demo rests on),
  - `login` returns a token; `sanitize()` strips `password`.
- **Traffic suite** (`traffic/test_api.py`): passing functional tests, **no** security assertions (asserting the leak here would defeat the "tests can't see it" narrative).

**Live validation gate (must pass before shipping):** using the real sensor + alpha, record the traffic suite against instance A, replay against instance B, build a profile (ID-map the token, drop timestamps), `apply_profile_to_replay`, and confirm ReGrade surfaces **exactly the `$.password` finding** with `query_deltas(unlabeled_only=true)` → the password delta(s) as the sole real finding. Record the recording/replay IDs in memory.

## Global Constraints

- **Language/stack:** Python 3.12, Flask, `bcrypt`. In-memory only. Match sibling conventions (`create_app()`, `_json()` with `sort_keys=True` for byte-stable bodies where relevant).
- **One flaw only:** the `$.password` leak on `PATCH /users/<id>`. No other planted vulns.
- **Same version both sides:** no `v1`/`v2`; two instances of one image.
- **Traffic is passing functional tests** with no security assertions.
- **Public, Apache-2.0, `Curtail-Inc/hello-ReGrade-security`,** pushed as `slisteraley`.
- **Brand:** red `#E0001F`; reuse hello-ReGrade video pipeline; cite CVE-2023-5968 as inspiration, no Mattermost code or impersonation.
- **Hosting:** after validation, add as the 3rd entry in curtail.com's `demos[]` array (product page + jump links already support N demos).

## Success Criteria

1. `docker compose up` runs two identical instances; the traffic suite passes green against either.
2. App-correctness unit tests pass, including the "two instances → different password hashes" test.
3. Live gate: real record→replay→profile surfaces the `$.password` leak as the sole real finding after mapping the session token and dropping timestamps.
4. ~3-min branded video rendered, faithful beats, CVE cited, correct on-screen numbers.
5. Public repo shipped; curtail.com updated to host it as the third demo.
