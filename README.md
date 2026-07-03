# hello-ReGrade-security

A hands-on demo of **zero-day discovery with [ReGrade](https://app.regrade.curtail.com)**.
You'll point an ordinary test suite at ReGrade, record it against a tiny service, **replay it
against a second copy of the same service**, and use **Claude Code + the ReGrade MCP tools** to
surface a **password-hash leak** — a vulnerability no test was written to find.

It models a real bug: **CVE-2023-5968**, where a collaboration platform's username-update
endpoint returned the full user object *including the bcrypt password hash*. It shipped in
2017 and survived 7 years of tests, reviews, and audits. ([Curtail's write-up](https://curtail.com/blog/how-we-found-a-7-year-old-vulnerability-on-the-first-replay).)

**The twist:** there is no `v2`. You compare the app **to itself**. A fresh instance hashes
its passwords with different bcrypt salts, so the leaked hash's *values differ between the two
copies* — and that entropy is what ReGrade flags. The vulnerability is latent in the code you
already shipped; no version change is needed to find it.

## What you'll need

- **Docker** (for the demo service) and **Python** (to run the traffic test suite).
- A **ReGrade account + API key** — sign up at https://app.regrade.curtail.com, install the
  `regrade` sensor from https://app.regrade.curtail.com/downloads, and set `REGRADE_API_KEY`
  (or `~/.regrade/key`).
- **Claude Code** with the ReGrade plugin:
  `claude plugin marketplace add https://app.regrade.curtail.com/downloads/latest/marketplace.json`
  then `claude plugin install regrade@regrade --scope user`, and connect it once (`/mcp`,
  signed into the same account as your key).

## The demo service

A tiny "team-chat" API (`app/store.py`) with users and channels. Docker Compose runs **two
identical copies** — same image, same code, no version flag:

- **instance-a** on `http://localhost:8001` — you record against this.
- **instance-b** on `http://localhost:8002` — you replay against this.

One endpoint has a planted flaw:

| Endpoint | Behavior |
|---|---|
| `GET /users/<id>` | **Sanitized** — never returns the password. The clean baseline. |
| `PATCH /users/<id>` (rename) | **The bug** — returns the full user object *including* the bcrypt `password` hash. One missing `sanitize()` call, exactly like CVE-2023-5968. |

Passwords are bcrypt-hashed **at boot**, so instance-a and instance-b hold *different* hashes
for the same user.

```bash
git clone https://github.com/Curtail-Inc/hello-ReGrade-security
cd hello-ReGrade-security
docker compose up -d --build
```

## 1. Record — point your existing tests at ReGrade

`traffic/test_api.py` is a normal functional test suite: login, read a user, rename a user,
list channels. It asserts CRUD behavior and makes **no security assertions** — it never checks
whether `password` leaks. (Why would it? No one knew the bug existed.)

Start the sensor proxy in front of instance-a:

```bash
regrade proxy --target http://localhost:8001 --port 19870
```

In another terminal, run the **same test suite** — just point `BASE_URL` at the proxy. This is
the only change:

```bash
BASE_URL=http://localhost:19870 python -m pytest traffic/test_api.py
```

All tests pass, unchanged. Stop the proxy (Ctrl-C); the recording uploads and prints a
`Recording ID: <uuid>` — note it.

## 2. Replay against instance-b

```bash
regrade replay --rec-id <RECORDING_ID> --target http://localhost:8002
```

Same code on both sides — the only differences are the values that a fresh instance generates.

## 3. Find the leak in Claude Code

Open this repo in Claude Code and ask it to walk you through the replay. Guided by this repo's
`CLAUDE.md`, it will:

- run `summarize_deltas` → several deltas: the login `token`, channel `created_at` timestamps,
  and — quietly among them — `$.password`.
- **reduce the noise with profile rules** (the reusable, correct path):
  - `create_id_mapping` for the session `$.token` (a dynamic ID, not noise to drop),
  - `create_filter_rule` **DROP** for `$.channels[*].created_at` (a per-boot timestamp),
  - `apply_profile_to_replay`, then `query_deltas(unlabeled_only=true)` — repeat until only one
    delta remains.
- **The reveal:** the surviving delta is **`$.password`** — a bcrypt hash in a response body.
  A CVE-class leak, found with zero prior knowledge and zero security assertions.

## 4. Why this is different

The session token and the password hash *both* differ between the two runs — both are
high-entropy strings that change every time. One is legitimate noise you **map**; the other is
a **breach**. You can't tell them apart by "it changed" — you have to look at *what* changed.
Filter every high-entropy field away as noise and you'd have hidden the vulnerability.

That's the lesson: ReGrade doesn't validate expectations, it compares behavior — so it can
surface the bugs no one thought to write a test for.

## How the leak works

`app/store.py` is one file. The `GET` paths call `sanitize()`; the `PATCH` path forgets to.
Look *after* you've found it with ReGrade — the point is that ReGrade caught it from **traffic
alone**, comparing the app to itself.

## License

Apache-2.0.
