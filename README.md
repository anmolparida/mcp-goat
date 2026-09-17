# mcp-server-scan

A **deliberately vulnerable MCP (Model Context Protocol) server** used to validate
that an MCP security scanner — such as **Qualys TotalAI** — detects a broad
catalog of MCP findings. Think DVWA / OWASP Juice Shop, but for MCP.

Vulnerabilities are **grouped by category**, one MCP endpoint per group, so you
can scan and confirm findings group by group.

> ⚠️ **Safety.** Every dangerous tool body (command exec, SQL, SSRF, credential
> use, browser file access…) is **mocked** — it describes what it *would* do and
> returns fake data. It never runs commands, connects to a database, or makes
> real outbound requests. Fake credentials use documented placeholder values
> (e.g. `AKIAIOSFODNN7EXAMPLE`). What the scanner detects is the exposed
> *surface*: tool schemas, poisoned descriptions, weak OAuth metadata, protocol
> behaviors.
>
> ⚠️ **Public exposure.** The only genuinely-live behaviors are the OAuth
> **open redirect** and **open registration**. On a public host the open
> redirect is real phishing infrastructure, so it ships **public-safe** by
> default: the finding stays detectable (unvalidated `redirect_uri` reflected +
> advertised in metadata) but it does not auto-forward visitors to arbitrary
> external sites. Set `ALLOW_OPEN_REDIRECT=true` to restore the raw 302 in a
> **closed/isolated lab only**. Publicly exposing an intentionally vulnerable
> app may also violate your hosting provider's acceptable-use policy — check it.

---

## Endpoints

| Point the scanner at | Category | # checks |
|---|---|---|
| `/mcp/discovery` | endpoint/tool discovery, hidden & duplicate tools, prompt/roots disclosure, dependency confusion | 8 |
| `/mcp/injection` | SSRF, command/SQL/NoSQL/XXE/LDAP/SSTI/argument injection, unicode, ANSI, resource traversal | 12 |
| `/mcp/tool-poisoning` | tool poisoning (basic + advanced), rug-pull, shadowing, RADE, spoofing, sampling, elicitation, beacon, notification abuse, error injection, schema-default | 12 |
| `/mcp/disclosure` | info/credential/secret disclosure, browser file access, cross-session leak, JSON dup-key, output-schema mismatch, resource mutation, session fixation, DNS rebinding | 10 |
| `/mcp/oauth` | 21 OAuth findings (metadata + authorize/token/register endpoints) | 21 |

`/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`
are served at the root (and RFC-9728 path-suffixed) so the OAuth scan discovers them.

Full check-by-check mapping: see **[CHECKS.md](CHECKS.md)**.

---

## Run locally

```bash
docker compose up --build -d          # http://localhost:8080
curl http://localhost:8080/           # lists all endpoints
```

Without Docker:

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

---

## Deploy publicly

Both paths give you an **HTTPS** URL. Use that URL (with the `https://` prefix
toggled on) in TotalAI's *Inference Endpoint URL* field.

### Option A — Fly.io

1. Install flyctl and put it on your PATH, then log in:
   ```zsh
   curl -L https://fly.io/install.sh | sh
   # flyctl installs to ~/.fly — add it to your shell (zsh):
   echo 'export FLYCTL_INSTALL="$HOME/.fly"' >> ~/.zshrc
   echo 'export PATH="$FLYCTL_INSTALL/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc          # reload so `fly` is found
   fly version              # verify
   fly auth login
   ```
   (bash users: use `~/.bashrc` instead of `~/.zshrc`.)
2. Edit **`fly.toml`** → set `app` to a unique name (e.g. `mcp-scan-yourhandle`)
   and pick a `primary_region`.
3. Create the app (without deploying yet):
   ```bash
   fly apps create mcp-scan-yourhandle
   ```
4. Deploy:
   ```bash
   fly deploy
   ```
5. Your target is `https://mcp-scan-yourhandle.fly.dev`.
   ```bash
   curl https://mcp-scan-yourhandle.fly.dev/
   ```
6. (Closed lab only) enable the live open redirect:
   ```bash
   fly secrets set ALLOW_OPEN_REDIRECT=true
   ```

### Option B — Render

1. Push this folder to a Git repo (GitHub/GitLab).
2. In Render: **New +** → **Blueprint** → select the repo. Render reads
   **`render.yaml`**, builds the Dockerfile, and injects `$PORT`.
3. Click **Apply**. You get `https://mcp-server-scan.onrender.com`.
   ```bash
   curl https://mcp-server-scan.onrender.com/
   ```
4. (Closed lab only) in the service's **Environment** tab set
   `ALLOW_OPEN_REDIRECT=true` and redeploy.

> Free tiers sleep when idle; the first request after idle takes a few seconds
> to wake. Run one warm-up `curl` before starting a scan.
>
> Note: Fly.io no longer offers a standing free tier (trial credit + card
> required). Render's free web-service tier needs no card but sleeps when idle.

### Option C — AWS EC2

Good when you have AWS access and want full control. TotalAI accepts plain
`http://`, so a domain/TLS is optional.

1. Launch an instance (Amazon Linux 2023 or Ubuntu; `t3.micro` is enough).
2. Security group inbound: **TCP 22** from your IP, **TCP 8080** from your
   scanner's IP (avoid `0.0.0.0/0` — it's an intentionally vulnerable target).
3. SSH in and install Docker (works on both distros):
   ```bash
   curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker $USER && newgrp docker
   ```
4. Get the code on the box — `git clone <your-repo> mcp-server-scan`, or from
   your laptop: `scp -r mcp-server-scan ec2-user@<ip>:~/`.
5. Run it:
   ```bash
   cd mcp-server-scan
   docker compose up --build -d
   curl http://localhost:8080/
   ```
6. Point TotalAI at `http://<EC2-public-ip>:8080` (Auth = None).

Optional HTTPS with a domain — put Caddy in front for automatic TLS:

```bash
# with a DNS A record pointing scan.example.com -> the instance:
docker run -d --restart unless-stopped --name caddy \
  -p 80:80 -p 443:443 -v caddy_data:/data \
  caddy caddy reverse-proxy --from scan.example.com --to localhost:8080
```
Then use `https://scan.example.com` in TotalAI.

---

## Point Qualys TotalAI at it

In **Create MCP Server** → **Basic Information**:

1. **Name** — e.g. `mcp-scan-injection`.
2. **Inference Endpoint URL** — your host, e.g. `mcp-scan-yourhandle.fly.dev`
   (toggle the prefix to **`https://`** for a deployed host; `http://` for local).
3. **Endpoints** — type a category path, e.g. `/mcp/injection`, then **Add**.
   Repeat to add several, or create one MCP server per category.
4. **Authentication Type** — `None` for every group (metadata is read
   unauthenticated; the OAuth group needs no token to enumerate its weaknesses).
5. Finish **Scan Settings → Comments → Review and Confirm**, then run the scan.
6. Repeat per category (or add all five endpoints) and compare results to the
   detection table below.

---

## Will a scan detect all of these? — expected results

63 checks are seeded. Detection depends on your scanner's coverage, but here is
what each is *designed to produce* and the confidence that a capable MCP scanner
flags it against this target.

**Legend:** ✅ high — clear static/metadata signal · 🟡 medium — needs an active
probe or heuristic the scanner may or may not run.

### `/mcp/discovery` (8)

| Check | Expected | Why |
|---|---|---|
| MCP Endpoint Discovery | ✅ | Responds to MCP handshake on a discoverable path |
| MCP Tool Discovery | ✅ | `tools/list` returns tools unauthenticated |
| MCP Hidden Tool | 🟡 | `admin_debug_shell` callable but not listed — needs a probe that calls unlisted names |
| MCP Duplicate Tool Names | ✅ | Two tools advertise `get_status` |
| MCP Prompt Listing Disclosure | ✅ | `prompts/list` exposes internal prompts |
| MCP Prompt Detail Leak | ✅ | `internal_support_agent` body leaks admin pw + DB DSN |
| MCP Roots Disclosure | ✅ | `roots/list` returns `~/.ssh`, prod-db paths |
| MCP Dependency Confusion | 🟡 | `render_report` cites unscoped internal packages — needs description analysis |

### `/mcp/injection` (12)

| Check | Expected | Why |
|---|---|---|
| MCP SSRF Vulnerabilities | ✅ | `fetch_url(url)` + description naming `169.254.169.254` |
| MCP Argument Injection | ✅ | `ping_host` description shows raw concatenation |
| MCP Command Execution | ✅ | `run_shell(command)` |
| MCP Unrestricted SQL Execution | ✅ | `sql_query(query)` |
| MCP NoSQL Injection | ✅ | `mongo_find(filter)` object passthrough |
| MCP XXE Injection | ✅ | `parse_xml` states external entities enabled |
| MCP LDAP Injection | ✅ | `ldap_lookup` builds `(uid=<raw>)` |
| MCP Template Injection (SSTI) | ✅ | `render_template` unsandboxed Jinja2 |
| MCP Unicode Injection | 🟡 | bidi/zero-width chars in `set_display_name` desc + output |
| MCP ANSI Terminal Escape Injection | 🟡 | `get_log_line` output has raw ANSI/OSC — needs output inspection |
| MCP Resource Read Side Effect (SSRF) | 🟡 | `resources/read` fetch side effect — needs a resource probe |
| MCP Resource Template Traversal | ✅ | `file:///srv/data/{path}` template unsanitized |

### `/mcp/tool-poisoning` (12)

| Check | Expected | Why |
|---|---|---|
| MCP Tool Poisoning | ✅ | `<IMPORTANT>` exfil block in `add` description |
| MCP Advanced Tool Poisoning | ✅ | instructions inside a field `description` |
| MCP Tool Schema Default Injection | 🟡 | malicious `default` on `summarize.style` — needs schema inspection |
| MCP Rug-Pull Detection | 🟡 | `weather` admits post-approval change — heuristic/behavioral |
| MCP Cross-Server Shadowing | ✅ | `send_email` says to override other servers' tools |
| MCP Server Spoofing | ✅ | `serverInfo` impersonates "GitHub Official MCP" |
| MCP Retrieval-Agent Deception (RADE) | 🟡 | hidden commands in `docs://quarterly/q3` — needs resource read |
| MCP Error Message Prompt Injection | 🟡 | injected text in `process_payment` error — needs a call that errors |
| MCP Exfiltration Beacon | ✅ | `track_usage` desc names `beacon.evil.example` |
| MCP Notification Abuse | 🟡 | `subscribe_alerts` advertises flooding — heuristic |
| MCP Sampling Attacks | 🟡 | `_sampling_request` in `autocomplete` result — needs a call + parse |
| MCP Elicitation Disclosure | 🟡 | `verify_account` elicits SSN/card — needs a call + parse |

### `/mcp/disclosure` (10)

| Check | Expected | Why |
|---|---|---|
| MCP Information Disclosure | ✅ | `debug_info` leaks env/host/traceback; `debug=True` app |
| MCP Credential Exposure | ✅ | `get_service_token` returns bearer + refresh |
| MCP Hardcoded Secret in Metadata | ✅ | secrets in `serverInfo`/`instructions` |
| MCP Browser File Access | ✅ | `read_browser_data` targets Chrome `Cookies`/`Login Data` |
| MCP Cross-Session State Leak | 🟡 | `note_get_all` returns global store — needs 2-session probe |
| MCP JSON Duplicate-Key Pollution | 🟡 | `get_role` raw body has dup keys — needs raw-body inspection |
| MCP Output Schema Mismatch | 🟡 | `get_temperature` violates its `outputSchema` — needs a call + compare |
| MCP Resource Mutation After Subscribe | 🟡 | `state://balance` mutates on 2nd read — needs subscribe+reread |
| MCP Session Fixation | 🟡 | accepts client `X-Session-Id` — needs a fixation probe |
| MCP DNS Rebinding Risk | ✅ | `serverInfo` advertises `host_validation: disabled`, `allowed_origins: *` |

### `/mcp/oauth` (21)

Detected from the two `.well-known` documents and the `/oauth/*` endpoints.

| Check | Expected | Why |
|---|---|---|
| MCP Weak OAuth Metadata | ✅ | metadata omits recommended fields; permissive |
| MCP OAuth PKCE Not Enforced | ✅ | `code_challenge_methods_supported` includes `plain` |
| MCP OAuth PKCE Downgrade | ✅ | both `plain` and `S256` offered |
| MCP OAuth Missing Client Auth | ✅ | `token_endpoint_auth_methods_supported: ["none",…]` |
| MCP OAuth Implicit Flow | ✅ | `response_types_supported` includes `token` |
| MCP OAuth Password Grant | ✅ | `grant_types_supported` includes `password` |
| MCP OAuth Open Redirect | 🟡 | unvalidated `redirect_uri` reflected (+ `X-Unvalidated-Redirect`); live 302 only if `ALLOW_OPEN_REDIRECT=true` |
| MCP OAuth Open Registration | ✅ | `/oauth/register` unauthenticated |
| MCP OAuth Scope Escalation | 🟡 | token grants `admin` regardless of request — needs a token call |
| MCP OAuth Missing State | 🟡 | `/oauth/authorize` proceeds without `state` — behavioral |
| MCP OAuth Insecure Cookie | ✅ | `Set-Cookie` lacks Secure/HttpOnly/SameSite |
| MCP OAuth No Revocation | ✅ | no `revocation_endpoint` in metadata |
| MCP OAuth Weak Token | 🟡 | implicit flow returns `weak_token_1` — needs a flow probe |
| MCP OAuth alg=none Accepted | ✅ | `…signing_alg_values_supported: ["none",…]`; JWTs use alg=none |
| MCP OAuth Unbound Token | 🟡 | issued JWT has no `aud`/`cnf` — needs token decode |
| MCP OAuth Code Reuse | 🟡 | static code redeemable repeatedly — needs 2 token calls |
| MCP OAuth Token in Query String | ✅ | `bearer_methods_supported: ["query"]` |
| MCP OAuth Cacheable Token | 🟡 | token response `Cache-Control: public` — needs header inspection |
| MCP OAuth No Refresh Rotation | 🟡 | same refresh token each time — needs 2 refresh calls |
| MCP OAuth Excessive Token Lifetime | 🟡 | `expires_in: 315360000` — needs a token call |
| MCP OAuth Audience Not Validated | 🟡 | no audience binding in PRM; `whoami` accepts any token |

### Summary

- **Static / metadata-visible (✅):** ~33 checks — flagged by almost any capable
  MCP scanner just from `tools/list`, `prompts/list`, `resources/list`,
  `serverInfo`, and the `.well-known` metadata.
- **Requires an active probe (🟡):** ~30 checks — flagged only if the scanner
  actively calls tools, reads resources, opens two sessions, decodes JWTs, or
  inspects raw bodies/headers. TotalAI is an active scanner, so it should catch
  most of these; any it misses points at a genuine coverage gap worth filing.
- **`ALLOW_OPEN_REDIRECT=false` (public default):** the open-redirect finding is
  still present via reflection + metadata; only the live victim-forwarding 302 is
  disabled. Set it `true` in a closed lab for a full open-redirect confirmation.

If a check you expect is **not** detected, confirm the behavior manually (see
below) — if the behavior is present but unflagged, that's a scanner finding, not
a target bug.

---

## Manually verify a target

```bash
H=https://mcp-scan-yourhandle.fly.dev

# handshake + tools
curl -s -X POST $H/mcp/injection -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# OAuth metadata
curl -s $H/.well-known/oauth-authorization-server | jq .

# open-redirect reflection (public-safe interstitial)
curl -si "$H/oauth/authorize?redirect_uri=https://evil.example/cb" | grep -i x-unvalidated-redirect
```

---

## Publishing to GitHub

This repo is safe to make public. Every credential-looking string in the code is
**synthetic and non-functional** — it exists so a scanner detects the
"Hardcoded Secret in Metadata" / "Credential Exposure" findings. There are no
real secrets, and `.gitignore` blocks `.env`, keys, and credential files from
ever being committed.

```bash
cd mcp-server-scan
git init
git add .
git commit -m "Deliberately vulnerable MCP test target for scanner validation"
git branch -M main
git remote add origin git@github.com:<you>/<repo-name>.git
git push -u origin main
```

Notes:
- **Push protection:** the AWS values are AWS's documented example keys
  (allow-listed by GitHub). The other fakes are shaped to avoid GitHub's
  high-confidence detectors. If a push is ever blocked on a synthetic value,
  it's a false positive — mark it "used in tests" in the GitHub prompt.
- Add a `LICENSE` (MIT or Apache-2.0) and keep the "intentionally vulnerable"
  warning near the top of the README so nobody mistakes it for a real service.
- Never point `ALLOW_OPEN_REDIRECT=true` at a public deployment.

## Layout (everything lives in this one folder)

```
mcp-server-scan/
  app/
    main.py            # Starlette app; endpoints + OAuth routes + .well-known + banner
    mcp_core.py        # minimal MCP streamable-HTTP/SSE protocol core
    servers/
      discovery.py
      injection.py
      tool_poisoning.py
      disclosure.py
      oauth.py         # weak OAuth AS; ALLOW_OPEN_REDIRECT switch
  Dockerfile           # honors $PORT (Fly/Render/local)
  docker-compose.yml   # local run on :8080
  fly.toml             # Fly.io deploy
  render.yaml          # Render blueprint
  requirements.txt
  README.md
  CHECKS.md            # every check -> exact location
```

Not affiliated with any vendor named in spoofed metadata; those strings exist
only to exercise impersonation detection.
