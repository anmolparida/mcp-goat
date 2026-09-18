# 🐐 mcp-server-scan

> **A deliberately vulnerable MCP (Model Context Protocol) server — a punching bag for MCP security scanners.**
> DVWA and OWASP Juice Shop walked so this could run. Point your scanner at it and watch the findings light up.

<p align="center">
  <img alt="status" src="https://img.shields.io/badge/status-lab%20use%20only-red">
  <img alt="checks" src="https://img.shields.io/badge/seeded%20findings-63-blue">
  <img alt="transport" src="https://img.shields.io/badge/MCP-streamable%20HTTP%20%2B%20SSE-informational">
  <img alt="license" src="https://img.shields.io/badge/license-MIT-green">
</p>

Building or testing an MCP security scanner (like **Qualys TotalAI**)? You need a
target that fails *on purpose*. This one seeds **63 distinct MCP findings** across
five categories — from classic injection to OAuth misconfig to MCP-native attacks
like tool poisoning, rug-pulls, and RADE — each **grouped behind its own endpoint**
so you can scan a category and tick the findings off one by one.

Every finding is engineered to be **detectable but harmless**: the scanner sees a
real vulnerable *surface*, while the box behind it can't actually hurt anything.

### Why you'd use it

- ✅ **Benchmark a scanner** — know exactly what *should* be found, then measure what *is*.
- 🕵️ **Find coverage gaps** — anything on the list your scanner misses is a real gap worth filing.
- 🎓 **Learn / demo** — a safe sandbox to see what MCP attacks actually look like on the wire.
- ⚡ **Deploy in minutes** — Docker in, HTTPS URL out. EC2, Fly, or Render.

> ⚠️ **It's a decoy, not a weapon.** Every dangerous tool body (command exec, SQL,
> SSRF, credential use, browser file access…) is **mocked** — it *describes* what it
> would do and returns fake data. It never runs a command, touches a database, or
> makes a real outbound request. Credential-looking strings are synthetic (e.g. the
> documented placeholder `AKIAIOSFODNN7EXAMPLE`). The scanner detects the exposed
> *surface* — tool schemas, poisoned descriptions, weak OAuth metadata, protocol
> quirks — not a live exploit.
>
> ⚠️ **Two behaviors are genuinely live:** the OAuth **open redirect** and **open
> registration**. On the public internet an open redirect is real phishing plumbing,
> so it ships **public-safe** by default — the finding stays detectable (unvalidated
> `redirect_uri` reflected + advertised in metadata) but it won't forward visitors to
> arbitrary external sites. Flip `ALLOW_OPEN_REDIRECT=true` only in a **closed lab**.
> Also: hosting an intentionally vulnerable app may violate your provider's AUP —
> check before you deploy.

---

## ⚡ 60-second quickstart (local)

```bash
docker compose up --build -d          # boots on http://localhost:8080
curl http://localhost:8080/           # lists every endpoint
```

No Docker? `pip install -r requirements.txt && uvicorn app.main:app --host 0.0.0.0 --port 8080`

Then jump to [Point your scanner at it](#-point-qualys-totalai-at-it).

---

## 🎯 What's inside — five targets, 63 findings

| Point the scanner at | What it seeds | Findings |
|---|---|---|
| `/mcp/discovery` | endpoint/tool discovery, hidden & duplicate tools, prompt/roots disclosure, dependency confusion | **8** |
| `/mcp/injection` | SSRF, command/SQL/NoSQL/XXE/LDAP/SSTI/argument injection, unicode, ANSI, resource traversal | **12** |
| `/mcp/tool-poisoning` | tool poisoning (basic + advanced), rug-pull, shadowing, RADE, spoofing, sampling, elicitation, beacon, notification abuse, error injection, schema-default | **12** |
| `/mcp/disclosure` | info/credential/secret disclosure, browser file access, cross-session leak, JSON dup-key, output-schema mismatch, resource mutation, session fixation, DNS rebinding | **10** |
| `/mcp/oauth` | the full OAuth misconfig buffet (metadata + authorize/token/register) | **21** |

The OAuth metadata is served at `/.well-known/oauth-authorization-server` and
`/.well-known/oauth-protected-resource` (root **and** RFC-9728 path-suffixed) so
scanners discover it automatically.

📋 **Every check mapped to its exact tool/endpoint:** see **[CHECKS.md](CHECKS.md)**.

---

## 🚀 Deploy publicly

Pick a host, get a URL, scan it. TotalAI accepts plain `http://`, so TLS is optional.

### Option A — AWS EC2 (recommended)

Full control, no free-tier games, and you can lock it to your scanner's IP.

1. Launch an instance (Amazon Linux 2023 or Ubuntu; `t3.micro` is plenty).
2. Security group inbound: **TCP 22** from your IP, **TCP 8080** from your
   scanner's IP. Skip `0.0.0.0/0` — this is a vulnerable target, keep it on a leash.
3. SSH in and install Docker (works on both distros):
   ```bash
   curl -fsSL https://get.docker.com | sudo sh
   sudo usermod -aG docker $USER && newgrp docker
   ```
4. Get the code on the box:
   ```bash
   git clone https://github.com/anmolparida/mcp-goat.git && cd mcp-goat
   # or from your laptop:  scp -r mcp-server-scan ec2-user@<ip>:~/
   ```
5. Launch it:
   ```bash
   docker compose up --build -d
   curl http://localhost:8080/
   ```
6. Point TotalAI at `http://<EC2-public-ip>:8080` (Auth = None). Done.

<details>
<summary>Optional: HTTPS on your own domain (Caddy, auto-TLS)</summary>

With a DNS `A` record for `scan.example.com` pointing at the instance:

```bash
docker run -d --restart unless-stopped --name caddy \
  -p 80:80 -p 443:443 -v caddy_data:/data \
  caddy caddy reverse-proxy --from scan.example.com --to localhost:8080
```
Then use `https://scan.example.com` in TotalAI.
</details>

### Option B — Fly.io

Gives you an `https://<app>.fly.dev` URL. Note: Fly no longer has a standing free
tier (trial credit + card required).

1. Install flyctl and get it on your PATH:
   ```zsh
   curl -L https://fly.io/install.sh | sh
   echo 'export FLYCTL_INSTALL="$HOME/.fly"' >> ~/.zshrc
   echo 'export PATH="$FLYCTL_INSTALL/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc      # bash users: use ~/.bashrc
   fly version && fly auth login
   ```
2. In **`fly.toml`**, set `app` to a unique name and pick a `primary_region`.
3. Ship it:
   ```bash
   fly apps create <your-app-name>
   fly deploy
   curl https://<your-app-name>.fly.dev/
   ```
4. Closed lab only: `fly secrets set ALLOW_OPEN_REDIRECT=true`.

### Option C — Render

Zero-CLI, no card needed (free tier sleeps when idle).

1. Push this repo to GitHub/GitLab.
2. Render → **New +** → **Blueprint** → pick the repo. It reads **`render.yaml`**,
   builds the Dockerfile, and injects `$PORT`.
3. **Apply** → you get `https://<service>.onrender.com`.
4. Closed lab only: set `ALLOW_OPEN_REDIRECT=true` in **Environment** and redeploy.

> 💤 Free tiers sleep when idle — fire one warm-up `curl` before you start a scan.

---

## 🔍 How to scan an MCP server with Qualys TotalAI

[**Qualys TotalAI**](https://www.qualys.com/apps/totalai) is an AI/LLM security
platform that scans MCP servers for the kinds of findings this target seeds. Here's
how to point it at your deployment.

**TotalAI → Create MCP Server → Basic Information:**

1. **Name** — e.g. `mcp-scan-injection`.
2. **Inference Endpoint URL** — your host (toggle **`https://`** for a deployed box,
   `http://` for local or a bare EC2 IP).
3. **Endpoints** — type a category path like `/mcp/injection`, hit **Add**. Add
   several, or make one MCP server per category.
4. **Authentication Type** — `None` for every group (even OAuth — the weaknesses are
   enumerable unauthenticated).
5. Walk through **Scan Settings → Comments → Review and Confirm**, then run the scan.
6. Repeat per category and check the results against the scorecard below. 👇

Learn more about TotalAI: <https://www.qualys.com/apps/totalai>

---

## ✅ Will it detect everything? — the scorecard

63 findings are seeded. Here's what each is *designed* to produce and how likely a
capable MCP scanner is to catch it.

**Legend:** ✅ **high** — clear static/metadata signal · 🟡 **medium** — needs an
active probe or heuristic the scanner may or may not run.

<details open>
<summary><b>/mcp/discovery — 8 findings</b></summary>

| Check | Likely | Signal |
|---|---|---|
| MCP Endpoint Discovery | ✅ | Responds to the MCP handshake on a discoverable path |
| MCP Tool Discovery | ✅ | `tools/list` returns tools unauthenticated |
| MCP Hidden Tool | 🟡 | `admin_debug_shell` is callable but unlisted — needs an unlisted-name probe |
| MCP Duplicate Tool Names | ✅ | Two tools both advertise `get_status` |
| MCP Prompt Listing Disclosure | ✅ | `prompts/list` exposes internal prompts |
| MCP Prompt Detail Leak | ✅ | `internal_support_agent` body leaks admin pw + DB DSN |
| MCP Roots Disclosure | ✅ | `roots/list` returns `~/.ssh`, prod-db paths |
| MCP Dependency Confusion | 🟡 | `render_report` cites unscoped internal packages — needs description analysis |

</details>

<details>
<summary><b>/mcp/injection — 12 findings</b></summary>

| Check | Likely | Signal |
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

</details>

<details>
<summary><b>/mcp/tool-poisoning — 12 findings</b></summary>

| Check | Likely | Signal |
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

</details>

<details>
<summary><b>/mcp/disclosure — 10 findings</b></summary>

| Check | Likely | Signal |
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

</details>

<details>
<summary><b>/mcp/oauth — 21 findings</b> (from the two <code>.well-known</code> docs + <code>/oauth/*</code>)</summary>

| Check | Likely | Signal |
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

</details>

**Bottom line:** ~**33** findings are static/metadata-visible (✅ — almost any scanner
gets these from `tools/list`, `prompts/list`, `resources/list`, `serverInfo`, and the
`.well-known` docs). ~**30** need an active probe (🟡 — calling tools, reading
resources, opening two sessions, decoding JWTs, inspecting raw bodies/headers).
TotalAI is an active scanner, so it should catch most of the 🟡 set — and **anything
it misses is a real coverage gap**, which is the whole point.

> If a check you expect isn't flagged, confirm the behavior by hand (below). Behavior
> present but unflagged = a scanner finding, not a target bug.

---

## 🧪 Verify a target by hand

```bash
H=http://localhost:8080      # or your deployed URL

# handshake + tool list
curl -s -X POST $H/mcp/injection -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# weak OAuth metadata
curl -s $H/.well-known/oauth-authorization-server | jq .

# open-redirect reflection (public-safe interstitial)
curl -si "$H/oauth/authorize?redirect_uri=https://evil.example/cb" | grep -i x-unvalidated-redirect
```

---

## 📁 Layout

```
mcp-server-scan/
  app/
    main.py            # Starlette app: endpoints + OAuth routes + .well-known + banner
    mcp_core.py        # minimal MCP streamable-HTTP/SSE protocol core
    servers/
      discovery.py     # 8 findings
      injection.py     # 12 findings
      tool_poisoning.py# 12 findings
      disclosure.py    # 10 findings
      oauth.py         # weak OAuth AS + ALLOW_OPEN_REDIRECT switch (21 findings)
  Dockerfile           # honors $PORT (EC2/Fly/Render/local)
  docker-compose.yml   # local run on :8080
  fly.toml             # Fly.io deploy
  render.yaml          # Render blueprint
  requirements.txt
  CHECKS.md            # every check → its exact location
  README.md
  LICENSE              # MIT
```

Adding a check? Drop a `Tool`/`Prompt`/`ResourceEntry` into the relevant
`app/servers/*.py` — the description/schema/behavior *is* the signal. The core
supports any number of endpoints, so you can also split a category into
one-finding-per-URL servers.

---

## 📜 License

[MIT](LICENSE). This is an **intentionally vulnerable** test target — every
credential-like value is synthetic and non-functional. Run it in an isolated lab
only; the authors accept no liability for misuse. Not affiliated with any vendor
named in spoofed metadata; those strings exist purely to exercise impersonation
detection.
