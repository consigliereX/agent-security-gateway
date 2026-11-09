<div align="center">

# Agent Security Gateway

### A production-hardened, stateful security gateway for AI agents

<p>
  <img src="https://img.shields.io/badge/STATUS-v1.0.0-111111?style=for-the-badge&logo=github&logoColor=white" />
  <img src="https://img.shields.io/badge/TESTS-UNIT%20TESTED-111111?style=for-the-badge&logo=checkmarx&logoColor=white" />
  <img src="https://img.shields.io/badge/PYTHON-3.11%2B-111111?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FASTAPI-GATEWAY-111111?style=for-the-badge&logo=fastapi&logoColor=white" />
</p>

**Secure the agent before it acts.**

</div>

---

## Overview

Agent Security Gateway sits between an AI agent and real-world execution surfaces.

It inspects prompts, tool calls, session behavior, approval requirements, and returned outputs **before** sensitive actions are allowed to proceed. The goal is simple: convert free-moving agent behavior into a controlled, auditable, policy-enforced execution path.

This project is a serious internal baseline for agent security. It is designed to reduce operational risk, not to claim perfect safety.

---

## Why this exists

Modern agents can move from text to action fast:

- prompt → plan
- plan → tool call
- tool call → shell, filesystem, network, memory
- output → leakage, drift, or escalation

Without a security layer, that chain is too direct.

This gateway introduces a single control path that can:

- inspect risky intent
- score multi-step session behavior
- require approval for dangerous actions
- redact sensitive output
- expose audit and operator visibility
- enforce auth, rate limiting, and health boundaries at the service edge

---

## Architecture

```mermaid
flowchart TD
    A[User / Agent Runtime] --> B[Agent Security Gateway]

    subgraph B1[Gateway Control Plane]
        B --> C[Detection]
        B --> D[Policy]
        B --> E[Session Risk]
        B --> F[Approval]
        B --> G[Redaction]
        B --> H[Audit]
        B --> I[Auth / Rate Limit / Metrics]
    end

    B --> J[Controlled Adapters]

    subgraph J1[Execution Adapters]
        J --> K[Shell]
        J --> L[Filesystem]
        J --> M[HTTP]
        J --> N[Memory]
    end

    K --> O[Execution Surfaces]
    L --> O
    M --> O
    N --> O
```

### Design rules

- **Single enforcement path** — decisions are made in the gateway/service layer
- **Thin adapters** — adapters do not carry their own policy engines
- **Fail closed** — denied, invalid, expired, or replayed requests do not execute
- **Central redaction** — masking happens in one pipeline, not ad hoc in adapters
- **Session-aware enforcement** — repeated lower-risk behavior can escalate over time

---

## Core capabilities

<table>
  <tr>
    <td><b>Inspection</b></td>
    <td>Prompt injection, secret leakage, indirect tool abuse, unsafe action-chain detection</td>
  </tr>
  <tr>
    <td><b>Session Risk</b></td>
    <td>Cross-call escalation, staged action tracking, cumulative risk scoring</td>
  </tr>
  <tr>
    <td><b>Execution Control</b></td>
    <td>Mediated shell, filesystem, HTTP, and memory adapters</td>
  </tr>
  <tr>
    <td><b>Approval</b></td>
    <td>One-time, expiring, action-bound permits for high-risk actions</td>
  </tr>
  <tr>
    <td><b>Redaction</b></td>
    <td>Central masking of secrets, high-entropy tokens, and optional PII</td>
  </tr>
  <tr>
    <td><b>Visibility</b></td>
    <td>Operator overview, session timeline, audit persistence, metrics</td>
  </tr>
  <tr>
    <td><b>Service Hardening</b></td>
    <td>Auth, rate limiting, health/readiness probes, Docker packaging</td>
  </tr>
</table>

---

## Decision model

The gateway can return:

| Decision | Meaning |
|---|---|
| `allow` | Execute normally |
| `allow_with_redaction` | Execute, but sanitize returned output |
| `challenge` | Deny by default and require further handling |
| `require_approval` | Pause execution pending approval |
| `block` | Deny execution |

### Important semantics

- `allow_with_redaction` only upgrades from a base `allow`
- a true `block` remains `block`
- approval is bound to normalized action context
- approval does **not** bypass the rest of inspection
- replayed or expired permits fail closed

---

## What the gateway protects against

- prompt injection
- secret leakage
- indirect tool abuse
- unsafe multi-step chains
- risky session buildup
- sensitive output exposure

## What it does **not** guarantee

- complete jailbreak prevention
- perfect semantic reasoning against novel attacks
- safety if tools bypass the gateway entirely
- cluster-global rate limiting in the current release
- enterprise identity maturity beyond shared-secret auth in the current release

---

## Repository structure

```text
.
├── .dockerignore
├── .gitignore
├── Dockerfile
├── firewall_config.example.json
├── pyproject.toml
├── README.md
├── configs/
│   ├── dev_profile.json
│   ├── production_profile.json
│   └── strict_profile.json
├── firewall/
│   ├── __init__.py
│   ├── adapters.py
│   ├── api.py
│   ├── approval_store.py
│   ├── audit_store.py
│   ├── chain_guard.py
│   ├── client.py
│   ├── config.py
│   ├── detectors.py
│   ├── engine.py
│   ├── gateway.py
│   ├── logging_utils.py
│   ├── main.py
│   ├── models.py
│   ├── policy.py
│   ├── redaction.py
│   ├── session_risk.py
│   ├── session_store.py
│   └── types.py
├── gateway/
│   ├── __init__.py
│   ├── app.py
│   ├── controls.py
│   ├── routes_approval.py
│   ├── routes_health.py
│   ├── routes_inspect.py
│   ├── routes_operator.py
│   └── service.py
├── scripts/
│   └── benchmark_firewall.py
└── tests/
    ├── corpus/
    │   └── security_cases.json
    ├── test_adapters.py
    ├── test_adversarial_vectors.py
    ├── test_approval_flow.py
    ├── test_cli.py
    ├── test_config.py
    ├── test_corpus.py
    ├── test_engine.py
    ├── test_firewall.py
    ├── test_gateway.py
    ├── test_gateway_http.py
    ├── test_operator_console.py
    ├── test_redaction.py
    ├── test_redaction_gateway.py
    └── test_types_api.py
```

---

## Quickstart

### Install
```powershell
python -m pip install -e .
```

### Run the gateway
```powershell
uvicorn gateway.app:app --host 127.0.0.1 --port 8000
```

### Run tests
```powershell
python -m unittest discover -s tests -p "test_*.py"
```

### Production-like local run
Configure two **distinct** high-entropy credentials (agent and operator).
Agent credentials may inspect/submit, but **cannot** approve or read the operator console.
Never put example keys on a publicly reachable service.
```powershell
$env:FIREWALL_CONFIG="configs/production_profile.json"
$env:GATEWAY_AUTH_ENABLED="true"
$env:GATEWAY_API_KEYS="replace-with-random-agent-key"
$env:GATEWAY_OPERATOR_API_KEYS="replace-with-different-random-operator-key"
$env:GATEWAY_RATE_LIMIT_ENABLED="true"
$env:GATEWAY_RATE_LIMIT_REQUESTS="120"
$env:GATEWAY_RATE_LIMIT_WINDOW_SECONDS="60"
uvicorn gateway.app:app --host 127.0.0.1 --port 8000
```

### Docker
```powershell
docker build -t agent-security-gateway:local .
docker run --rm -p 8000:8000 ^
  -e GATEWAY_AUTH_ENABLED=true ^
  -e GATEWAY_API_KEYS=replace-with-random-agent-key ^
  -e GATEWAY_OPERATOR_API_KEYS=replace-with-different-random-operator-key ^
  -e GATEWAY_RATE_LIMIT_ENABLED=true ^
  -e GATEWAY_RATE_LIMIT_REQUESTS=60 ^
  -e GATEWAY_RATE_LIMIT_WINDOW_SECONDS=60 ^
  -e FIREWALL_SESSION_DB=/tmp/gateway.sqlite3 ^
  agent-security-gateway:local
```

---

## Configuration profiles

| Profile | Purpose |
|---|---|
| `configs/dev_profile.json` | easiest local workflow |
| `configs/production_profile.json` | recommended baseline deployment profile |
| `configs/strict_profile.json` | higher sensitivity, more aggressive blocking/redaction |

### Key environment controls

- `FIREWALL_CONFIG`
- `FIREWALL_SESSION_DB`
- `FIREWALL_ALLOW_WITH_REDACTION`
- `FIREWALL_REDACTION_ENABLED`
- `FIREWALL_REDACTION_MASK_PII`
- `GATEWAY_AUTH_ENABLED`
- `GATEWAY_AUTH_HEADER`
- `GATEWAY_API_KEYS` — agent/API credentials
- `GATEWAY_OPERATOR_API_KEYS` — separate operator credentials; mandatory for `/approval/resolve` and `/operator`
- `GATEWAY_RATE_LIMIT_ENABLED`
- `GATEWAY_RATE_LIMIT_REQUESTS`
- `GATEWAY_RATE_LIMIT_WINDOW_SECONDS`

---

## Redaction model

Sensitive output masking is centralized in the service layer.

### Supported masking
- secret key/value forms such as `api_key=...` and `token=...`
- JWT-like and AWS-key-like patterns
- high-entropy tokens
- optional PII masking for email, phone, and SSN

### Deterministic mask format
```text
[REDACTED:<kind>:<sha256-prefix>]
```

### Example
```text
Raw:
api_key=SECRET123 user=alice@example.com

Sanitized:
api_key=[REDACTED:secret:...] user=[REDACTED:pii_email:...]
```

---

## API surface

### Health and metrics
- `GET /health`
- `GET /ready`
- `GET /metrics`

### Inspection
- `POST /inspect/input`
- `POST /inspect/tool-call`

### Approval
- `POST /approval/submit` — agent credential (when authentication enabled)
- `POST /approval/resolve` — **operator credential required** even if general auth is disabled

The operator console (`/operator` and `/operator/api/*`) also requires an operator credential.
Example header: `x-api-key: <operator-secret>`. If no operator key is configured,
operator endpoints return HTTP 503 rather than granting access.

### Operator visibility
- `GET /operator`
- `GET /operator/api/overview`
- `GET /operator/api/session/{session_id}/timeline`

---

<details>
<summary><b>Minimal example API calls</b></summary>

### Inspect a risky tool call
```bash
curl -s http://127.0.0.1:8000/inspect/tool-call \
  -H "content-type: application/json" \
  -H "x-api-key: dev-secret-key" \
  -d '{
    "session_id":"sess-1",
    "agent_id":"agent-a",
    "tool_name":"shell",
    "action":"cat ~/.ssh/id_rsa"
  }'
```

### Submit approval
```bash
curl -s http://127.0.0.1:8000/approval/submit \
  -H "content-type: application/json" \
  -H "x-api-key: dev-secret-key" \
  -d '{
    "session_id":"sess-1",
    "agent_id":"agent-a",
    "tool_name":"shell",
    "action":"cat ~/.ssh/id_rsa"
  }'
```

</details>

---

## Validation

Current validated baseline:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Expected result:

```text
Ran <N> tests ... OK
```

---

## Roadmap

- stronger authentication beyond shared API keys
- shared-state rate limiting for multi-instance deployment
- PostgreSQL-backed persistence
- replay and trace analysis
- richer policy packs for different agent classes
- semantic fallback for hard cases
- deeper adversarial corpus expansion

---


## Enforcement M1 and data retention

- The shell adapter binds inspection and one-time permits to the **entire argument vector** using an unambiguous JSON representation; it executes those same arguments.
- Secret-leakage and tool-abuse detectors also receive planned action targets. These heuristic detectors are **not** a sandbox or an exhaustive command interpreter.
- Approved permits are atomically consumed once. Separate agent/operator API keys are required for distinct roles.
- The shipped `gateway_sessions.sqlite3` has been removed from version control by this maintenance change, but **old Git history still contains it**. Assess any previous real session records/tokens and rotate exposed credentials as necessary; do not publish the local runtime DB.
- This gateway cannot constrain an agent that retains access to tools outside its adapters. Use operating-system sandboxing, filesystem permissions, and egress controls.
- Default general authentication is still off for local development: **bind only to `127.0.0.1`** unless explicitly secured behind a trustworthy network boundary.

## Enforcement M2 — HTTP and filesystem boundaries

- HTTP supports only explicit `http://` and `https://` URLs with allowlisted hosts. Redirects of **all kinds** are rejected rather than silently following an unapproved destination; URL-embedded credentials and environment-provided HTTP proxies are disabled.
- HTTP host allowlisting does **not** pin DNS resolution or eliminate DNS rebinding, compromised DNS, or network-layer routing risks. Use OS/network egress filtering for untrusted destinations.
- Filesystem access on POSIX platforms uses descriptor-relative `open` with `O_NOFOLLOW`; nested symlinks and non-regular files are rejected, and writes also reject hard-linked files. Path selection is bound to the configured root and checked after policy inspection.
- Filesystem confinement is implemented for POSIX platforms supporting `dir_fd` and `O_NOFOLLOW`. The adapter intentionally **fails closed on unsupported platforms**, including Windows; use an OS-specific safe backend rather than weakening these checks.
- This is an adapter path-confinement measure, **not a process/container sandbox**: mount points, privileged processes, unmediated agent tools, and other I/O channels are outside this guarantee.
- M2 regression tests simulate symlink swaps during approval, hard links, nested path traversal, HTTP 3xx responses, and proxy/redirect handler configuration without sending requests to external services.

## Enforcement M3 — agent runtime integration and adversarial evidence

M3 provides an **opt-in stdio MCP tool server** (`python -m gateway.mcp_stdio`) that routes agent file operations through the real gateway's policy-aware adapters. MCP framing is JSON-RPC over newline-delimited stdin/stdout. It is a restricted interface, **not an operating-system sandbox**.

- The only tools exposed by default are `asg_read_file` and `asg_write_file`. The server exposes **no shell execution** or approval-resolution tool. HTTP GET is hidden unless `ASG_MCP_ALLOWED_HOSTS` is explicitly supplied; even then the central policy can block network actions.
- Set `ASG_MCP_ROOT` to an **existing, absolute, isolated workspace** with no sensitive data. File operations remain confined to that root through the POSIX M2 adapter. Store session, approval, and audit SQLite state separately (`ASG_MCP_DB_PATH`), never inside the exposed workspace. The default state path is `~/.local/state/agent-security-gateway/mcp.sqlite3`.
- MCP messages have a 128 KiB limit, file writes a 16 KiB UTF-8 limit, and each server process permits up to 128 tool-call attempts. The runtime assigns a nonempty random session identifier; agents cannot supply a session ID or approval token through its tool schemas.
- To use this server with an MCP-capable agent client, register its command using the project's Python interpreter and the module `gateway.mcp_stdio`; supply `ASG_MCP_ROOT` and optionally `ASG_MCP_DB_PATH` as launch environment variables. This milestone **does not modify any agent's global configuration**.
- **Disable direct/unmediated filesystem, shell, browser, network, and other tool access in the agent host.** Merely adding this MCP server to OMP, Claude Code, or another runtime does not force those clients to use it. Run the agent under separate OS/container confinement if bypass resistance is required.

Run the offline integration and adversarial scenario (writes only to temporary directories):

```bash
python scripts/m3_adversarial.py --evidence .git/security-m3-evidence.json
```

A local OpenAI-compatible model can *optionally* be probed without executing any model-generated command outside the restricted MCP tool interface:

```bash
python scripts/m3_adversarial.py --evidence .git/security-m3-evidence.json \
  --llm-url http://127.0.0.1:18080/v1/chat/completions --model coder
```

The scripted test deliberately reproduces one **unmediated subprocess bypass** on a disposable temporary file and records it as `FIND`, not `PASS`. That is an expected design limitation of adapter-level mediation; it is **not** proof of secure agent isolation. Successful M3 tests demonstrate real MCP transport and mediated adapter behavior, **not** enforcement against processes with unrestricted OS privileges. The M3 script does not automatically connect to OMP or claim an actual OMP run.

## Operational limits

- API-key auth is shared-secret based
- rate limiting is per-instance, not cluster-global
- `/health` and `/ready` are probe-friendly and should be network-restricted
- rule-based detection and masking can miss novel encodings or fragmented leakage
- some benign high-entropy strings may be masked by design
- SQLite is used as a practical local/internal baseline
- this should be deployed alongside sandboxing, IAM, egress controls, and secret managers

---

## Security note

Agent Security Gateway is best treated as a **security control plane for agent execution**.

Its value comes from enforcing one path to action, mediating execution surfaces, making risk visible, requiring approval where needed, and reducing output leakage.

It should be one layer in a broader defensive stack, not the only one.

---

## Development note

Built with GPT and Codex assistance in ~6 hours, then reviewed, tested, and finalized by the author.
