# Security Policy

Event Horizon runs close to network infrastructure and changes routing, so we take security reports seriously and appreciate responsible disclosure.

## Supported versions

| Version | Supported |
|---|---|
| Latest release | Yes |
| `main` branch | Yes (best effort) |
| Older releases | No, please upgrade |

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for security problems.**

Report privately through GitHub Security Advisories:

1. Go to [https://github.com/LLCForge/Event-Horizon/security/advisories/new](https://github.com/LLCForge/Event-Horizon/security/advisories/new).
2. Describe the issue, affected version or commit, and steps to reproduce.
3. Include a proof of concept if you have one. Strip any real customer data, IP addresses or credentials from captures and logs.

What to expect:

- Acknowledgement within **3 business days**.
- An initial assessment and severity rating within **10 business days**.
- A fix or mitigation plan, coordinated disclosure date, and credit in the advisory (unless you prefer to stay anonymous).

## In scope

- Any path that announces a host route or a FlowSpec rule outside `guardrails.protected` or inside `guardrails.never`, or that bypasses the policy engine (escalation, approval, restore, reload, regional scope) (critical).
- A FlowSpec rule with an action, protocol or port the policy should have refused, or a regional announcement carrying the global BLACKHOLE community.
- Trigger API authentication bypass, token leakage, TLS / mTLS verification bypass.
- Telegram approval forgery: a button press from another chat or user being honoured, approval of a request that was denied or timed out, markup injection into approval messages.
- Remote crash or unbounded memory use via crafted sFlow, NetFlow v9, IPFIX (including template floods), BGP messages, API bodies, or RIPEstat / Pathology / Telegram responses.
- Leaking secrets (API token, TCP-MD5 password, bot token, sink credentials) into logs, alerts, reports or the audit log.
- Dependency vulnerabilities that are reachable from Event Horizon's code paths.

## Out of scope

- Vulnerabilities in third-party services or protocols themselves (report those upstream), e.g. the absence of authentication in sFlow / NetFlow.
- Issues that require an attacker to already control the host, the config file or the environment.
- Denial of service by volumetric flooding of the network the tool runs on.
- TCP-MD5 being unavailable on macOS and Windows (an operating system limitation, documented).

## Attack surface

| Surface | Default | Protection |
|---|---|---|
| Trigger API (`/v1/blackholes`, `/v1/flowspec`, `/v1/approvals`, `/v1/reports`) | `127.0.0.1:9179`, plain HTTP | Rate limit before auth, constant-time bearer token (32+ chars), body limit, strict schemas, optional TLS 1.3/1.2 and client certificates, policy engine behind it. |
| Management listener (`/metrics`, `/healthz`, `/readyz`) | `127.0.0.1:9180` | Read-only, unauthenticated by design (probes); `/v1/silences` and `/v1/reload` only when their token variables are set. |
| Flow collectors | sFlow `6343/udp`, NetFlow / IPFIX `2055/udp` when configured | Source-address allowlist, bounded parsers, bounded template cache, bounded destination table (65 536). |
| BGP sessions | outgoing only | OPEN validation, received UPDATEs discarded, optional TCP-MD5 (Linux), multihop TTL explicit. |
| Telegram approval bot | off | Outgoing long polling only, chat + user allowlist, random 128-bit ids, policy re-check on approval, timeout = deny. |
| Outgoing HTTP (RIPEstat, Pathology, alert sinks) | RIPEstat when `[propagation]` is set | rustls, timeouts, no redirects, response size limits, results never change routing. |

## Hardening recommendations

- Run as an unprivileged user (the systemd unit, Windows service and container image already do); no capabilities are needed unless collectors bind ports below 1024.
- Bind the API and management listeners to localhost or a management network. If the API must be remote, enable `[api.tls]` with `client_ca_file`.
- Use approval mode `detector` while you tune thresholds, and a dedicated Telegram bot and chat for approvals.
- Keep `never` complete (gateways, resolvers, monitoring, your own management addresses) and `max_active` / `flowspec.max_active` small.
- Keep secrets in environment variables or your secret manager, never in the config file or in version control.
- Use TCP-MD5 (Linux) or a dedicated, filtered link for BGP sessions.
