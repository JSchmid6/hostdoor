# hostdoor

**A secure host cockpit for AI agents: planner → doorkeeper → operator approval → runner → verifier, with a way back.**

*Sicheres Host-Cockpit für KI-Agenten: Planer → Türsteher → Operator-Freigabe → Runner → Verifier, mit Rückweg.*

hostdoor lets an AI agent administer real Linux hosts (package and kernel updates, Docker services, GitLab upgrades, backups) as root, without handing it a shell or a sudo rule. The agent writes a plan; an isolated reviewer reads the concrete steps; a signed envelope opens exactly that plan once; a snapshot or a fresh backup is the way back; an independent verifier decides whether the job really succeeded. The human operator is asked only when the reviewer has an evidenced finding, when the plan declares a real risk, or when backups would be deleted.

Formerly **wireguard-ops-cockpit**. The repository, the install directory (`/opt/wireguard-ops-cockpit`), the systemd units (`wireguard-ops-cockpit-*`) and the npm workspaces (`@wireguard-ops-cockpit/*`) still carry that name.

## What it is not

- **Not a WireGuard manager.** WireGuard only appears because the cockpit listens on a private VPN interface instead of the public internet. It does not configure peers or tunnels.
- **Not related to [Cockpit](https://cockpit-project.org/)** (the Red Hat web console). Different project, different purpose.
- **Not a general agent framework.** It is the door between an agent and a host: lock, doorkeeper, safety net, audit.
- **Not a finished product.** See [Deployment status](#deployment-status).

## Architecture

```
  agent (e.g. a chat assistant)          operator (browser, phone)
        │ intent, bearer token                 │ admin session
        ▼                                      ▼
 ┌──────────────────────────── control API ─────────────────────────────┐
 │                                                                      │
 │  planner ──► plan + host-run manifest (steps, checks, rollback, risk)│
 │                   │                                                  │
 │                   ▼                                                  │
 │  doorkeeper: isolated safety review of the concrete steps            │
 │     pass ─────────────────────────┐                                  │
 │     evidenced finding / declared  │                                  │
 │     risk / backup deletion ──► "waiting for you" ──► operator ──┐    │
 │     incomplete material ──► stop  │                     approve │    │
 │                                   ▼                             ▼    │
 │            HMAC envelope: bound to the manifest hash, expiring       │
 └───────────────────────────────────┬──────────────────────────────────┘
                                     │ typed request, Unix socket
                                     ▼
 executor broker ──► sudo static root helper (start | status only)
                                     │ checks the envelope again
                                     ▼
 transient systemd unit:  safety net first, then steps and checks
   vps:  last borg backup ≤ 30 h + machine snapshot at the hoster
   lab0: local host snapshot, backup disks mounted read-only
   box:  host snapshot + a snapshot of every Proxmox guest
                                     │
                                     ▼
 verifier: independent check of the outcome ──► job completed / failed
```

Planner, research, doorkeeper and verifier run as one unprivileged identity, the runner as another; neither holds sudo, the envelope secret or the cockpit's configuration. Details: [`doc/services/target-architecture.md`](doc/services/target-architecture.md), [`doc/services/execution-control-model.md`](doc/services/execution-control-model.md), [`doc/setup/host-run.md`](doc/setup/host-run.md) (German).

## Security guarantees

The guarantees G1–G10 are binding for every change at the door. They are listed in [`doc/setup/self-update.md` → "The guarantees and the one door"](doc/setup/self-update.md#the-guarantees-and-the-one-door):

| | |
| --- | --- |
| G1 Approval | only the admin session approves; an agent token never approves |
| G2 Lock | HMAC envelope bound to plan and manifest hash, with expiry, checked by the root helper |
| G3 Doors | `host.run` is the one general door; everything else stays typed and narrow |
| G4 Root helpers and sudoers | static, narrow, version-controlled; the runner never creates sudo policy |
| G5 Sandbox and safety net | no mutating run without the safety net of its instance role |
| G6 Secrets | redaction of outputs, logs and prompts |
| G7, G8 | self-update path, dependencies |
| G9 Doorkeeper | isolated review, a pass only on complete material, findings classes never narrowed |
| G10 Backups and declared risk | deleting, pruning or shortening backups and declared risks need the operator |

A pull request that touches the door's files must state which guarantees it touches and why each still holds (`.github/workflows/pr-guarantees.yml`). The cockpit updates itself only through a typed self-update that reviews the exact diff before installing it ([`doc/setup/self-update.md`](doc/setup/self-update.md)).

Honest limits are documented next to each guarantee, for example: credentials readable inside the agent's container make the doorkeeper, not the network, the real safeguard; a snapshot undoes damage, not exfiltration.

## Deployment status

- In daily production use for **one household**: a rented VPS, a home server that holds the backups, and a Proxmox host, each with its own cockpit instance (roles `vps`, `lab0`, `box`).
- All agent roles (planner, research, doorkeeper, runner, verifier) run on **Claude** via Claude Code. If Claude is unavailable, opencode with another model stands in and the job is marked `NOTBETRIEB` (emergency mode) for the operator.
- The operator is asked for decisions, not for routine clicks: most jobs run on the doorkeeper's pass.
- Single maintainer, no releases, no stability promise. Many design documents are in German.

## Quick start (local, no real host)

Requirements: Node.js 22.23.4 (`.node-version`; `better-sqlite3` is a native module), `tmux` optional.

```bash
git clone https://github.com/JSchmid6/wireguard-ops-cockpit.git hostdoor
cd hostdoor
cp .env.example .env
# set COCKPIT_ADMIN_PASSWORD, and COCKPIT_PLANNER_RUNTIME=demo-local for a planner without any LLM
npm install
npm run dev:api     # http://127.0.0.1:3001
npm run dev:web     # http://127.0.0.1:5173
```

Or with Docker Compose (development only, no host helpers):

```bash
cp .env.example .env
docker compose up
```

A plan reaches the door as a `host-run` manifest. Example (from the tests; nothing here touches a host unless an instance is installed):

````
```host-run
{
  "version": "cockpit-host-run/v1",
  "name": "apt maintenance",
  "purpose": "update packages from the configured sources",
  "mutates": true,
  "steps":  [{ "name": "upgrade", "run": "apt-get update && apt-get -y upgrade" }],
  "checks": [{ "name": "nothing pending", "run": "test -z \"$(apt list --upgradable 2>/dev/null | tail -n +2)\"" }],
  "rollback": ["downgrade the upgraded packages to the versions in /var/log/apt/history.log"],
  "risk": ["contained"]
}
```
````

A manifest without a rollback is refused. A declared risk other than `contained` (`exposure`, `data_loss`, `identity_or_secret`) always goes to the operator. More examples, including ones the doorkeeper must flag: [`apps/api/test/fixtures/host-run-review-cases.json`](apps/api/test/fixtures/host-run-review-cases.json).

Installing on a real host is deliberately not a one-liner: see [`doc/setup/vps-handover.md`](doc/setup/vps-handover.md), [`deploy/lab0/`](deploy/lab0/) and [`doc/setup/box-bootstrap.md`](doc/setup/box-bootstrap.md).

## Build and test

```bash
npm run build
npm run test
npm run coverage
npm run check      # build + test, the CI gate
```

## Repository structure

- `apps/api/` – control API (Fastify, SQLite): auth, jobs, approvals, audit, planner/doorkeeper/verifier orchestration
- `apps/agent-broker/` – isolated broker for the agent roles; the same code serves the runner under its own identity
- `apps/executor-broker/` – HMAC-authenticated typed capability executor
- `apps/web/` – operator UI, start page "Wartet auf dich" (waiting for you)
- `deploy/` – static root helpers, systemd units, sudoers, deploy scripts per instance role
- `doc/` – architecture, guarantees, setup ([index](doc/README.md))
- `AGENTS.md` – rules for coding agents working on this repository

## Security

Please report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
