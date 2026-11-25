# Security policy

hostdoor (formerly wireguard-ops-cockpit) lets AI agents run root operations on real hosts. A weakness in its lock, doorkeeper or safety net is a real risk for the hosts that run it, so please report it privately.

## Reporting a vulnerability

- Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** in this repository.
- Please do not open a public issue or pull request for a vulnerability.
- Helpful: the affected guarantee (G1–G10, see [`doc/setup/self-update.md`](doc/setup/self-update.md#the-guarantees-and-the-one-door)), the file and line, and a way to reproduce it without a production host.

This is a single-maintainer project without a support contract. Reports are read and answered as soon as possible; there is no fixed response time.

## Scope

In scope: everything that lets a plan, an agent token or untrusted input (mail, web pages, logs, documents) get past the approval, the envelope, the doorkeeper, the root helpers, the safety net or the secret redaction — or weaken one of them.

Known and documented limits (for example the shared identity of the plan roles, or credentials readable inside the agent's container) are listed under "Honest limit" in the documentation. A practical way to exploit one of them is still welcome as a report.

## Supported versions

Only the current `main` branch. There are no releases.
