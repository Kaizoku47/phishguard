# PHISHGUARD

An autonomous phishing investigation platform. PHISHGUARD takes a suspicious
email, analyses it in an isolated and non-executing pipeline, enriches it with
threat intelligence, produces an explainable risk score, and gives an analyst a
reviewable report backed by an auditable decision trail.

> **Status: planning and repository foundation only.** No backend, frontend,
> database schema, analysis module or AI agent code exists yet. Nothing in this
> repository has been implemented or deployed. The sections below describe the
> intended system, not delivered capability.

---

## Problem statement

Phishing remains one of the most common ways an attacker gains an initial
foothold. Investigation is slow because it is manual and scattered: an analyst
opens a message in a mail client, inspects headers by hand, copies URLs into
several browser tabs, uploads attachments to a sandbox, and writes findings into
a ticket.

That workflow has three problems.

1. **It does not scale.** Each message costs minutes of skilled attention.
2. **It is inconsistent.** Verdicts depend on the analyst's experience and on
   which tools happened to be consulted.
3. **It is hard to audit.** When a verdict is challenged, the evidence behind it
   is usually a screenshot, not a structured record.

Opening a phishing message is itself a risk. Analysts need an environment where
the message is data to be examined, never code that can run.

## Objectives

- Parse an uploaded email without executing any part of it.
- Extract and correlate the signals that matter: authentication results, routing
  headers, URLs, attachment metadata and lookalike domains.
- Enrich those signals with external threat intelligence through a strictly
  bounded set of outbound requests.
- Produce a risk score that explains itself, where every contributing signal
  carries a weight and a human-readable reason.
- Give an AI agent a narrow, read-only tool surface for investigation, with
  every step recorded so a reviewer can reconstruct the reasoning.
- Keep the whole pipeline reproducible, testable and safe to run on hostile
  input.
- Ship the result as a public reference implementation with real CI gates.

## Planned features

| Feature | Intent |
|---|---|
| Email ingestion | Accept an uploaded message, validate size and structure, store the raw bytes unmodified. |
| Authentication analysis | Surface SPF, DKIM and DMARC results that the receiving infrastructure recorded. |
| Header forensics | Compare `From`, `Return-Path`, `Reply-To` and `Received` chains to expose forged senders. |
| URL extraction and inspection | Extract every link, identify the registered domain, and detect lookalikes without visiting the target. |
| Attachment analysis | Record filename, declared and detected type, size and cryptographic hashes. Never open or execute. |
| Threat intelligence enrichment | Query allow-listed providers with caching, timeouts and response-size limits. |
| Explainable risk scoring | Weighted signals with per-signal reasons, so a verdict can be argued with. |
| AI investigation agent | Plan and summarise within a fixed, read-only tool set and a hard step budget. |
| Analyst dashboard | Upload a message, watch progress, read the score breakdown, and inspect the agent's decision trail. |
| Audit trail | Append-only record of every analysis action, tool call and intelligence lookup. |

## Technology stack

| Layer | Planned choice |
|---|---|
| Backend | Python 3.12, FastAPI, Pydantic v2 |
| ORM and migrations | SQLAlchemy 2.0 (async), Alembic |
| Database | PostgreSQL 16 with JSONB for analysis artefacts |
| Queue and cache | Redis, with a worker process for ingestion and enrichment |
| Email parsing | Python standard library `email` package |
| Frontend | React, TypeScript, Vite, TanStack Query, Tailwind CSS |
| Testing | pytest, Vitest, Playwright |
| Packaging | Docker and Docker Compose |
| CI/CD | GitHub Actions, including secret, dependency and container scanning |
| AI agent | Provider-agnostic client behind a constrained tool interface |

## High-level architecture

```
                        +---------------------------+
   analyst uploads      |      React frontend       |
   a suspicious  -----> |  upload, report, review   |
   message              +-------------+-------------+
                                      | HTTPS / JSON
                                      v
                        +---------------------------+
                        |       FastAPI API         |  validates and stores
                        |  (untrusted input only)   |
                        +-------------+-------------+
                                      |
                    +-----------------+-----------------+
                    |                                   |
                    v                                   v
        +-----------------------+           +-----------------------+
        |   Postgres + Redis    |           |   Worker process      |
        |  messages, artefacts, | <-------- |  ingestion, analysis, |
        |  scores, audit trail  |           |  enrichment           |
        +-----------------------+           +-----------+-----------+
                                                        |
                              +-------------------------+---------------+
                              |                         |               |
                              v                         v               v
                    +------------------+     +----------------+  +----------------+
                    | Static analysis  |     | Threat intel   |  | AI agent       |
                    | headers, URLs,   |     | adapters via   |  | read-only      |
                    | attachments      |     | SSRF guard     |  | tools + audit  |
                    +------------------+     +----------------+  +----------------+
```

The upload path never executes anything. Attachments are hashed and described,
never opened. URLs are analysed from their text and from provider reputation,
never fetched by PHISHGUARD. Everything leaving the platform goes through the
same guarded outbound boundary.

Detailed design lives in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security principles

These are design constraints, not aspirations. A change that breaks one is a
change that does not ship.

1. **Everything from outside is hostile.** Emails, URLs, attachments, headers and
   intelligence responses are untrusted input.
2. **Nothing executes.** No attachment is opened, rendered or run.
3. **Nothing is auto-visited.** PHISHGUARD does not fetch suspicious URLs.
4. **Outbound is allow-listed.** Intelligence calls go only to approved endpoints
   through an SSRF guard that rejects private ranges and redirects inward.
5. **Credentials never reach source or logs.** Secrets come from the environment
   and pass through a redaction filter before logging.
6. **The agent is caged.** A fixed, read-only tool set, a step budget, and an
   append-only audit trail. Email content is data, never instruction.
7. **Least privilege everywhere.** Read-only default CI tokens, non-root
   containers, and a database user with only the rights it needs.
8. **Fail closed.** Ambiguity about a boundary is resolved by refusing the
   operation.

Full detail lives in [docs/SECURITY.md](docs/SECURITY.md).

## Development status

Milestone 1 — repository foundation. Present in the repository:

| Item | State |
|---|---|
| Root `.gitignore` | Created |
| `.env.example` | Created |
| `README.md` | Created |
| `docs/ARCHITECTURE.md` | Created |
| `docs/SECURITY.md` | Created |
| `docs/DEVELOPMENT.md` | Created |
| `.github/workflows/ci.yml` | Created — hygiene, Gitleaks and Dependabot config validation |
| `.github/dependabot.yml` | Created — GitHub Actions ecosystem only |
| `LICENSE` | Created — MIT, copyright holder placeholder pending |
| `PHASE2-ARCHITECTURE.md` | Preserved planning record from the previous phase |
| `.opencode/` | Preserved working OpenCode/ECC configuration |

Nothing else exists. There is no application code, no test suite, no dependency
manifest, no Dockerfile and no database schema. The CI workflow does not pretend
otherwise: it runs only the checks that are meaningful for a repository
containing no code yet.

## Roadmap

Implementation order, each step intended as one reviewable change with CI green
before the next begins.

1. Backend skeleton: FastAPI application, configuration, structured logging,
   health endpoint.
2. Database layer: SQLAlchemy models and the initial Alembic migration.
3. Safe email ingestion: header, body, link and attachment-metadata extraction
   with no execution.
4. Static analysis modules: authentication results, header forensics, URL
   inspection, attachment hashing.
5. Threat intelligence adapters behind the SSRF guard, with caching.
6. Explainable risk scoring with per-signal reasons.
7. AI investigation agent: constrained tools, step budget, audit trail.
8. Frontend: upload flow, progress, report and score breakdown.
9. Docker and Compose for the full local stack.
10. Full CI/CD: backend and frontend tests, linting, type checking, dependency
    auditing and container scanning.
11. Documentation, runbook and contribution guide.

## Local development prerequisites

Nothing has been installed by this milestone. The intended toolchain is:

- Python 3.12 or newer, with a virtual environment
- Node.js 20 or newer
- Docker Engine with the Docker Compose v2 plugin (`docker compose`, not the
  retired `docker-compose` v1 script)
- PostgreSQL 16 (or the containerised service once Compose exists)
- Git 2.40 or newer

Setup, conventions and the third-party licence position are described in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Contributing

No contribution process is defined yet. Until one exists, treat the security
principles as the review bar and open an issue before starting significant work.

## License

This project is licensed under the **MIT License**. The full text is in
[LICENSE](LICENSE).

The copyright holder in `LICENSE` is currently a placeholder
(`[COPYRIGHT HOLDER]`). It must be replaced with the owner's chosen copyright
identity before the first commit is published.

Two related notes:

- Planned runtime and tooling dependencies have not been selected or vendored
  yet, so no third-party license obligations attach to application code.
- The `.opencode/skills/` directory contains third-party skill bundles with
  mixed or absent license declarations. It is deliberately excluded from version
  control. See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for the per-skill
  position.

## Acknowledgements

Development uses the Everything Claude Code (ECC) framework for skills, agents
and workflow automation, running under OpenCode. ECC is a development-time tool:
it is not a runtime dependency of PHISHGUARD and no ECC code is vendored into
this repository.
