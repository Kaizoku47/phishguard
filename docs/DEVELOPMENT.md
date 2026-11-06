# PHISHGUARD Development Guide

> **Status: repository foundation only.** There is no application code and no
> dependency manifest, so there is nothing to install or run yet. This document
> covers the repository conventions, the tooling the implementation will use, and
> the third-party license position that affects what may be committed.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Getting started](#2-getting-started)
3. [Repository layout](#3-repository-layout)
4. [Branching and commits](#4-branching-and-commits)
5. [Environment and secrets](#5-environment-and-secrets)
6. [Planned toolchain](#6-planned-toolchain)
7. [Continuous integration](#7-continuous-integration)
8. [Third-party skills and licensing](#8-third-party-skills-and-licensing)
9. [Git identity and privacy](#9-git-identity-and-privacy)
10. [Planned test strategy](#10-planned-test-strategy)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

Expected local versions:

| Tool | Version | Why |
|---|---|---|
| Python | 3.12 or newer | Backend runtime; 3.12 is the tested baseline |
| Node.js | 20 or newer | Frontend toolchain |
| Docker Engine | current | Containerised development stack |
| Docker Compose | v2 plugin, invoked as `docker compose` | The v1 `docker-compose` script is retired |
| PostgreSQL | 16 | Local database, or the containerised service |
| Git | 2.40 or newer | Branching, hooks and filters |

Nothing above is installed by this repository.

## 2. Getting started

```bash
git clone <repository-url> phishguard
cd phishguard
cp .env.example .env
```

Then edit `.env` and replace every placeholder. `.env` is ignored by git; do not
commit a filled-in copy.

There is no build step yet. The application will be added in later milestones.

## 3. Repository layout

```
phishguard/
├── .github/
│   ├── workflows/ci.yml    # hygiene, secret scanning, Dependabot config check
│   └── dependabot.yml      # GitHub Actions ecosystem only
├── docs/
│   ├── ARCHITECTURE.md     # components, data flow, scoring, agent
│   ├── SECURITY.md         # threat model and security requirements
│   └── DEVELOPMENT.md      # this document
├── .opencode/              # local OpenCode and ECC configuration (see below)
├── .env.example            # documented environment variables, placeholders only
├── .gitignore
├── PHASE2-ARCHITECTURE.md  # Phase 2 planning record
└── README.md
```

Directories that will be added as milestones land: `backend/`, `frontend/`,
`tests/`.

`.opencode/` is a working tool configuration, not application code. Its skills
directory is excluded from version control; see
[section 8](#8-third-party-skills-and-licensing). Machine-specific state,
credentials and backups under `.opencode/` are excluded too. Today **no file
under `.opencode/` is tracked**: the whole directory stays local until its
contents are reviewed for redistribution.

## 4. Branching and commits

`main` is the default branch and must stay deployable. Work happens on short
lived branches merged by pull request.

| Kind | Pattern | Example |
|---|---|---|
| Feature | `feat/<slug>` | `feat/email-ingestion` |
| Fix | `fix/<slug>` | `fix/ssrf-redirect-bypass` |
| Documentation | `docs/<slug>` | `docs/runbook` |
| Chore | `chore/<slug>` | `chore/ci-node-version` |

Commit messages follow Conventional Commits:

```
<type>(<scope>): <subject>

[optional body: why, not what]

[optional footer: refs, breaking change]
```

Types in use: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`,
`perf`, `ci`, `revert`.

Rules:

- Subject in the imperative mood, no trailing period, roughly 50 characters.
- One logical change per commit.
- Explain the reason in the body when the reason is not obvious from the diff.
- Never commit secrets, evidence files, `node_modules`, build output or local
  environment files.

## 5. Environment and secrets

- `.env.example` documents every variable name the application reads, with a
  placeholder value. It is the single source of truth for configuration keys.
- `.env` is local, ignored, and never committed.
- Generate secret values locally:

  ```bash
  openssl rand -hex 32
  ```

- In CI, values come from GitHub encrypted secrets. Pull-request runs from forks
  receive no repository secrets, and workflows must not assume otherwise.
- If a credential is ever committed, rotate it first, then remove it from
  history. Removal alone does not undo the exposure, because a public repository
  is copied and indexed.

## 6. Planned toolchain

Not yet configured. Listed so conventions are decided before code lands.

**Backend**

| Concern | Tool |
|---|---|
| Package and project metadata | `pyproject.toml` |
| Linting and formatting | Ruff (lint and format) |
| Type checking | mypy in strict mode for application code |
| Tests and coverage | pytest, pytest-cov |
| Security linting | Bandit |
| Dependency audit | pip-audit |

**Frontend**

| Concern | Tool |
|---|---|
| Package manager | npm |
| Linting and formatting | ESLint and Prettier |
| Type checking | TypeScript `tsc --noEmit` |
| Tests | Vitest, Testing Library |
| End-to-end tests | Playwright |

**Style conventions.** Python follows Ruff defaults with a line length of 100;
type hints are required on public functions. TypeScript runs in strict mode with
no implicit any. Shared naming: snake case in Python, camel case in TypeScript,
kebab case for file names in the frontend.

## 7. Continuous integration

The initial workflow at `.github/workflows/ci.yml` runs only checks that are
meaningful today:

| Job | What it proves |
|---|---|
| `repository-hygiene` | No evidence or secret files are committed; required files exist; production workflows are SHA-pinned and use least-privilege permissions; no workflow uses `pull_request_target` |
| `secret-scan` | No credential patterns in the current tree or any commit |
| `dependabot-config` | `.github/dependabot.yml` is valid YAML and only lists ecosystems that have manifests |

Backend tests, frontend tests, linting, type checking, dependency auditing and
container scanning are deliberately absent, because there is no code, manifest
or Dockerfile to run them against. Each is added in the milestone that introduces
its target, so a green check always means something.

All jobs run with `contents: read` and receive no repository secrets.

## 8. Third-party skills and licensing

`.opencode/` contains a working OpenCode and ECC configuration, including skill
bundles imported from the machine-global ECC installation. The repository is
intended to be public, so licence terms decide what may be published.

Observed position at Milestone 1:

| Skill | Declared licence | Publication position |
|---|---|---|
| `banner-design` | MIT | Permissive; attributable redistribution is permitted |
| `design` | MIT | Permissive; attributable redistribution is permitted |
| `design-system` | MIT | Permissive; attributable redistribution is permitted |
| `ui-styling` | MIT (bundled `LICENSE.txt`) | Permissive; keep the notice |
| `impeccable` | Apache 2.0 | Permissive, requires NOTICE handling; carries a 21 MB prebuilt binary |
| `brand` | None declared | Not published pending confirmation |
| `slides` | None declared | Not published pending confirmation |
| `ui-ux-pro-max` | None declared | Not published pending confirmation |

Decisions taken:

1. `.opencode/skills/` is excluded from version control. Three bundles declare no
   licence, and one vendors a 21 MB platform binary that does not belong in a
   source repository. The local configuration keeps working unchanged.
2. `.opencode/package.json` and `.opencode/package-lock.json` are not required by
   the project. They are retained locally so the existing setup is not disturbed,
   and are excluded from publication. They also pin a dependency declared as
   `file:` and a caret range, so neither would install reproducibly elsewhere.
3. The global ECC installation is a development tool. No ECC code is vendored
   into this repository.
4. Machine-specific OpenCode state is excluded narrow-by-path rather than by
   ignoring `.opencode/` wholesale: `.opencode/auth.json`, `state.json`,
   `ecc-install-state.json`, `*.bak` backups, and the `agents/`, `agent/`,
   `plugins/`, `tools/`, `hooks/` and `mcp-configs/` directories. These can hold
   credentials, install state or personal agent definitions.
5. No file under `.opencode/` is tracked. `.opencode/commands/impeccable.md`
   contains no third-party code, but it invokes a skill that is not published,
   so it is excluded by exact path (`gitignore` rule at
   `.opencode/commands/impeccable.md`). Other commands under the same directory
   remain eligible, so this exclusion does not block future paperwork.

To publish a skill deliberately, in a future milestone:

1. Confirm the upstream licence and its exact terms.
2. If permissive, copy the skill together with its licence and notice files.
3. Add a `THIRD-PARTY-NOTICES.md` entry naming the source, version and licence.
4. Add a narrow negation to `.gitignore` for that one path.
5. Never publish a vendored binary unless it is required at runtime and covered
   by the licence.

## 9. Git identity and privacy

Commits carry an author name and email. A personal address in a public
repository is permanently public, it is scraped, and rewriting history does not
reliably recall copies already taken.

Check the current identity:

```bash
git config user.name
git config user.email
```

If you prefer not to publish a personal address, use the GitHub noreply address
for the account. It has the form `<id>+<username>@users.noreply.github.com`, or
the older `<username>@users.noreply.github.com`. Find the identifier in GitHub
under Settings, Emails.

Set it for this repository only:

```bash
git config user.email "<id>+<username>@users.noreply.github.com"
```

Then confirm before the first commit that no unintended address will appear in
history:

```bash
git log --format='%an <%ae>' | sort -u
```

Once a commit is published, changing the address in configuration affects only
future commits.

## 10. Planned test strategy

| Layer | Target | Notes |
|---|---|---|
| Unit | Analysis modules, scoring, guard | Fast, no network, no database |
| Integration | API endpoints, worker pipeline | Real database in a container, providers mocked |
| Contract | Intel adapters | Recorded responses for each provider shape |
| Security | Guard refusal cases, input validation | One test per refusal rule in `SECURITY.md` |
| End-to-end | Upload to report | Playwright once the frontend exists |
| Fixtures | Sanitized `.eml` samples | Synthetic only; real evidence is never committed |

Tests are written against the security requirements, not only against the happy
path. Every refusal rule in [SECURITY.md](SECURITY.md) should have a test that
proves it refuses.

## 11. Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| `docker compose` not found | Only the v1 script is installed | Install the Compose v2 plugin |
| CI fails on a SHA-pin check | A workflow uses `@v4` style tags | Pin the full commit SHA and keep the version in a comment |
| CI fails on a hygiene check | An evidence file or `.env` was staged | Remove it, confirm `.gitignore` covers the path, and rotate any credential it contained |
| Secret scan flags a test fixture | A fixture looks like a real credential | Use an obviously synthetic value; never add a real one, even revoked |

---

Questions about a requirement should be resolved in the relevant document
rather than in chat, so the reasoning survives. Architecture questions go to
[ARCHITECTURE.md](ARCHITECTURE.md); security requirements go to
[SECURITY.md](SECURITY.md).
