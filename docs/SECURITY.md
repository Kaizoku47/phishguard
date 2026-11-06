# PHISHGUARD Security Model

> **Status: requirements, not controls in place.** No application code exists
> yet, so none of these controls is implemented or verified. This document is the
> review bar: implementation must satisfy it, and a change that breaks it does
> not ship without an explicit decision recorded here.

## Contents

1. [Threat model](#1-threat-model)
2. [Untrusted input rules](#2-untrusted-input-rules)
3. [No-execution policy](#3-no-execution-policy)
4. [No-auto-visit policy](#4-no-auto-visit-policy)
5. [Outbound request guard (SSRF)](#5-outbound-request-guard-ssrf)
6. [Secret management](#6-secret-management)
7. [Logging and error handling](#7-logging-and-error-handling)
8. [AI agent security](#8-ai-agent-security)
9. [Attachment handling](#9-attachment-handling)
10. [Data protection and retention](#10-data-protection-and-retention)
11. [CI/CD and supply chain](#11-cicd-and-supply-chain)
12. [Container hardening](#12-container-hardening)
13. [Threat intelligence handling](#13-threat-intelligence-handling)
14. [Vulnerability reporting](#14-vulnerability-reporting)
15. [Non-goals](#15-non-goals)

---

## 1. Threat model

**Assets.**

- The raw phishing messages and attachments uploaded by analysts. These are
  evidence and may contain personal data.
- Provider API credentials.
- The integrity of scores and reports: a wrong "clean" verdict is a security
  outcome, not just a bug.
- The audit trail.
- The host and network the platform runs on.

**Adversaries and inputs considered hostile.**

| Adversary | Capability assumed |
|---|---|
| The phishing author | Full control of the message: headers, bodies, links, attachment names and bytes, and any text designed to look like instructions to an LLM |
| A malicious or compromised intel provider | Arbitrary response bodies, including oversized, malformed or instruction-bearing content |
| A curious or malicious authenticated user | Can upload crafted messages; cannot be trusted with other users' evidence |
| An opportunist on the network | Can reach any endpoint the platform exposes |

**Abuse of the platform itself.** PHISHGUARD parses hostile input and makes
outbound requests. Those are the two properties an attacker will try to turn
into remote code execution or server-side request forgery.

## 2. Untrusted input rules

- Every request body, query parameter and uploaded file is validated against an
  explicit schema before use. Validation is allow-list based.
- Uploads are capped in size before the body is read fully, using
  `PHISHGUARD_MAX_UPLOAD_BYTES`.
- Declared content type and filename are treated as hints only. They never
  decide how a file is handled.
- Decoded text is never rendered as HTML in the dashboard. Body content is shown
  as text, escaped by the rendering layer.
- Nothing derived from input is used to build a file path, a shell command, a
  template, or a database query string.
- Errors returned to a caller describe what was rejected, never internal paths,
  stack traces or library versions.

## 3. No-execution policy

Attachments and message parts are data. They are never:

- opened, rendered, previewed or handed to an application that understands them;
- executed, or passed to an interpreter, macro engine, or sandbox run;
- decompressed recursively (archives are described, not expanded, in the first
  release).

What is permitted: reading bytes to compute a hash and to identify a type by
magic bytes, within a size cap.

Any future detonation feature is a separate design with its own isolation model,
and is out of scope for the first release.

## 4. No-auto-visit policy

PHISHGUARD does not fetch URLs found in a message. Analysis uses the URL text
and provider reputation only.

Rationale: fetching an attacker-controlled URL confirms that the message was
opened, can leak the analyst's network position, and turns every email into a
request the platform must defend against. Reputation data answers the analyst's
question without that exposure.

If a "visit safely" capability is ever added, it must run in an isolated,
network-restricted environment with its own review, not inside the worker.

## 5. Outbound request guard (SSRF)

All outbound requests from the platform go through one shared guard. Nothing
calls an HTTP client directly.

Guard requirements:

1. **Allow-list by hostname.** Only pre-declared provider hostnames are
   permitted. A URL from a message can never become a destination.
2. **Scheme restriction.** HTTPS only.
3. **Resolution check.** Resolve the hostname first, and refuse private,
   loopback, link-local, multicast, reserved and cloud metadata ranges, for both
   IPv4 and IPv6.
4. **Rebinding resistance.** Connect to the checked address rather than
   re-resolving, so a name cannot change between the check and the connection.
5. **Redirect policy.** Redirects are disabled; a redirect to a new host is
   treated as a refusal, not followed.
6. **Resource limits.** Per-request timeout
   (`PHISHGUARD_INTEL_TIMEOUT_SECONDS`) and a maximum response size
   (`PHISHGUARD_INTEL_MAX_RESPONSE_BYTES`), enforced while streaming rather than
   after buffering.
7. **No credential forwarding.** Provider keys are attached only to that
   provider's own requests.
8. **One place to review.** The guard is a small, well-tested module with tests
   for each refusal case above.

## 6. Secret management

- No credential, token or key is committed to the repository. `.env` is ignored;
  `.env.example` contains placeholders only and no value that could ever work.
- In CI, secrets live in GitHub encrypted secrets, are scoped to the jobs that
  need them, and are never exposed to pull-request runs from forks.
- Application secrets arrive through the environment. Configuration objects
  load them once and never print them.
- A redaction filter sits in front of the logging pipeline and masks known
  credential patterns, including provider keys and authorization headers.
- Comparison of secrets, where it happens at all, uses constant-time comparison.
- Rotation: every credential must be replaceable by changing one environment
  value and restarting a service. Anything that would require a code change to
  rotate is a defect.
- Local evidence and credentials are separate concerns: evidence lives under
  ignored paths, credentials live in the environment.

Known limitation, stated plainly: an environment variable is not sealed storage.
Anyone who can read the container's environment or the process memory can read
the secret. The mitigation is least-privilege keys with tight quotas, so a leaked
key is a bounded problem.

## 7. Logging and error handling

Log **identifiers and outcomes**, not evidence.

| Log freely | Never log |
|---|---|
| Message and run identifiers | Raw message bodies |
| Module names, timings, counts of findings | Attachment contents |
| Provider name, target host, status, latency | Provider API keys, bearer tokens |
| Error classes and short messages | Full request headers containing credentials |

Rules:

- Structured logging with stable field names, so a scan is possible later.
- A redaction filter processes every record before it is emitted.
- Callers receive a generic error and a correlation identifier. Full detail
  stays server-side.
- Unhandled exceptions are caught at the API boundary, recorded, and turned into
  a safe response; the process must not leak a traceback to a client.
- Failed intel lookups are recorded as findings in `missing_evidence`, not only
  as log noise, so the report reflects that evidence is incomplete.

## 8. AI agent security

The agent is treated as a potentially manipulable component with no trust.

- **Fixed, read-only tools.** The list in
  [ARCHITECTURE.md](ARCHITECTURE.md#7-ai-investigation-agent) is exhaustive. No
  shell, no filesystem write, no arbitrary URL fetch, no database write.
- **Budget.** A hard step limit per investigation prevents runaway loops and
  unbounded spend.
- **Prompt injection assumed.** Message text, headers and provider payloads are
  inserted as clearly delimited data. Instructions inside that data are
  reported as findings and never executed. Since the tool surface cannot reach
  the network or the filesystem, a successful injection still cannot cause an
  effect outside the investigation.
- **No authority over the verdict.** The agent cannot change the score. It
  explains and expands, and a human decides.
- **Append-only audit.** Tool name, arguments, result digest and rationale are
  recorded per step, so a reviewer can reconstruct the investigation.
- **Output handling.** Agent narrative is rendered as plain text, never as HTML
  or Markdown with executable content.

## 9. Attachment handling

- Filename is stored as a string and displayed escaped. It is never used to
  build a path on disk.
- Detected type comes from magic bytes with a size cap, not from the extension.
- Content is hashed (SHA-256) and the hash is used for reputation lookups.
- Stored bytes are held in an ignored evidence path or the database, never in a
  web-served directory.
- Any download endpoint that serves raw attachment bytes is treated as a
  high-risk surface: it must set `Content-Disposition: attachment`, a
  restrictive `Content-Type`, `X-Content-Type-Options: nosniff`, and never
  render inline.

## 10. Data protection and retention

- Evidence retention period is **undecided**; see the open questions in
  [ARCHITECTURE.md](ARCHITECTURE.md#11-open-questions). Until it is decided, the
  default is to keep only what the analysis needs.
- Raw messages may contain personal data. They are stored in the database and on
  disk, not in logs, and not in crash reports.
- A deletion path must exist before this is used on real evidence: given a
  message identifier, remove the raw bytes, derived artefacts and caches.
- Database access is least privilege: one application user with the rights the
  application needs, no superuser, no public network exposure.

## 11. CI/CD and supply chain

- Workflow default permission is `contents: read`. Any job needing more declares
  it explicitly.
- No workflow uses `pull_request_target`, and no repository secret is made
  available to pull-request runs.
- Third-party actions are pinned to full commit SHAs, with the human-readable
  version in a comment. A hygiene check in CI enforces the pin.
- Secret scanning runs on every push and pull request.
- Dependency auditing is added per ecosystem as soon as that ecosystem has a
  manifest. Container scanning is added when the first Dockerfile exists.
- Dependabot is enabled for ecosystems that actually have manifests in the
  repository.

## 12. Container hardening

Applies once Dockerfiles exist. Recorded here so the images are built correctly
the first time.

- Run as a non-root user with a stable, high user id.
- Pin base images by digest, not by floating tag.
- Multi-stage builds; the runtime image carries no build tools or package
  managers.
- Read-only root filesystem where the application allows it, with explicit
  writable mounts for evidence.
- No `--privileged`, no host network, no Docker socket mount.
- Resource limits on CPU and memory, so a pathological message cannot starve the
  host.
- No secrets baked into images or layers; secrets arrive at runtime.

## 13. Threat intelligence handling

- Provider responses are untrusted input, parsed defensively with size limits.
- A response is stored raw alongside the parsed view, so a later disagreement
  can be investigated.
- A provider cannot cause the platform to make a further request. Responses are
  never treated as instructions or as new destinations.
- Provider reputation is evidence, not proof. A single positive never decides a
  verdict on its own; the scoring model shows the contribution.
- Caching is keyed by target and provider, with a TTL, to respect free-tier
  quotas and to keep reports reproducible.

## 14. Vulnerability reporting

A private reporting channel is **not yet established**. Until one exists, do not
open a public issue containing an exploitable finding. This section will be
replaced with a concrete channel before the first release.

## 15. Non-goals

PHISHGUARD does not:

- send, quarantine, delete or modify mail;
- take remediation action on any system;
- guarantee correct verdicts. It presents evidence and an explained score for a
  human decision;
- provide a hardened multi-tenant service in the first release.
