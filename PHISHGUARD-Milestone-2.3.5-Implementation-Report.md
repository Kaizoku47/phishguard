# PHISHGUARD — Milestone 2.3.5 Implementation Report

## 1. Branch and base

```text
Branch: feat/milestone-2.3.5-deterministic-analysis
Base:   a486d1ee971281b4748bb42d232e78f7b3b7f79f (origin/main, PR #8 merge)
```

Created from `origin/main` after confirming the merge. No existing source file
was modified; the working tree contains only the new analysis package and new
tests, plus the pre-existing untracked review artifact.

## 2. Files created

```text
backend/app/services/analysis/__init__.py
backend/app/services/analysis/signals.py
backend/app/services/analysis/score.py
backend/app/services/analysis/service.py
backend/tests/test_signals.py
backend/tests/test_score.py
backend/tests/integration/test_analysis.py
```

`service.py` is the minimal persistence boundary required by §12.2. No analysis
Pydantic schema was added: it would only serve A10, which belongs to Milestone
2.3.7.

## 3. Implemented signals and scoring

All 12 approved signals are implemented with the approved contributions from a
single central table in `score.py`:

```text
reply_to_mismatch            20
lookalike_sender_domain      18
auth_results_unverifiable     0  (always unevaluated)
link_host_count              10
url_credential_scheme        15
punycode_host                15
free_mail_sender              8
attachment_type_mismatch     12
archive_attachment           10
html_form_count              20
suspicious_tld                8
missing_date                  5
```

Approved v1 band ranges are implemented exactly:

```text
low       0–24
medium   25–49
high     50–79
critical 80–100
```

Score is the sum of evaluated contributions only, clamped to 0–100. Engine
version is centralized as `1.0.0`. `Signal` is immutable, requires a non-empty
reason, and refuses an unevaluated signal with non-zero contribution.

## 4. Reference lists and deterministic parsing

Explicit fixed constants in `signals.py`:

- brands: microsoft.com, google.com, apple.com, amazon.com, paypal.com, netflix.com
- free mail: gmail.com, googlemail.com, outlook.com, hotmail.com, live.com,
  yahoo.com, icloud.com, proton.me, protonmail.com, aol.com
- suspicious TLDs: top, xyz, click, work, country, gq, tk

Parsing rules implemented:

- domains: lowercase, strip whitespace, strip trailing dot, built-in IDNA;
- lookalike: deterministic Levenshtein distance exactly 1; exact brand excluded;
- free mail: exact normalized domain membership;
- suspicious TLD: final hostname label against fixed list;
- link hosts: distinct, non-empty normalized hosts from parser links; count >= 5;
- credential URLs: `urlsplit`, HTTP/HTTPS only, both username and password present;
- punycode: any `xn--` host label;
- archives: fixed ZIP/RAR filename extensions and MIME types from attachment metadata;
- attachment mismatch: normalized declared and detected content types; missing values ignored;
- HTML forms: `html.parser.HTMLParser` start-tag count over stored text; no rendering;
- missing date: existing `date_header` / `date_parsed` fields.

No lists are downloaded or dynamically updated.

## 5. Authentication-Results boundary

`auth_results_unverifiable` is always emitted with `evaluated=False`,
contribution `0` and severity `none`. Its reason states uploaded authentication
results are sender-controlled/untrusted and that no SPF/DKIM/DMARC outcome can
be established. The engine never parses or interprets the uploaded header, and
produces no SPF/DKIM/DMARC verdict field. `missing_evidence()` exposes the
approved `auth:spf_dkim_dmarc` target for the future report endpoint.

## 6. Persistence behavior

`analyse_and_persist()`:

1. loads `ParsedEmail` and `EmailAttachment` rows for one evidence id;
2. evaluates deterministic signals and builds the score;
3. inserts one `AnalysisResult` with score, band, signals, `{}` intelligence
   results and stable engine version;
4. leaves narrative fields in the initial state: `narrative=None`,
   `narrative_status='unavailable'`, `narrative_reason='investigation pending'`;
5. reuses an existing row on repeat analysis and relies on the existing unique
   constraint as the final guard.

No schema, migration, ingestion, parser, evidence-store, deletion or API
behavior was changed.

## 7. Security constraints

The analysis engine performs no network, DNS, socket, filesystem, model,
attachment extraction/execution or HTML rendering. It processes only parsed
metadata and stored HTML text. Header-derived reasons explicitly state the
values are sender-claimed or claimed. No new dependency or infrastructure was
introduced.

## 8. Tests executed and results

Focused signal and score tests:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_signals.py tests/test_score.py -q
22 passed, 1 warning
```

Persistence integration test:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/integration/test_analysis.py -q
1 passed, 1 warning
```

Full backend suite:

```text
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q
316 passed, 1 warning
```

The warning is the pre-existing `StarletteDeprecationWarning` for
`httpx` + `starlette.testclient`.

Coverage includes T-42 through T-46, T-51 storage, T-52 uniqueness (existing
constraint test retained plus repeat-analysis test), all band boundaries,
clamping, malformed inputs, normalization, deduplication, archive mapping,
HTML forms and deterministic repeated output.

## 9. Ruff and diff checks

```text
.venv/bin/ruff check . --no-cache
All checks passed!

.venv/bin/ruff format --check . --no-cache
74 files already formatted

git diff --check
clean
```

## 10. Deviations and unresolved issues

No deviation from the approved v1 policy. The only additional module beyond
the four named implementation files is `analysis/service.py`, required for the
§12.2 persistence flow, plus the package `__init__.py`.

T-51's report-endpoint assertion is intentionally deferred to Milestone 2.3.7;
this milestone verifies result storage only.

## 11. Preservation and authorization

Pre-existing untracked artifact preserved unchanged:

```text
PHISHGUARD-Milestone-2.3.3-Code-Review.diff
SHA-256: 3385b7b46973c6b012543efd5009a868afcd993882b9952f47ab4155fa427b16
```

No commit, push, pull request, merge, migration, dependency, CI, Docker,
database-schema or infrastructure change was performed. No unrelated project
file was modified. Awaiting owner review and explicit authorization before any
Git workflow action.
