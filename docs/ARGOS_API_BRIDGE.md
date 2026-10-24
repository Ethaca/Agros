# Argos API → dynamic-scan bridge

**Argos API** is Argos's *static / GitHub-PR* half: it reads a PR diff and reports
OWASP API Top 10 candidates, but it does not run the app — every path is marked
`verificationStatus: "not_run"`. The dynamic engine is the other half: it boots
the app and attacks it with multiple personas. This bridge turns a static
*SUSPECT* into a dynamic *PROOF*.

```
PR diff ──▶ Argos API (static)                 findings.json ("not_run")
                                                     │  argos import-findings
                                                     ▼
                          argos resources / draft config  (routes + checks inferred)
                                                     │  argos scan
                                                     ▼
                          persona × resource matrix: 🔴 VULNERABLE / 🟢 OK  (proven)
```

## Usage

Export findings from Argos API as JSON, then feed them to the dynamic scan:

```bash
# draft a new config from the findings
argos import-findings findings.json --out argos.config.yaml
#   ...complete the TODO fields (start command, auth tokens, owner columns), then:
argos scan --config argos.config.yaml

# or cross-reference findings against a config you already have
argos import-findings findings.json --config argos.config.yaml
```

## What the bridge does (`src/bridge.ts`)

- **Category → check.** `API1→bola`, `API2/API5/API9→unauth`, `INJECTION→sqli`,
  `API3/SECRETS→secrets`. Categories the dynamic engine can't execute yet (SSRF,
  misconfig, rate limits, upstream APIs) are listed as `unmapped`, not silently
  dropped.
- **Route extraction.** Pulls `METHOD /path` from the finding's code quote
  (`app.get("/api/datasets/:id", …)` → `GET /api/datasets/:id`). Express `:param`
  is already Argos-native.
- **Owner table.** A route handler and its SQL sink come back as separate findings
  a few lines apart; the bridge attaches the table from a nearby sink
  (`SELECT * FROM datasets …` → `owner.table: datasets`) to the route above it.
- **Draft config.** Emits an `argos.config.yaml` with the inferred resources and
  `checks`. `target`/`seed`/`personas` and `owner.column` are left as TODO —
  static analysis can't know the boot command or auth tokens (same contract as
  `argos init`).
- **Annotate.** Matches findings to the resources of an existing config by route,
  so the matrix shows which endpoints the static analysis also flagged.

## Worked example (demo/vendor-platform)

The static scan of the demo app returns 6 findings (4× API1 BOLA, 1× API5,
1× API9). `argos import-findings --config` cross-references them with the demo's
`argos.config.yaml`:

```
🔎 dataset-read   (GET /api/datasets/:id)  flagged by [F4] → argos scan will prove it
🔎 vendor-profile (GET /api/vendors/:id)   flagged by [F5] → argos scan will prove it
🔎 debug-env      (GET /debug/env)         flagged by [F3, F6] → argos scan will prove it
```

`argos scan` then proves them for real — e.g. `dataset-read` comes back
`🔴 [bola] vendor2 read v1's data. GET /api/datasets/1: expected deny, observed allow [200]`.
The static "suspect" is now an executed proof.

See `test/bridge.test.ts` (run against the captured fixture
`test/fixtures/argos-api-findings.json`).
