# Release certification tooling

This directory contains the release-candidate evidence aggregator used by the release runbook.

The tooling requires Python 3.10 or newer and depends only on the Python standard library.  The
self-tests do not start Cryptad, download a Hyphanet baseline, require signing keys, or contact the
network.

## Commands

Run the Python-only self-tests:

```bash
python3 tools/release-certification/release_certification.py --self-test
python3 tools/release-certification/app_platform_smoke.py --self-test
```

Generate a quick local report without running expensive Gradle or node gates:

```bash
tools/release-certification/run-release-certification.sh
```

Generate release-candidate evidence under the standard output directory:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --out-dir build/release-certification
```

The wrapper runs the app-platform smoke collector, then aggregates existing interop and
performance summaries when they are present.  In `pr` mode it skips Gradle by default so local and
normal CI use stay lightweight.  Set `CRYPTAD_CERT_RUN_GRADLE=1` or pass `--mode nightly` or
`--mode release-candidate` to run the app-platform Gradle staging and CLI checks.

## Outputs

The stable release evidence outputs are:

```text
build/release-certification/
  release-certification-summary.json
  release-certification-report.md
  artifacts/
  app-platform-smoke/
    summary.json
    app-platform-smoke-report.md
    artifacts/
```

The summary uses stable evidence ids and status values:

```text
pass
warn
fail
skip
missing
```

Each item contains `id`, `status`, `requiredForReleaseCandidate`, `summary`, `source`, and
`details`.

## Required release-candidate evidence

Release-candidate mode fails when required evidence is missing, skipped, or failing unless a waiver
is recorded.  The required evidence ids are:

```text
interop.smoke
performance.smoke
app-platform.first-party
app-platform.devtools-cli
app-platform.signed-bundles
catalog.smoke
app-ui.smoke
legacy.retirement
```

`interop.extended` and `apphost.live` are recorded as optional stronger evidence.  Extended interop
is still required by the release runbook when compatibility-sensitive behavior changed.  Live
AppHost lifecycle evidence is optional because normal PR CI must not require a running node or
operator credentials.

Record an explicit waiver when a release manager accepts missing optional or replacement evidence:

```bash
tools/release-certification/run-release-certification.sh \
  --mode release-candidate \
  --waive interop.extended="No compatibility-sensitive behavior changed in this release."
```

Waivers change the evidence item to `warn`, preserve the original reason in `details`, and keep the
release-candidate gate from failing for that item.

## App-platform smoke

The app-platform smoke runner validates first-party staged app manifests, static app UI/SDK
coherence, the `crypta-app` developer CLI, signed bundle evidence when signing inputs are present,
signed catalog authoring/verification, and the legacy-admin retirement map.

Signing inputs use the documented first-party app environment variables:

```text
CRYPTAD_APP_SIGNING_KEY_ID
CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64
CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE
CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64
CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE
```

In `pr` and `nightly` modes, missing signing inputs are recorded as skipped or warning evidence.
In `release-candidate` mode, missing signed bundle or signed catalog evidence is a failing required
item.

Optional live-node AppHost lifecycle smoke is enabled only when requested:

```bash
CRYPTAD_CERT_APP_SMOKE_LIVE=1 \
CRYPTAD_CERT_NODE_BASE_URL=http://127.0.0.1:8888 \
CRYPTAD_CERT_FORM_PASSWORD=<redacted> \
tools/release-certification/run-release-certification.sh --mode nightly
```

The live smoke only records localhost node metadata.  It redacts the form password and does not
write raw request bodies.

## Redaction

Certification outputs must remain suitable for release-candidate evidence.  Do not upload or paste:

- private signing keys;
- app process tokens;
- browser-session tokens;
- the host/operator form password;
- raw request bodies;
- full query strings that may contain secrets;
- private insert URIs;
- developer-specific absolute filesystem paths;
- non-localhost remote endpoint metadata.

The aggregator sanitizes paths as `<repo>`, `<workdir>`, `<home>`, or `<path>` placeholders.  It
also filters `artifacts/private-insert-uris.json` from interop evidence even when the source
`summary.json` mentions that private diagnostics file.
