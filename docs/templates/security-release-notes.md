# Security release notes template

Use this template for app ecosystem security advisories, emergency catalog updates, reviewer-key
responses, catalog signing key rotations, and app signing key compromise responses.

## Stable vulnerability advisory identity

- Advisory id: `<authorized-csa-id>`
- Advisory edition: `<positive-integer-edition>`
- Previous advisory digest: `<sha256-or-none>`
- Status: `<published|updated|superseded|withdrawn>`
- Authorized exact content digest: `<sha256>`
- Opaque public case binding: `<authorized-case-id-or-public-case-digest>`
- Stable milestone: `1.0`
- Integer fixed or mitigated build: `<build-number-or-not-applicable>`
- Exact affected public identities: `<approved-build-package-app-component-list>`
- Exact fixed or mitigated public identities: `<approved-build-package-app-component-list>`
- Mitigation versus fix: `<fixed|temporarily-mitigated>`
- Release/catalog/lifecycle references: `<exact-authorized-public-references>`
- External identifiers: `<optional-authorized-cve-ghsa-osv-vendor-references>`
- Supersedes/superseded by: `<immutable-advisory-id-or-none>`
- Redaction status: `<pass>`

Do not fill these fields from an issue, pull request, branch, commit message, mutable `latest`
target, or external identifier. Use the exact protected disclosure authorization and verified
publication receipt. For a Stable vulnerability advisory, render these values from the canonical
advisory bytes; do not manually repeat or broaden them in the generic fields below.

## Advisory

- Advisory id:
- Severity:
- Status:
- Published:
- Updated:
- Affected apps and versions:
- Affected signing key id or fingerprint:
- Affected reviewer key id:
- Affected catalog id and catalog signing key id:

## Impact

- Impact summary:
- Public-safe impact category:
- Required operator action:
- Known limitations:

## Containment

- Catalog advisory action:
- Denylisted exact versions:
- Review receipt revocations:
- Reviewer key lifecycle changes:
- Catalog signing key rotation status:
- Replacement app/version:
- Channel status:

## Operator guidance

- Update guidance:
- Safe uninstall guidance:
- Export-before-uninstall guidance:
- Replacement guidance:
- Web Shell status labels:
- Support bundle guidance:

## Verification

- Security drill scenario:
- Security drill artifact digest:
- Security drill summary status:
- Signed catalog verified:
- Advisory parser/writer verified:
- Install/update/stage/apply gates verified:
- App update scheduler behavior verified:
- Review trust and receipt revocation verified:
- Web Shell/operator summary verified:
- Support redaction verified:
- Release certification evidence id:

## Redaction note

This advisory excludes private keys, private insert URIs, bearer/session/app tokens, raw fetched
content, raw app data, raw request bodies, raw trust statements, raw signatures, command lines
containing secrets, local absolute paths, CI secret values, and reporter private data.

## Credits

Omit the reporter-credit field entirely unless the exact protected opt-in consent record authorizes
the exact public-safe text. Do not include a blank reporter placeholder, contact detail, private
alias, or internal reporter reference.

- Optional authorized public credit:
- Public acknowledgements:

Private reporter details are excluded from these notes and retained only through the protected
contact-location boundary.

Reporter consent binds the exact public-safe credit text. It does not authorize release,
disclosure, catalog or lifecycle mutation, key action, or case closure.
