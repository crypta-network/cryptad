# Security release notes template

Use this template for app ecosystem security advisories, emergency catalog updates, reviewer-key
responses, catalog signing key rotations, and app signing key compromise responses.

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
- Trigger signal:
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

- Reporter or team:
- Acknowledgements:
- Private reporter details retained outside public notes:
