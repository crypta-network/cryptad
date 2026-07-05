# Public beta known issues

This tracker is a deterministic, redaction-safe index for public beta issues that maintainers have
confirmed or are actively investigating. It stores metadata only. Do not paste issue bodies, support
bundle contents, app data, fetched content, social messages, profile documents, trust statements,
private URIs, local paths, or stack traces.

Machine-readable sample metadata is kept in
`tools/release-certification/public-beta-known-issues.json`. Release certification verifies that this
document and the JSON metadata stay redaction-safe.

## Required fields

Each known issue entry must include:

- `knownIssueId`
- `status`
- `severity`
- `area`
- `affectedChannels`
- `affectedAppIds`
- `affectedVersions`
- `firstSeenReleaseId`
- `fixedInReleaseId`
- `workaroundSummary`
- `supportBundleEvidenceAllowed`
- `redactionNotes`
- `backlogLinkOrPlaceholder`

## Entries

### PBKI-EXAMPLE-001: Catalog mirror health warning after channel refresh

- `knownIssueId`: `PBKI-EXAMPLE-001`
- `status`: `open-example`
- `severity`: `severity/medium`
- `area`: `area/catalog`
- `affectedChannels`: `stable-first-party`
- `affectedAppIds`: `none`
- `affectedVersions`: `cryptad-beta-example`
- `firstSeenReleaseId`: `cryptad-beta-example`
- `fixedInReleaseId`: `unfixed`
- `workaroundSummary`: Refresh the catalog from another configured mirror and include only catalog
  ID, channel, health status, signature verification status, and a support bundle digest in public
  feedback.
- `supportBundleEvidenceAllowed`: `digest-and-summary-only`
- `redactionNotes`: Do not include catalog source private material, private insert URIs, mirror
  operator local paths, raw support bundle files, or raw request and response bodies.
- `backlogLinkOrPlaceholder`: `BACKLOG-PUBLIC-BETA-CATALOG-MIRROR-EXAMPLE`

## Release-note linkage

When a known issue is fixed, moved to backlog, or waived, the beta release notes should cite the
`knownIssueId`, area, severity, safe workaround summary, fixed release ID, and verification status.
Use [../templates/beta-release-notes.md](../templates/beta-release-notes.md) for the public text.
