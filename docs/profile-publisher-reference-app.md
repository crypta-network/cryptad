# Profile Publisher reference app

Profile Publisher is the first-party static app for creating bounded public profile documents from
app-owned identities. It composes AppVault identity metadata, the bounded profile-document signing
route, generated app-document insertion, queue status, and app-owned durable draft state.

These content profiles are Crypta app ecosystem profiles. They are not compatibility promises for
legacy WoT, Freetalk, Sone, Freemail, or any old plugin ABI/protocol.

Profile documents use the `crypta.profile.v1` content format profile:

| Property | Value |
| --- | --- |
| Schema | `crypta.profile.v1` |
| Content type | `application/vnd.crypta.profile+json` |
| Default filename | `profile.json` |
| Signing purpose | `profile.publish.v1` |
| Status | experimental |
| Max document bytes | 65536 |
| Max signed payload bytes | 32768 |

The browser UI uses `CryptaPlatform.contentFormats.profileDocument` for the schema, content type,
default filename, byte bounds, and signing purpose. The AppVault route rejects unknown profile
parameters before signing, emits deterministic canonical payload JSON, and returns a signed
document with public verification material only.

Profile Publisher app-data stores bounded draft fields, selected identity id, last published URI
summary, and recent publish summaries. It must not persist raw signed profile documents, private
identity material, private insert URIs, raw app-data values, tokens, browser sessions, or local
paths. Release evidence records profile format status, route names, checks, and digests rather
than raw profile documents or raw signatures.

For the cross-app content format table, version policy, canonicalization rules, and release
certification evidence, see
[trust-social-content-format-profiles.md](trust-social-content-format-profiles.md).
