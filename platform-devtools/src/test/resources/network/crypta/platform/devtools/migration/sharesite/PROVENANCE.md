# Sharesite synthetic binary conformance vectors

These files contain deterministic synthetic data. They are not real-user migration evidence.
The binary files were produced offline on Java 25.0.4.1 by the unmodified `MapToData.mapToData`
writer and `SmartMap` classes from `hyphanet/plugin-sharesite` revision
`c99ad9c8e83004f904f8ee742ab2861f5751ee3b`.

| Input source | Exact Git blob |
| --- | --- |
| [MapToData.java](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/src/plugins/Sharesite/common/MapToData.java) | `9725e87fc6d5cc22434579b06f5f8122f963d2bc` |
| [SmartMap.java](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/src/plugins/Sharesite/common/SmartMap.java) | `e5aeeea9d477b38db049517fc7b5dda64e1b06ff` |
| [LICENSE](https://github.com/hyphanet/plugin-sharesite/blob/c99ad9c8e83004f904f8ee742ab2861f5751ee3b/LICENSE) | `4362b49151d7b34ef83b3067a8f9c9f877d72a0e` |

The upstream repository carries GNU LGPL 2.1 text. No upstream implementation code or Textile
runtime is vendored here. Production decoding independently implements the observed framing.
Ordinary tests read these checked-in binary fixtures and do not download or execute legacy code.

| File | SHA-256 |
| --- | --- |
| `upstream-empty.db` | `d5108daf198fa75ed90d090ab1480f03d9b672876f9b97f52ae162d03ef6e378` |
| `upstream-mixed.db` | `89cebfb977a2cd6687954eb618570d79bf00b617a8d334062a8d2bb744cf162a` |

The empty fixture is the writer output for a new empty `SmartMap`. It has the literal UTF-8
header `ShareWiki-db-ver1` followed by a four-byte big-endian zero count.

The mixed fixture was constructed through the upstream `SmartMap` setters with these values:

- Root `keys` integer list `[0, 2]`; `deleted_keys` list `[1]`; `increasingCounter=3`;
  `lastDeletedTime=1234567890`.
- For each ID `0`, `1`, and `2`: `name="Synthetic page " + id`,
  `description="Synthetic PRIVATE description"`, `pastebin=(id != 2)`,
  `css="body { color: red; }"`, empty `activelinkUri` and `requestSSK`,
  `insertSSK="SYNTHETIC_SECRET_CANARY_DO_NOT_EXPORT"`, `edition=-1`, `insertHour=-1`,
  `l10nStatus="Status.New"`. Historical `path` is deliberately absent.
- ID `0` text is Java literal `"<script>inert</script>\r\n\u03b1\n\ud83d\ude42\r"`.
  The other IDs have empty literal text.

`mapToData` traverses `HashMap` entries, so order is not an interchange identity. The exact frozen
bytes above provide provenance; converter tests also reorder independent format-compatible maps
to verify that logical content and draft identity do not depend on entry order.

The synthetic canary is intentionally present only in the source fixture. Tests require it to be
absent from converted records and diagnostics. Fixture checksums may be public because these bytes
are synthetic; real snapshot and text fingerprints remain private local consent/fidelity data.
