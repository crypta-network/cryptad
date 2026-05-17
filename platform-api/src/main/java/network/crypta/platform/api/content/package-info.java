/**
 * Bounded app-facing content fetch endpoints for Crypta content documents.
 *
 * <p>This package owns the transport-neutral Platform API adapter for foreground content reads,
 * currently {@code POST /api/v1/content/fetch}. It turns decoded form parameters into bounded
 * runtime content-fetch requests, limits app principals to Crypta/Freenet content keys, and returns
 * JSON-compatible maps that the shared Platform API response writer can serialize directly. The
 * package exists so first-party and third-party apps can demonstrate content consumption without
 * taking dependencies on daemon URI classes, client-layer fetch APIs, legacy toadlets, or local
 * filesystem paths.
 *
 * <p>The boundary is intentionally strict. App callers receive byte and timeout caps, sanitized URI
 * diagnostics, stable error codes, and either strict UTF-8 text or base64 content. They do not
 * receive raw runtime exception messages, request bodies, fetched bodies in audit records, browser
 * session tokens, process tokens, form passwords, or private local paths. Local file reads,
 * arbitrary HTTP(S) fetches, LAN probing, and background subscription services are outside this
 * package's contract.
 *
 * <p>Authorization, audit recording, and method/path dispatch remain in the parent Platform API
 * router and capability registry. Runtime fetch mechanics remain behind {@code :runtime-spi} and
 * the daemon implementation. This package only performs app-facing validation, normalization,
 * response shaping, and runtime-error translation for the content route family.
 *
 * @see network.crypta.platform.api.content.ContentApiHandler
 * @see network.crypta.runtime.spi.ContentFetchPort
 */
package network.crypta.platform.api.content;
