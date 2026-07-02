/**
 * Versioned content format profile descriptors for Crypta app ecosystem documents.
 *
 * <p>The package contains metadata and canonical JSON helpers shared by Platform API builders,
 * browser SDK mirrors, reference app checks, and release certification. It does not parse untrusted
 * document bodies or expose raw fetched content, raw app data, signatures, tokens, private insert
 * URIs, private keys, or local paths.
 *
 * <p>Callers use the registry to discover profile ids, MIME types, default filenames, lifecycle
 * status, byte limits, signing domains, and version policy labels. Profile-specific parsers remain
 * responsible for required fields, unknown-field rejection, canonical payload construction, and
 * signature verification.
 */
package network.crypta.platform.api.contentformats;
