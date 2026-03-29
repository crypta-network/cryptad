/**
 * Peer-reference text loading helpers shared by runtime and client adapters.
 *
 * <p>This package hosts the small, transport-neutral seam that turns noderef text stored behind a
 * regular URL or a Freenet URI into the newline-preserving {@link java.lang.StringBuilder} form
 * expected by existing peer-add parsers. Keeping that logic in runtime code lets HTTP toadlets,
 * text-mode endpoints, and FCP compatibility shims reuse one implementation without importing each
 * other's transport-specific classes.
 *
 * <p>The classes here are intentionally narrow. They preserve established charset handling and
 * fetch limits while helping the surrounding codebase continue its package-boundary cleanup with
 * minimal behavior risk.
 */
package network.crypta.runtime.peers.reference;
