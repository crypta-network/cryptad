/**
 * Cryptographic key types and related blocks/URIs used by Crypta (Freenet‑compatible).
 *
 * <p>This package implements the core key families and their client/node utilities:
 *
 * <ul>
 *   <li><b>CHK</b> (Content Hash Key) — content‑addressed; verification uses hash matching.
 *   <li><b>SSK</b> (Signed Subspace Key) — keypair‑based; verification uses digital signatures.
 *   <li><b>USK</b> (Updatable Subspace Key) — a client‑side alias and update scheme built on SSK;
 *       not a distinct node‑level key type. See {@link network.crypta.keys.USK}.
 * </ul>
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Node‑level verification of blocks (hash and signature checks).
 *   <li>Client‑level encoding/decoding of keys, blocks, and {@link network.crypta.keys.FreenetURI}
 *       forms.
 * </ul>
 *
 * <p>Encode/decode/verify failures are reported via typed exceptions such as {@link
 * network.crypta.keys.CHKDecodeException}, {@link network.crypta.keys.CHKEncodeException}, {@link
 * network.crypta.keys.CHKVerifyException}, {@link network.crypta.keys.SSKDecodeException}, {@link
 * network.crypta.keys.SSKEncodeException}, {@link network.crypta.keys.SSKVerifyException}, and
 * {@link network.crypta.keys.PubkeyVerifyException}.
 */
package network.crypta.keys;
