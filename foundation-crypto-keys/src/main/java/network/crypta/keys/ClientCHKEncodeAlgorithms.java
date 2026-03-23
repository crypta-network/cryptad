package network.crypta.keys;

/**
 * Bundles algorithm identifiers and metadata flags for client-side CHK encoding.
 *
 * <p>This record carries the algorithm selectors and metadata flag that are embedded into CHK
 * headers and used to steer encode behavior. It is typically created alongside a {@link
 * ClientCHKEncodePayload} and then passed into {@link ClientCHKEncodeParams} so that call sites can
 * communicate all header-related choices in a single value. The record is a shallow, immutable
 * carrier; it does not validate the identifiers or interpret their meaning beyond storing them.
 *
 * <p>This type treats the values as simple scalars. Callers are responsible for ensuring that the
 * identifiers match supported algorithms and that the metadata flag correctly reflects the intended
 * key semantics. Because the record is immutable and thread-safe, it can be freely shared across
 * threads as long as the surrounding encoding workflow is safe for reuse.
 *
 * <ul>
 *   <li>Captures the metadata flag that distinguishes content from metadata blocks.
 *   <li>Stores compression, crypto, and block-hash identifiers without validation.
 * </ul>
 *
 * @param asMetadata whether the resulting key represents metadata rather than content
 * @param compressionAlgorithm compression algorithm identifier recorded in the generated key
 * @param cryptoAlgorithm crypto algorithm identifier indicating the cipher used for the block
 * @param blockHashAlgorithm block hash identifier recorded in the block header
 * @see ClientCHKEncodeParams
 * @see ClientCHKEncodePayload
 */
public record ClientCHKEncodeAlgorithms(
    boolean asMetadata, short compressionAlgorithm, byte cryptoAlgorithm, int blockHashAlgorithm) {}
