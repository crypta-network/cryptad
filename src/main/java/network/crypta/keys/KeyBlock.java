package network.crypta.keys;

import network.crypta.store.StorableBlock;

/**
 * Represents a fetched, storable key block.
 *
 * <p>A {@code KeyBlock} is the raw result of retrieving a block identified by a {@link Key} (e.g.,
 * CHK/SSK). Client code typically uses a {@link ClientKey} to construct a {@link ClientKeyBlock}
 * from this interface and then decodes the payload into a {@link
 * network.crypta.support.api.Bucket}. Implementations expose the unprocessed bytes that were
 * received from the network or read from disk so higher layers can verify and decode them.
 *
 * <p>This interface only defines accessors; it does not prescribe mutability or thread-safety.
 */
public interface KeyBlock extends StorableBlock {

  /**
   * Constant identifier for the SHA‑256 hash algorithm.
   *
   * <p>The exact usage depends on the concrete block type and associated header format.
   */
  int HASH_SHA256 = 1;

  /**
   * Returns the locating key for this block.
   *
   * @return the {@link Key} that identifies the block instance.
   */
  Key getKey();

  /**
   * Returns the raw header bytes associated with the block, if any.
   *
   * <p>The format and presence of headers are defined by the concrete key type. The bytes are
   * provided as obtained from storage or the wire without interpretation.
   *
   * @return the header bytes in their original encoding.
   */
  byte[] getRawHeaders();

  /**
   * Returns the raw payload bytes of the block.
   *
   * <p>These bytes are the undecoded content to be verified and decrypted/decoded by key‑specific
   * logic (e.g., via {@link ClientKey} → {@link ClientKeyBlock}).
   *
   * @return the block payload bytes as stored or received.
   */
  byte[] getRawData();

  /**
   * Returns the public key bytes associated with this block.
   *
   * <p>The presence and format of the public key depend on the block type (for example, SSK may
   * include a key, while CHK may not). The bytes are returned in the block’s native encoding.
   *
   * @return the public key bytes for verification or decoding.
   */
  byte[] getPubkeyBytes();
}
