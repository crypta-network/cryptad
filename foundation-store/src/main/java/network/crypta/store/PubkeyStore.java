package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.CryptFormatException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.PubkeyVerifyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Store adapter for {@link network.crypta.crypt.DSAPublicKey} blocks.
 *
 * <p>This callback binds the {@link DSAPublicKey} type to a {@link FreenetStore} by defining fixed
 * sizes, construction logic, and key handling rules. For DSA public keys, the routing key and the
 * full key are identical and equal to the SHA-256 of the serialized key bytes (see {@link
 * DSAPublicKey#asBytesHash()}). Collisions are therefore not expected for distinct keys.
 */
public class PubkeyStore extends StoreCallback<DSAPublicKey> {
  private static final Logger LOG = LoggerFactory.getLogger(PubkeyStore.class);

  /** {@inheritDoc} In this store distinct public keys do not collide. */
  @Override
  public boolean collisionPossible() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Constructs a {@link DSAPublicKey} from the provided {@code data}. Headers and key material
   * are not used for reconstruction in this implementation. The {@code data} buffer typically
   * contains the padded serialization as produced by {@link DSAPublicKey#asPaddedBytes()} but the
   * factory tolerates trailing zeros.
   *
   * @param payload payload bytes and key material for the block.
   * @param options cache flags and metadata; ignored here.
   * @param ignored preconstructed value (from callers that already resolved a key); ignored here.
   * @return a new {@link DSAPublicKey} instance parsed from {@code data}.
   * @throws KeyVerifyException if the byte sequence cannot be parsed as a public key.
   */
  @Override
  public DSAPublicKey construct(
      BlockPayload payload, ConstructOptions options, DSAPublicKey ignored)
      throws KeyVerifyException {
    if (payload.data() == null) throw new PubkeyVerifyException("Need data to construct pubkey");
    try {
      return DSAPublicKey.create(payload.data());
    } catch (CryptFormatException e) {
      throw new PubkeyVerifyException(e);
    }
  }

  /**
   * Fetches a public key by its routing key from the underlying store.
   *
   * <p>This delegates to {@link FreenetStore#fetch(byte[], byte[], boolean, boolean, boolean,
   * boolean, BlockMetadata)} with {@code fullKey = null} and both caches disabled, as public key
   * reconstruction does not require them.
   *
   * @param hash routing key (SHA-256 of the serialized key) used as the datastore key.
   * @param dontPromote when {@code true}, does not promote the entry in the store's LRU.
   * @param ignoreOldBlocks when {@code true}, ignores entries marked as old.
   * @param meta optional metadata container populated during the fetch.
   * @return the matching {@link DSAPublicKey}, or {@code null} if not found.
   * @throws IOException on I/O errors from the underlying store.
   */
  public DSAPublicKey fetch(
      byte[] hash, boolean dontPromote, boolean ignoreOldBlocks, BlockMetadata meta)
      throws IOException {
    return store.fetch(hash, null, dontPromote, false, false, ignoreOldBlocks, meta);
  }

  // Shared empty header buffer; public keys do not carry a store header.
  private static final byte[] empty = new byte[0];

  /**
   * Stores a public key using its padded serialization as the data section.
   *
   * <p>Headers are not used and an empty buffer is supplied. Key collisions are considered
   * impossible for this block type; a collision would indicate a deeper inconsistency and is logged
   * as an error.
   *
   * @param key the key to persist.
   * @param isOldBlock whether the entry should be flagged as old for Bloom sharing.
   * @throws IOException on I/O errors from the underlying store.
   */
  public void put(DSAPublicKey key, boolean isOldBlock) throws IOException {
    try {
      store.put(key, key.asPaddedBytes(), empty, false, isOldBlock);
    } catch (KeyCollisionException e) {
      LOG.error("Impossible for PubkeyStore: {}", e, e);
    }
  }

  /** {@inheritDoc} Fixed to {@link DSAPublicKey#PADDED_SIZE}. */
  @Override
  public int dataLength() {
    return DSAPublicKey.PADDED_SIZE;
  }

  /** {@inheritDoc} Fixed to {@link DSAPublicKey#HASH_LENGTH}. */
  @Override
  public int fullKeyLength() {
    return DSAPublicKey.HASH_LENGTH;
  }

  /** {@inheritDoc} Public keys have no separate header section. */
  @Override
  public int headerLength() {
    return 0;
  }

  /** {@inheritDoc} Fixed to {@link DSAPublicKey#HASH_LENGTH}. */
  @Override
  public int routingKeyLength() {
    return DSAPublicKey.HASH_LENGTH;
  }

  /** {@inheritDoc} This store does not persist full keys in a sidecar. */
  @Override
  public boolean storeFullKeys() {
    return false;
  }

  /** {@inheritDoc} Reconstruction uses only the data bytes. */
  @Override
  public boolean constructNeedsKey() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * <p>For {@link DSAPublicKey} the full key and the routing key are equal, so the buffer is
   * returned unchanged.
   */
  @Override
  public byte[] routingKeyFromFullKey(byte[] keyBuf) {
    return keyBuf;
  }
}
