package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.NodeCHK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Store adapter for {@link network.crypta.keys.CHKBlock}.
 *
 * <p>This {@link StoreCallback} specialization wires the CHK block type to a {@link FreenetStore}.
 * It specifies fixed sizes for data, headers, routing keys, and full keys; it constructs a {@link
 * network.crypta.keys.CHKBlock} from raw bytes; and it delegates fetch and put operations to the
 * underlying store.
 *
 * <p>For CHK, the routing key is an SHA‑256 digest of {@code headers || data}. Collisions between
 * different blocks are considered cryptographically infeasible and are treated as impossible by
 * this adapter.
 */
public class CHKStore extends StoreCallback<CHKBlock> {
  private static final Logger LOG = LoggerFactory.getLogger(CHKStore.class);

  /**
   * Report whether distinct blocks can share a key.
   *
   * <p>Because a CHK key is derived from an SHA‑256 hash of the content, two different blocks
   * having the same key are treated as impossible.
   *
   * @return {@code false} — collisions are not expected for CHK.
   */
  @Override
  public boolean collisionPossible() {
    return false;
  }

  /**
   * Construct a {@link CHKBlock} from raw components.
   *
   * <p>Both {@code data} and {@code headers} must be non-null. The crypto algorithm is derived from
   * the supplied {@code fullKey} (see {@link NodeCHK#cryptoAlgorithmFromFullKey(byte[])}), and the
   * block is instantiated via {@link CHKBlock#construct(byte[], byte[], byte)}. The {@code
   * DSAPublicKey} parameter is unused for CHK and may be {@code null}.
   *
   * @param payload payload bytes, headers, and key material for the block.
   * @param options cache flags and metadata; ignored for CHK.
   * @param ignored unused for CHK.
   * @return a verified {@link CHKBlock} instance.
   * @throws KeyVerifyException if {@code data} or {@code headers} is {@code null}, or if header
   *     validation within {@link CHKBlock} fails.
   */
  @Override
  public CHKBlock construct(BlockPayload payload, ConstructOptions options, DSAPublicKey ignored)
      throws KeyVerifyException {
    if (payload.data() == null || payload.headers() == null)
      throw new CHKVerifyException("Need either data and headers");
    return CHKBlock.construct(
        payload.data(), payload.headers(), NodeCHK.cryptoAlgorithmFromFullKey(payload.fullKey()));
  }

  /**
   * Fetch a CHK block from the underlying store.
   *
   * <p>Delegates to {@link FreenetStore#fetch(byte[], byte[], boolean, boolean, boolean, boolean,
   * BlockMetadata)} with the routing and full keys from {@code chk}. Client and slashdot caches are
   * not consulted for CHK; both flags are forwarded as {@code false}.
   *
   * @param chk node-level CHK containing routing and full keys.
   * @param dontPromote when {@code true}, does not promote the entry in the store's LRU.
   * @param ignoreOldBlocks when {@code true}, suppresses return of blocks flagged as old in {@code
   *     meta}.
   * @param meta metadata container populated by the store.
   * @return the stored {@link CHKBlock}, or {@code null} when not found.
   * @throws IOException if the underlying store reports an I/O error.
   */
  public CHKBlock fetch(
      NodeCHK chk, boolean dontPromote, boolean ignoreOldBlocks, BlockMetadata meta)
      throws IOException {
    // NOTE: Optimize the API to pass the crypto algorithm explicitly instead of requiring a
    // materialized full key here; avoids allocating the .keys representation on read paths.
    return store.fetch(
        chk.getRoutingKey(), chk.getFullKey(), dontPromote, false, false, ignoreOldBlocks, meta);
  }

  /**
   * Store a CHK block in the underlying datastore.
   *
   * <p>Writes the raw data and headers and does not allow overwriting existing content. A {@link
   * KeyCollisionException} is logged and ignored because CHK collisions are treated as impossible
   * for distinct content.
   *
   * @param b block to store.
   * @param isOldBlock when {@code true}, marks the entry as old so it is excluded from Bloom-based
   *     sharing.
   * @throws IOException if the underlying store reports an I/O error.
   */
  public void put(CHKBlock b, boolean isOldBlock) throws IOException {
    try {
      store.put(b, b.getRawData(), b.getRawHeaders(), false, isOldBlock);
    } catch (KeyCollisionException e) {
      LOG.error("Impossible for CHKStore: {}", e, e);
    }
  }

  /**
   * Return the fixed payload size for CHK data.
   *
   * @return {@link CHKBlock#DATA_LENGTH} (32,768 bytes).
   */
  @Override
  public int dataLength() {
    return CHKBlock.DATA_LENGTH;
  }

  /**
   * Return the fixed size of a serialized CHK full key.
   *
   * @return {@link NodeCHK#FULL_KEY_LENGTH} (34 bytes).
   */
  @Override
  public int fullKeyLength() {
    return NodeCHK.FULL_KEY_LENGTH;
  }

  /**
   * Return the fixed size of CHK headers.
   *
   * @return {@link CHKBlock#TOTAL_HEADERS_LENGTH} (36 bytes).
   */
  @Override
  public int headerLength() {
    return CHKBlock.TOTAL_HEADERS_LENGTH;
  }

  /**
   * Return the fixed size of a CHK routing key.
   *
   * @return {@link NodeCHK#KEY_LENGTH} (32 bytes).
   */
  @Override
  public int routingKeyLength() {
    return NodeCHK.KEY_LENGTH;
  }

  /**
   * Indicate that the store should persist full keys in a sidecar file.
   *
   * <p>Keeping full keys allows lazy reconstruction during compaction or migration by transcoding
   * directly from the {@code .keys} file without instantiating every block.
   *
   * @return {@code true} — persist full keys.
   */
  @Override
  public boolean storeFullKeys() {
    // With full keys we can transcode from .keys straight into the database without constructing
    // each block.
    return true;
  }

  /**
   * Report whether reconstruction requires key material to be supplied.
   *
   * <p>For CHK, integrity verification relies on hashing {@code headers || data}, not on external
   * key material. This method therefore reports {@code false}.
   *
   * @return {@code false} — CHK construction does not require a key for integrity.
   */
  @Override
  public boolean constructNeedsKey() {
    return false;
  }

  /**
   * Compute routing-key bytes from a CHK full key or return the given routing key.
   *
   * <p>Delegates to {@link NodeCHK#routingKeyFromFullKey(byte[])}; see that method for accepted
   * input sizes and recovery behaviors.
   *
   * @param keyBuf routing key (32 bytes) or full key (34 bytes).
   * @return routing key bytes or {@code null} for unsupported lengths.
   */
  @Override
  public byte[] routingKeyFromFullKey(byte[] keyBuf) {
    return NodeCHK.routingKeyFromFullKey(keyBuf);
  }
}
