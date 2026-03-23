package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;

/**
 * Store adapter for Signed Subspace Key (SSK) blocks.
 *
 * <p>An {@code SSKStore} binds the {@link FreenetStore} interface to the SSK block type by defining
 * fixed sizes, constructing {@link SSKBlock} instances from raw bytes, and delegating fetch/put
 * operations. It resolves the {@link DSAPublicKey} required to verify an SSK by using a {@link
 * GetPubkey} provider when the public key is not already attached to the reconstructed {@link
 * NodeSSK}.
 */
public class SSKStore extends StoreCallback<SSKBlock> {

  /** Provider used to retrieve and cache DSA public keys by hash when reconstructing SSKs. */
  private final GetPubkey<DSAPublicKey> pubkeyCache;

  /**
   * Creates a new store adapter for SSK blocks.
   *
   * @param pubkeyCache source used to resolve {@link DSAPublicKey}s by their SHA‑256 hash when the
   *     key is not already attached to the {@link NodeSSK} being reconstructed.
   */
  public SSKStore(GetPubkey<DSAPublicKey> pubkeyCache) {
    this.pubkeyCache = pubkeyCache;
  }

  /**
   * Constructs an {@link SSKBlock} from raw payload and header bytes.
   *
   * <p>This method parses {@code fullKey} into a {@link NodeSSK}, attaches a known public key when
   * supplied, or looks up the key via {@link #pubkeyCache} if missing. It then creates an {@link
   * SSKBlock} that verifies signatures and header bindings unless the block implementation decides
   * otherwise. The {@code routingKey} argument is not required by this implementation but is part
   * of the generic callback contract.
   *
   * <p>Preconditions:
   *
   * <ul>
   *   <li>{@code data.length == } {@link SSKBlock#DATA_LENGTH}
   *   <li>{@code headers.length == } {@link SSKBlock#TOTAL_HEADERS_LENGTH}
   *   <li>{@code fullKey.length == } {@link NodeSSK#FULL_KEY_LENGTH}
   * </ul>
   *
   * @param payload payload bytes, headers, and key material for the block.
   * @param options cache flags and metadata used for public-key lookup.
   * @param knownPublicKey optional known public key to attach to the {@link NodeSSK}.
   * @return a verified {@link SSKBlock} instance.
   * @throws SSKVerifyException if any input is missing or invalid, if the public key cannot be
   *     located, or if the reconstructed block fails verification.
   */
  @Override
  public SSKBlock construct(
      BlockPayload payload, ConstructOptions options, DSAPublicKey knownPublicKey)
      throws SSKVerifyException {
    if (payload.data() == null || payload.headers() == null)
      throw new SSKVerifyException("Need data and headers");
    if (payload.fullKey() == null)
      throw new SSKVerifyException("Need full key to reconstruct an SSK");
    NodeSSK key;
    key = NodeSSK.construct(payload.fullKey());
    if (knownPublicKey != null) key.setPubKey(knownPublicKey);
    else if (!key.grabPubkey(
        pubkeyCache, options.canReadClientCache(), options.canReadSlashdotCache(), options.meta()))
      throw new SSKVerifyException("No pubkey found");
    return new SSKBlock(payload.data(), payload.headers(), key, false);
  }

  /**
   * Fetches an SSK block from the underlying store.
   *
   * <p>Delegates to {@link FreenetStore#fetch(byte[], byte[], boolean, boolean, boolean, boolean,
   * BlockMetadata)}, passing the routing and full keys derived from {@code chk}.
   *
   * @param chk locating key whose routing and full keys are used for the lookup.
   * @param dontPromote if {@code true}, does not promote the block in the store's eviction policy.
   * @param canReadClientCache whether client cache reads are allowed when resolving the public key.
   * @param canReadSlashdotCache forwarded as the {@code forULPR} hint to public-key resolution.
   * @param ignoreOldBlocks whether the store may ignore blocks marked as old.
   * @param meta metadata instance populated by the store during retrieval.
   * @return the block or {@code null} if not found.
   * @throws IOException on I/O failure in the underlying store.
   */
  public SSKBlock fetch(
      NodeSSK chk,
      boolean dontPromote,
      boolean canReadClientCache,
      boolean canReadSlashdotCache,
      boolean ignoreOldBlocks,
      BlockMetadata meta)
      throws IOException {
    return store.fetch(
        chk.getRoutingKey(),
        chk.getFullKey(),
        dontPromote,
        canReadClientCache,
        canReadSlashdotCache,
        ignoreOldBlocks,
        meta);
  }

  /**
   * Stores an SSK block in the underlying store.
   *
   * <p>Delegates to {@link FreenetStore#put(StorableBlock, byte[], byte[], boolean, boolean)} with
   * the raw arrays obtained from the block. When {@code overwrite} is {@code false} and the key is
   * already present with different content, the store may throw a {@link KeyCollisionException}.
   *
   * @param b block to store.
   * @param overwrite whether to overwrite existing content on key collision.
   * @param isOldBlock whether the block should be marked as old for Bloom propagation purposes.
   * @throws IOException on I/O failure in the underlying store.
   * @throws KeyCollisionException if a different block already exists and {@code overwrite} is
   *     {@code false}.
   */
  public void put(SSKBlock b, boolean overwrite, boolean isOldBlock)
      throws IOException, KeyCollisionException {
    store.put(b, b.getRawData(), b.getRawHeaders(), overwrite, isOldBlock);
  }

  /** Returns the fixed payload size in bytes for SSK blocks. */
  @Override
  public int dataLength() {
    return SSKBlock.DATA_LENGTH;
  }

  /** Returns the fixed full-key size in bytes for SSK identifiers. */
  @Override
  public int fullKeyLength() {
    return NodeSSK.FULL_KEY_LENGTH;
  }

  /** Returns the fixed header size in bytes for SSK blocks. */
  @Override
  public int headerLength() {
    return SSKBlock.TOTAL_HEADERS_LENGTH;
  }

  /** Returns the fixed routing-key size in bytes for SSK identifiers. */
  @Override
  public int routingKeyLength() {
    return NodeSSK.ROUTING_KEY_LENGTH;
  }

  /** Indicates that the store persists full keys for SSKs (sidecar {@code .keys} file). */
  @Override
  public boolean storeFullKeys() {
    return true;
  }

  /** Reports that distinct SSK blocks can collide on a key (signature differences, etc.). */
  @Override
  public boolean collisionPossible() {
    return true;
  }

  /** States that this constructor requires key material (the full SSK) to rebuild a block. */
  @Override
  public boolean constructNeedsKey() {
    return true;
  }

  /** Computes a routing key from a serialized full SSK buffer. */
  @Override
  public byte[] routingKeyFromFullKey(byte[] keyBuf) {
    return NodeSSK.routingKeyFromFullKey(keyBuf);
  }
}
