package network.crypta.store;

import com.onionnetworks.util.Util;
import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Minimal {@link GetPubkey} implementation backed by a single {@link PubkeyStore}.
 *
 * <p>This facade deliberately ignores all read/write hint flags exposed by the interface. Reads are
 * performed via one direct lookup and writes via one direct put using conservative options. Any
 * {@link IOException} raised by the backing store is logged and suppressed; callers receive {@code
 * null} on read failures and silent no-ops on writing failures.
 *
 * <p>Thread-safety: The instance holds only a reference to the provided store and does not keep any
 * mutable state. Concurrency characteristics therefore depend entirely on the {@link PubkeyStore}
 * implementation supplied at construction time.
 */
public class SimpleGetPubkey implements GetPubkey<DSAPublicKey> {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleGetPubkey.class);

  // Backing store used for all lookups and writes.
  final PubkeyStore store;

  /**
   * Creates a new facade over the given pubkey store.
   *
   * @param store backing store; must not be {@code null}.
   */
  public SimpleGetPubkey(PubkeyStore store) {
    this.store = store;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Implementation notes:
   *
   * <ul>
   *   <li>All hint flags are ignored; the method always delegates to {@link
   *       PubkeyStore#fetch(byte[], boolean, boolean, BlockMetadata)} with {@code
   *       dontPromote=false} and {@code ignoreOldBlocks=false}.
   *   <li>On {@link IOException}, an error is logged and {@code null} is returned.
   * </ul>
   *
   * @param hash hash of the public key. The typical size is {@link
   *     network.crypta.crypt.DSAPublicKey#HASH_LENGTH} bytes.
   * @param canReadClientCache ignored by this implementation.
   * @param forULPR ignored by this implementation.
   * @param meta optional metadata container passed through to the store; may be {@code null}.
   * @return the fetched key, or {@code null} if not present or when a read error occurs.
   */
  @Override
  public DSAPublicKey getKey(
      byte[] hash, boolean canReadClientCache, boolean forULPR, BlockMetadata meta) {
    try {
      return store.fetch(hash, false, false, meta);
    } catch (IOException e) {
      LOG.error("Caught {} fetching pubkey for {}", e, Util.bytesToHex(hash));
      return null;
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>Implementation notes:
   *
   * <ul>
   *   <li>All write-control flags are ignored; the method always delegates to {@link
   *       PubkeyStore#put(DSAPublicKey, boolean)} with {@code isOldBlock=false}.
   *   <li>On {@link IOException}, an error is logged and the exception is suppressed.
   * </ul>
   *
   * @param hash hash identifying the public key to cache.
   * @param key key material to store.
   * @param deep ignored by this implementation.
   * @param canWriteClientCache ignored by this implementation.
   * @param canWriteDatastore ignored by this implementation.
   * @param forULPR ignored by this implementation.
   * @param writeLocalToDatastore ignored by this implementation.
   */
  @Override
  public void cacheKey(
      byte[] hash,
      DSAPublicKey key,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      boolean writeLocalToDatastore) {
    try {
      store.put(key, false);
    } catch (IOException e) {
      LOG.error("Caught {} storing pubkey for {}", e, Util.bytesToHex(hash));
    }
  }
}
