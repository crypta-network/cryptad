package network.crypta.client.async;

import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.node.LowLevelGetException;
import network.crypta.node.SendableGet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Listener implementation optimized for tracking a single target key.
 *
 * <p>{@code SingleKeyListener} is a small, allocation-light {@link KeyListener} that answers
 * screening queries for exactly one node-level {@link network.crypta.keys.Key}. It is created by a
 * {@link BaseSingleFileFetcher} to watch the fetch pipeline for its single block and to forward the
 * first matching {@link network.crypta.keys.KeyBlock} to the owner. The class avoids storing large
 * state and keeps its fast paths branch-free where possible so callers may invoke it inside
 * scheduler hot paths. Once a match is processed or the owner is removed, the listener marks itself
 * as done and becomes effectively inert.
 *
 * <p>Usage and lifecycle:
 *
 * <ul>
 *   <li>Constructed internally by {@link BaseSingleFileFetcher#makeKeyListener(ClientContext,
 *       boolean)}; not intended for general reuse.
 *   <li>{@link #probablyWantKey(network.crypta.keys.Key, byte[])} quickly rejects non-matching
 *       keys; {@link #definitelyWantKey(network.crypta.keys.Key, byte[], ClientContext)} returns
 *       the owner’s priority for the single matching key.
 *   <li>{@link #handleBlock(network.crypta.keys.Key, byte[], network.crypta.keys.KeyBlock,
 *       ClientContext)} delivers the block to the owner and then finalizes the listener.
 * </ul>
 *
 * <p>Thread-safety: instances are not generally thread-safe beyond a narrow synchronized section
 * that flips the internal {@code done} flag. Callers should avoid blocking the listener on external
 * locks. Mutability is limited to completion bookkeeping; the target key and priority are immutable
 * after construction.
 *
 * @see BaseSingleFileFetcher
 * @see HasKeyListener
 * @see KeyListener
 */
public class SingleKeyListener implements KeyListener {
  private static final Logger LOG = LoggerFactory.getLogger(SingleKeyListener.class);

  private final Key key;
  private final BaseSingleFileFetcher fetcher;
  private boolean done;
  private final short prio;
  private final boolean persistent;

  /**
   * Creates a listener bound to a single node-level key.
   *
   * <p>The listener answers interest checks for {@code key} and passes any matching block to {@code
   * fetcher}. The instance becomes inactive after a successful hand-off or explicit removal.
   *
   * @param key node-level key to watch for; must be non-null and stable for the listener lifetime
   * @param fetcher owning single-file fetcher that will receive matching blocks and error callbacks
   * @param prio priority class to report when the key matches; used by schedulers to order work
   * @param persistent whether the owning fetch is persistent across restarts; affects scheduling
   */
  public SingleKeyListener(Key key, BaseSingleFileFetcher fetcher, short prio, boolean persistent) {
    this.key = key;
    this.fetcher = fetcher;
    this.prio = prio;
    this.persistent = persistent;
  }

  /** {@inheritDoc} */
  @Override
  public long countKeys() {
    if (done) return 0;
    else return 1;
  }

  /** {@inheritDoc} */
  @Override
  public short definitelyWantKey(Key key, byte[] saltedKey, ClientContext context) {
    if (!key.equals(this.key)) return -1;
    else return prio;
  }

  /** {@inheritDoc} */
  @Override
  public HasKeyListener getHasKeyListener() {
    return fetcher;
  }

  /** {@inheritDoc} */
  @Override
  public short getPriorityClass() {
    return prio;
  }

  /** {@inheritDoc} */
  @Override
  @SuppressWarnings("java:S1168")
  public SendableGet[] getRequestsForKey(Key key, byte[] saltedKey, ClientContext context) {
    if (!key.equals(this.key)) return null;
    return new SendableGet[] {fetcher};
  }

  /** {@inheritDoc} */
  @Override
  @SuppressWarnings("java:S1181")
  public boolean handleBlock(Key key, byte[] saltedKey, KeyBlock found, ClientContext context) {
    if (!key.equals(this.key)) return false;
    try {
      fetcher.onGotKey(key, found, context);
    } catch (Throwable t) {
      LOG.error("Failed: {}", t, t);
      fetcher.onFailure(
          new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR, t), null, context);
    }
    synchronized (this) {
      done = true;
    }
    return true;
  }

  /** {@inheritDoc} */
  @Override
  public boolean persistent() {
    return persistent;
  }

  /** {@inheritDoc} */
  @Override
  public boolean probablyWantKey(Key key, byte[] saltedKey) {
    if (done) return false;
    return key.equals(this.key);
  }

  /** {@inheritDoc} */
  @Override
  public synchronized void onRemove() {
    done = true;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isEmpty() {
    return done;
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSSK() {
    return key instanceof NodeSSK;
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getWantedKey() {
    return key instanceof NodeSSK nssk ? nssk.getPubKeyHash() : key.getRoutingKey();
  }
}
