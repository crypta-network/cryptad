package network.crypta.client.async;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.node.SendableGet;
import network.crypta.support.ByteArrayWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks listeners interested in specific keys and coordinates notification when data becomes
 * available. Tracking is intentionally decoupled from the act of scheduling and issuing network
 * requests so that locally observed traffic (e.g., neighbor requests, inserts routed through this
 * node, or late ULPR announcements) can satisfy pending interest. This still works even if this
 * scheduler did not originate a fetch for the same key.
 *
 * <p>Typical usage is:
 *
 * <ol>
 *   <li>Register a {@code KeyListener} via {@link #addPendingKeys(KeyListener)}. A listener may
 *       target a single salted key or a set of keys, depending on the implementation.
 *   <li>As blocks are received or discovered, call {@link #tripPendingKey(Key, KeyBlock,
 *       ClientContext)}. Matching listeners are asked to handle the block and may remove themselves
 *       once complete.
 *   <li>Use {@link #getKeyPrio(Key, short, ClientContext)} to adjust priorities for keys that are
 *       definitely wanted by registered listeners.
 * </ol>
 *
 * <p>Instances are created per scheduler flavor (insert/CHK/SSK/real-time) and are not persisted.
 * On startup, they are rebuilt and active downloads re-register their listeners. This class is not
 * thread-safe by default; methods that mutate internal collections either synchronize on {@code
 * this} or constrain access patterns to avoid concurrent modification.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>SSK schedulers do not salt keys; CHK schedulers salt with a per-instance random salt.
 *   <li>Retry counts are normalized by {@link #fixRetryCount(int)} so lightly tried requests do not
 *       starve other clients.
 *   <li>Listeners can be registered for a single key or as a catch-all; both sources are consulted
 *       when checking interest or dispatching blocks.
 * </ul>
 *
 * @see ClientRequestScheduler
 */
class KeyListenerTracker implements KeySalter {
  private static final Logger LOG = LoggerFactory.getLogger(KeyListenerTracker.class);

  // No static initialization required

  /**
   * Minimum number of retries after which additional retries start to affect priority decisions.
   * Below this threshold, requests are treated as if they have zero retries for scheduling
   * purposes. This avoids large batches of lightly tried requests starving other clients while
   * still allowing genuinely hard-to-fetch keys to gain precedence once they have been tried
   * several times.
   */
  private static final int MIN_RETRY_COUNT = 3;

  /**
   * Indicates that this tracker is associated with an insert scheduler, where insert-related events
   * may influence interest tracking. This flag is immutable for the lifetime of the instance and
   * primarily affects {@link #toString()} diagnostics.
   */
  final boolean isInsertScheduler;

  /**
   * True when this tracker is bound to an SSK scheduler. When set, keys are not salted (SSK uses
   * the raw routing/public key material). When false, CHK routing keys are salted to reduce
   * cross-scheduler interference.
   */
  final boolean isSSKScheduler;

  /**
   * True for real-time scheduling mode. Real-time schedulers may prioritize differently at higher
   * layers; the tracker itself uses the flag only for identification and logging.
   */
  final boolean isRTScheduler;

  /**
   * The owning scheduler that decides when and how requests are executed. The tracker does not
   * issue requests directly; instead, it exposes listener interest and potential requests that the
   * scheduler can query.
   */
  protected final ClientRequestScheduler sched;

  /**
   * Transient even for a persistent scheduler. There is one for each of the transients, persistent.
   */
  protected final ArrayList<KeyListener> keyListeners;

  /**
   * Map of a salted key to either a single {@code KeyListener} or an array of listeners. Lookups
   * are by salted key; for SSK schedulers no salting occurs. Values are intentionally stored as
   * either a single instance or an array to minimize allocation when only one listener exists.
   */
  protected final Map<ByteArrayWrapper, Object> singleKeyListeners;

  /**
   * Whether this tracker belongs to the persistent scheduler. The tracker itself is not serialized;
   * this flag communicates the intended lifecycle to callers and is exposed via {@link
   * #persistent()}.
   */
  final boolean persistent;

  /**
   * Returns whether the owning scheduler is persistent. This does not imply that the tracker or its
   * internal state is serialized; tracker instances are recreated on startup, and callers are
   * expected to re-register their listeners.
   *
   * @return {@code true} when associated with the persistent scheduler, {@code false} otherwise.
   */
  public boolean persistent() {
    return persistent;
  }

  /**
   * Creates a tracker bound to a specific scheduler flavor.
   *
   * <p>When {@code forSSKs} is {@code false}, a 32-byte per-instance salt is used to salt CHK
   * routing keys. If {@code globalSalt} is {@code null}, a new random salt is generated using the
   * provided {@code random} source. The salt remains constant for the lifetime of this instance.
   *
   * @param forInserts {@code true} when attached to an insert scheduler; affects diagnostics only.
   * @param forSSKs {@code true} for SSK schedulers; disables key salting and expects SSK keys.
   * @param forRT {@code true} for real-time mode; used for identification and logging.
   * @param random source of randomness for generating a salt when {@code globalSalt} is {@code
   *     null}. Must be non-{@code null} when {@code globalSalt} is {@code null}.
   * @param sched owning {@link ClientRequestScheduler} that queries interest and potential
   *     requests. Must not be {@code null}.
   * @param globalSalt optional 32-byte salt used for CHK key salting; when {@code null}, a new salt
   *     is generated.
   * @param persistent whether this tracker is associated with the persistent scheduler (see {@link
   *     #persistent()}).
   */
  protected KeyListenerTracker(
      boolean forInserts,
      boolean forSSKs,
      boolean forRT,
      RandomSource random,
      ClientRequestScheduler sched,
      byte[] globalSalt,
      boolean persistent) {
    this.isInsertScheduler = forInserts;
    this.isSSKScheduler = forSSKs;
    this.isRTScheduler = forRT;
    this.sched = sched;
    keyListeners = new ArrayList<>();
    singleKeyListeners =
        this.isSSKScheduler ? new TreeMap<>(ByteArrayWrapper.FAST_COMPARATOR) : new HashMap<>();
    if (globalSalt == null) {
      globalSalt = new byte[32];
      random.nextBytes(globalSalt);
    }
    this.globalSalt = globalSalt;
    this.persistent = persistent;
  }

  /**
   * Normalizes a raw retry count for scheduling comparisons.
   *
   * <p>Counts below {@link #MIN_RETRY_COUNT} are treated as zero so that recently started or
   * lightly retried requests do not dominate scheduling decisions. Only once a request has reached
   * the threshold, do additional retries make it more urgent relative to other clients' work.
   *
   * @param retryCount the raw number of attempts already made; negative values are treated as zero.
   * @return a non-negative normalized count suitable for comparing request urgency.
   */
  protected static int fixRetryCount(int retryCount) {
    return Math.max(0, retryCount - MIN_RETRY_COUNT);
  }

  private boolean contains(KeyListener[] listeners, KeyListener listener) {
    for (KeyListener l : listeners) {
      if (l == listener) return true;
    }
    return false;
  }

  /**
   * Registers a listener as interested in one or more keys.
   *
   * <p>If the listener targets a single key, it is stored under that key's salted form (for CHK) or
   * raw form (for SSK). Otherwise, it is added to the general list. Duplicate registrations are
   * ignored.
   *
   * @param listener the listener to register; must not be {@code null}. Its owner must report a
   *     consistent wanted key if a single-key listener.
   */
  public void addPendingKeys(KeyListener listener) {
    if (listener == null) throw new NullPointerException();
    byte[] wantedKey = listener.getWantedKey();
    ByteArrayWrapper wrapper = wantedKey != null ? new ByteArrayWrapper(saltKey(wantedKey)) : null;
    // Ensure the KeyListener's owner reports the same wanted key if present
    if (wantedKey != null
        && !Arrays.equals(wantedKey, listener.getHasKeyListener().getWantedKey())) {
      throw new IllegalStateException("Listener wantedKey mismatch with owner");
    }
    registerListener(wantedKey, wrapper, listener);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Registered pending keys on {} : size now {}/{} : {}",
          this,
          this.keyListeners.size(),
          singleKeyListeners.size(),
          listener);
  }

  /**
   * Removes a previously registered listener.
   *
   * <p>Both single-key and general listeners are supported. This method invokes {@code onRemove()}
   * on the listener to allow cleanup. The method is idempotent; removing a listener that is not
   * present returns {@code false}.
   *
   * @param listener the listener to remove; must not be {@code null}.
   * @return {@code true} if a registration was removed, {@code false} if no matching registration
   *     existed.
   */
  public boolean removePendingKeys(KeyListener listener) {
    boolean ret;
    byte[] wantedKey = listener.getWantedKey();
    ByteArrayWrapper wrapper = wantedKey != null ? new ByteArrayWrapper(saltKey(wantedKey)) : null;
    synchronized (this) {
      ret =
          (wantedKey != null) ? removeSingleListener(wrapper, listener) : removeFromList(listener);
      // Intentionally call onRemove() once here and once below, matching existing behavior.
      listener.onRemove();
    }
    listener.onRemove();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Removed listener pending keys from {} : size now {}/{} : {}",
          this,
          this.keyListeners.size(),
          singleKeyListeners.size(),
          listener);
    return ret;
  }

  /**
   * Removes all registrations owned by a given listener owner.
   *
   * <p>This scans both the single-key map and the general list, removing any listeners whose owner
   * matches the supplied instance. For each removed listener, {@code onRemove()} is invoked.
   *
   * @param hasListener the owner whose listeners should be removed.
   * @return {@code true} if at least one listener was removed; {@code false} otherwise.
   */
  public boolean removePendingKeys(HasKeyListener hasListener) {
    boolean ret;
    byte[] wantedKey = hasListener.getWantedKey();
    ByteArrayWrapper wrapper = wantedKey != null ? new ByteArrayWrapper(saltKey(wantedKey)) : null;
    synchronized (this) {
      if (wantedKey != null) {
        ret = removeSingleByOwner(hasListener, wrapper);
        return ret;
      }
      ret = removeListByOwner(hasListener);
    }
    return ret;
  }

  private ArrayList<KeyListener> probablyMatches(Key key, byte[] saltedKey) {
    final ByteArrayWrapper wrapper = new ByteArrayWrapper(saltedKey);
    synchronized (this) {
      Object singleMatch = singleKeyListeners.get(wrapper);
      ArrayList<KeyListener> matches = appendSingleMatches(singleMatch, key, saltedKey);
      if (keyListeners.isEmpty()) return matches;
      List<KeyListener> listMatches = new ArrayList<>(keyListeners);
      return appendListMatches(matches, listMatches, key, saltedKey);
    }
  }

  /**
   * Computes an adjusted priority for a key based on registered interest.
   *
   * <p>If the key type does not match this scheduler (e.g., CHK on an SSK scheduler), the supplied
   * priority is returned unchanged. Otherwise, listeners that definitely want the key may lower the
   * priority (numerically) to signal higher urgency.
   *
   * @param key the key being considered; must be of the correct type for this scheduler.
   * @param priority the current priority; smaller values represent higher priority.
   * @param context request context supplied to listeners when evaluating interest.
   * @return the possibly reduced priority reflecting definite listener interest.
   */
  public short getKeyPrio(Key key, short priority, ClientContext context) {
    if ((key instanceof NodeSSK) != isSSKScheduler) {
      return priority;
    }
    byte[] saltedKey = saltKey(key);
    ArrayList<KeyListener> matches = probablyMatches(key, saltedKey);
    if (matches == null) return priority;
    for (KeyListener listener : matches) {
      short prio;
      try {
        prio = listener.definitelyWantKey(key, saltedKey, context);
      } catch (Exception t) {
        LOG.error("Error in definitelyWantKey callback during getKeyPrio for {}", listener, t);
        prio = -1;
      }
      if (prio != -1 && prio < priority) priority = prio;
    }
    return priority;
  }

  /**
   * Counts the total number of pending keys across all registered listeners.
   *
   * <p>Both single-key and general listeners are included. Exceptions thrown by individual
   * listeners are logged and ignored.
   *
   * @return the sum of {@code countKeys()} across all listeners; never negative.
   */
  public long countWaitingKeys() {
    List<Object> singleSnapshot;
    List<KeyListener> listSnapshot;
    synchronized (this) {
      if (singleKeyListeners.isEmpty() && keyListeners.isEmpty()) return 0;
      singleSnapshot = new ArrayList<>(singleKeyListeners.values());
      listSnapshot =
          keyListeners.isEmpty() ? Collections.emptyList() : new ArrayList<>(keyListeners);
    }
    long count = 0;
    for (Object o : singleSnapshot) {
      if (o instanceof KeyListener listener1) {
        count += listener1.countKeys();
      } else if (o instanceof KeyListener[] listeners) {
        for (KeyListener listener : listeners) count += listener.countKeys();
      }
    }
    for (KeyListener listener : listSnapshot) {
      try {
        count += listener.countKeys();
      } catch (Exception t) {
        LOG.error("Error in countKeys callback during countWaitingKeys for {}", listener, t);
      }
    }
    return count;
  }

  /**
   * Returns whether any listener definitely wants the specified key.
   *
   * <p>If the key type does not match this scheduler, {@code false} is returned. Otherwise, all
   * probable matches are asked whether they definitely want the key using their context-aware
   * heuristic; a non-negative response indicates interest.
   *
   * @param key the key to test; must match the scheduler's key type.
   * @param context execution context supplied to listeners.
   * @return {@code true} if at least one listener definitely wants the key; {@code false}
   *     otherwise.
   */
  public boolean anyWantKey(Key key, ClientContext context) {
    if ((key instanceof NodeSSK) != isSSKScheduler) {
      return false;
    }
    byte[] saltedKey = saltKey(key);
    List<KeyListener> matches = probablyWantKey(key, saltedKey);
    if (!matches.isEmpty()) {
      for (KeyListener listener : matches) {
        try {
          if (listener.definitelyWantKey(key, saltedKey, context) >= 0) {
            return true;
          }
        } catch (Exception t) {
          LOG.error("Error in definitelyWantKey callback during anyWantKey for {}", listener, t);
        }
      }
    }
    return false;
  }

  /**
   * Returns whether any listener probably wants the specified key.
   *
   * <p>This performs a faster check that does not ask listeners to provide a definitive priority.
   * It is useful as a preliminary filter before more expensive evaluation.
   *
   * @param key the key to test; must match the scheduler's key type.
   * @param context execution context used for validation only; must not be {@code null}.
   * @return {@code true} if any listener indicates probable interest; {@code false} otherwise.
   */
  public boolean anyProbablyWantKey(Key key, ClientContext context) {
    java.util.Objects.requireNonNull(context, "context");
    if ((key instanceof NodeSSK) != isSSKScheduler) {
      return false;
    }
    byte[] saltedKey = saltKey(key);
    final ByteArrayWrapper wrapper = new ByteArrayWrapper(saltedKey);
    synchronized (this) {
      Object singleMatch = singleKeyListeners.get(wrapper);
      if (anySingleProbablyWant(singleMatch, key, saltedKey)) return true;
      if (keyListeners.isEmpty()) return false;
      List<KeyListener> listMatches = new ArrayList<>(keyListeners);
      return anyListProbablyWant(listMatches, key, saltedKey);
    }
  }

  /**
   * Notifies matching listeners that a block for {@code key} is available.
   *
   * <p>If the key type does not match this scheduler, the call is ignored and {@code false} is
   * returned. Otherwise, matching listeners are invoked. Listeners that become empty after handling
   * the block are removed.
   *
   * @param key the key for which a block is available; must match the scheduler's key type.
   * @param block the block data associated with the key.
   * @param context request context propagated to listeners.
   * @return {@code true} if any listener handled the block successfully; {@code false} otherwise.
   */
  public boolean tripPendingKey(Key key, KeyBlock block, ClientContext context) {
    if ((key instanceof NodeSSK) != isSSKScheduler) {
      LOG.warn("Key {} on scheduler ssk={}", key, isSSKScheduler);
      return false;
    }
    byte[] saltedKey = saltKey(key);
    ArrayList<KeyListener> matches = probablyMatches(key, saltedKey);
    boolean ret = false;
    if (matches != null) ret = processTripMatches(key, saltedKey, block, context, matches);
    return ret;
  }

  /**
   * Returns any concrete {@link SendableGet} requests that should be issued for the given key.
   *
   * <p>If the key type does not match this scheduler or no listener proposes requests, {@code null}
   * is returned. Otherwise, the returned array contains one or more requests collected from
   * matching listeners. The array is a snapshot; callers should not modify it.
   *
   * @param key the key to request.
   * @param context request context supplied to listeners.
   * @return an array of requests to issue, or {@code null} if none were proposed.
   */
  @SuppressWarnings("java:S1168")
  public SendableGet[] requestsForKey(Key key, ClientContext context) {
    ArrayList<SendableGet> list = new ArrayList<>();
    if ((key instanceof NodeSSK) != isSSKScheduler) {
      return null;
    }
    byte[] saltedKey = saltKey(key);
    List<KeyListener> matches = probablyWantKey(key, saltedKey);
    for (KeyListener listener : matches) {
      SendableGet[] reqs = null;
      try {
        reqs = listener.getRequestsForKey(key, saltedKey, context);
      } catch (Exception t) {
        LOG.error("Error in getRequestsForKey callback during requestsForKey for {}", listener, t);
      }
      if (reqs != null) {
        Collections.addAll(list, reqs);
      }
    }
    if (list.isEmpty()) {
      return null;
    }
    return list.toArray(new SendableGet[0]);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(super.toString());
    sb.append(':');
    if (isInsertScheduler) sb.append("insert:");
    if (isSSKScheduler) sb.append("SSK");
    else sb.append("CHK");
    return sb.toString();
  }

  private final byte[] globalSalt;

  /**
   * Returns the salted routing key used for listener maps.
   *
   * <p>For SSK schedulers the original key material is returned unchanged. For CHK schedulers a
   * per-instance salt is mixed with the routing key via {@link SHA256}.
   *
   * @param key the key whose routing bytes should be salted as appropriate for the scheduler.
   * @return a byte array containing the salted or raw routing key; never {@code null}.
   */
  public byte[] saltKey(Key key) {
    return saltKey(key instanceof NodeSSK nssk ? nssk.getPubKeyHash() : key.getRoutingKey());
  }

  private byte[] saltKey(byte[] key) {
    if (isSSKScheduler) return key;
    MessageDigest md = SHA256.getMessageDigest();
    md.update(key);
    md.update(globalSalt);
    return md.digest();
  }

  /** Returns all KeyListeners that return true on probablyWantKey(key, saltedKey) */
  private List<KeyListener> probablyWantKey(Key key, byte[] saltedKey) {
    ArrayList<KeyListener> matches = null;
    synchronized (this) {
      if (keyListeners.isEmpty()) return Collections.emptyList();
      List<KeyListener> listSnapshot = new ArrayList<>(keyListeners);
      for (KeyListener listener : listSnapshot) {
        try {
          if (listener.probablyWantKey(key, saltedKey)) {
            if (matches == null) matches = new ArrayList<>();
            matches.add(listener);
          }
        } catch (Exception t) {
          LOG.error(
              "Error in probablyWantKey callback during probablyWantKey scan for {}", listener, t);
        }
      }
    }
    return matches == null ? Collections.emptyList() : matches;
  }

  private void registerListener(byte[] wantedKey, ByteArrayWrapper wrapper, KeyListener listener) {
    synchronized (this) {
      // We have to register before checking the disk, so it may well get registered twice.
      if (wantedKey != null) {
        Object o = singleKeyListeners.get(wrapper);
        if (o == null) {
          singleKeyListeners.put(wrapper, listener);
        } else if (o instanceof KeyListener keyListener) {
          if (listener == o) return;
          singleKeyListeners.put(wrapper, new KeyListener[] {keyListener, listener});
        } else {
          KeyListener[] listeners = (KeyListener[]) o;
          if (contains(listeners, listener)) return;
          KeyListener[] newListeners = Arrays.copyOf(listeners, listeners.length + 1);
          newListeners[listeners.length] = listener;
          singleKeyListeners.put(wrapper, newListeners);
        }
      } else {
        if (keyListeners.contains(listener)) return;
        keyListeners.add(listener);
      }
    }
  }

  private boolean removeSingleListener(ByteArrayWrapper wrapper, KeyListener listener) {
    Object o = singleKeyListeners.get(wrapper);
    if (o == null) return false;
    boolean ret;
    if (o instanceof KeyListener) {
      ret = (listener == o);
      if (ret) singleKeyListeners.remove(wrapper);
      return ret;
    }
    KeyListener[] listeners = (KeyListener[]) o;
    return removeFromArrayMapping(listeners, wrapper, listener);
  }

  private boolean removeFromList(KeyListener listener) {
    return keyListeners.remove(listener);
  }

  private boolean removeSingleByOwner(HasKeyListener hasListener, ByteArrayWrapper wrapper) {
    boolean ret;
    Object o = singleKeyListeners.get(wrapper);
    if (o == null) return false;
    if (o instanceof KeyListener listener) {
      ret = (listener.getHasKeyListener() == hasListener);
      if (ret) {
        singleKeyListeners.remove(wrapper);
        listener.onRemove();
      }
      return ret;
    }
    KeyListener[] listeners = (KeyListener[]) o;
    return removeFromArrayByOwner(listeners, wrapper, hasListener);
  }

  private boolean removeListByOwner(HasKeyListener hasListener) {
    boolean ret = false;
    for (Iterator<KeyListener> i = keyListeners.iterator(); i.hasNext(); ) {
      KeyListener listener = i.next();
      if (listener.getHasKeyListener() == hasListener) {
        ret = true;
        i.remove();
        listener.onRemove();
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Removed owner pending keys from {} : size now {}/{} : {}",
              this,
              this.keyListeners.size(),
              singleKeyListeners.size(),
              listener);
      }
    }
    return ret;
  }

  private ArrayList<KeyListener> appendSingleMatches(
      Object singleMatch, Key key, byte[] saltedKey) {
    ArrayList<KeyListener> matches = null;
    if (singleMatch instanceof KeyListener single) {
      matches = appendMatchIfSingle(single, key, saltedKey);
    } else if (singleMatch instanceof KeyListener[] listeners) {
      matches = appendMatchesIfArray(listeners, key, saltedKey);
    }
    return matches;
  }

  private ArrayList<KeyListener> appendListMatches(
      ArrayList<KeyListener> matches, List<KeyListener> listMatches, Key key, byte[] saltedKey) {
    for (KeyListener listener : listMatches) {
      if (listener.probablyWantKey(key, saltedKey)) {
        if (matches == null) matches = new ArrayList<>();
        matches.add(listener);
      }
    }
    return matches;
  }

  private ArrayList<KeyListener> appendMatchIfSingle(
      KeyListener listener, Key key, byte[] saltedKey) {
    ArrayList<KeyListener> matches = null;
    if (listener.probablyWantKey(key, saltedKey)) {
      matches = new ArrayList<>();
      matches.add(listener);
    }
    return matches;
  }

  private ArrayList<KeyListener> appendMatchesIfArray(
      KeyListener[] listeners, Key key, byte[] saltedKey) {
    ArrayList<KeyListener> matches = null;
    for (KeyListener listener : listeners) {
      if (listener.probablyWantKey(key, saltedKey)) {
        if (matches == null) matches = new ArrayList<>();
        matches.add(listener);
      }
    }
    return matches;
  }

  private boolean removeFromArrayMapping(
      KeyListener[] listeners, ByteArrayWrapper wrapper, KeyListener toRemove) {
    boolean ret = false;
    KeyListener[] newListeners = new KeyListener[listeners.length - 1];
    int x = 0;
    for (KeyListener l : listeners) {
      if (!ret && toRemove == l) {
        ret = true;
        continue;
      }
      if (x < newListeners.length) newListeners[x++] = l;
    }
    if (ret) {
      if (x < newListeners.length) newListeners = Arrays.copyOf(newListeners, x);
      if (newListeners.length == 0) {
        singleKeyListeners.remove(wrapper);
      } else if (newListeners.length == 1) {
        singleKeyListeners.put(wrapper, newListeners[0]);
      } else {
        singleKeyListeners.put(wrapper, newListeners);
      }
    }
    return ret;
  }

  private boolean removeFromArrayByOwner(
      KeyListener[] listeners, ByteArrayWrapper wrapper, HasKeyListener owner) {
    RemovalAccum accum = scanRemovalByOwner(listeners, owner);
    if (accum.removed) finalizeOwnerRemoval(wrapper, accum.newListeners, accum.count, accum.msg);
    return accum.removed;
  }

  private void finalizeOwnerRemoval(
      ByteArrayWrapper wrapper, KeyListener[] newListeners, int x, String msg) {
    if (x < newListeners.length) newListeners = Arrays.copyOf(newListeners, x);
    if (newListeners.length == 0) {
      singleKeyListeners.remove(wrapper);
    } else if (newListeners.length == 1) {
      singleKeyListeners.put(wrapper, newListeners[0]);
    } else {
      singleKeyListeners.put(wrapper, newListeners);
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Removed owner pending keys (array cleanup) from {} : size now {}/{}{}",
          this,
          this.keyListeners.size(),
          singleKeyListeners.size(),
          msg);
  }

  private static final class RemovalAccum {
    boolean removed;
    KeyListener[] newListeners;
    int count;
    String msg;

    RemovalAccum(int size) {
      this.newListeners = new KeyListener[size];
      this.count = 0;
      this.removed = false;
      this.msg = null;
    }
  }

  private RemovalAccum scanRemovalByOwner(KeyListener[] listeners, HasKeyListener owner) {
    RemovalAccum accum = new RemovalAccum(listeners.length - 1);
    if (LOG.isDebugEnabled()) accum.msg = "";
    for (KeyListener l : listeners) {
      if (l.getHasKeyListener() == owner) {
        accum.removed = true;
        l.onRemove();
        if (LOG.isDebugEnabled()) accum.msg = "%s : %s".formatted(accum.msg, l);
      } else if (accum.count < accum.newListeners.length) {
        accum.newListeners[accum.count++] = l;
      }
    }
    return accum;
  }

  private boolean anySingleProbablyWant(Object singleMatch, Key key, byte[] saltedKey) {
    if (singleMatch instanceof KeyListener listener) {
      return listener.probablyWantKey(key, saltedKey);
    }
    if (singleMatch instanceof KeyListener[] listeners) {
      for (KeyListener listener : listeners) {
        if (listener.probablyWantKey(key, saltedKey)) return true;
      }
    }
    return false;
  }

  private boolean anyListProbablyWant(List<KeyListener> listMatches, Key key, byte[] saltedKey) {
    for (KeyListener listener : listMatches) {
      try {
        if (listener.probablyWantKey(key, saltedKey)) {
          return true;
        }
      } catch (Exception t) {
        LOG.error(
            "Error in probablyWantKey callback during anyListProbablyWant for {}", listener, t);
      }
    }
    return false;
  }

  private boolean processTripMatches(
      Key key, byte[] saltedKey, KeyBlock block, ClientContext context, List<KeyListener> matches) {
    boolean ret = false;
    for (KeyListener listener : matches) {
      try {
        if (listener.handleBlock(key, saltedKey, block, context)) {
          ret = true;
        }
      } catch (Exception t) {
        LOG.error("Error in handleBlock callback during tripPendingKey for {}", listener, t);
      }
      if (listener.isEmpty()) {
        try {
          removePendingKeys(listener);
        } catch (Exception t) {
          LOG.error("Error while removing pending listener {}", listener, t);
        }
      }
    }
    return ret;
  }
}
