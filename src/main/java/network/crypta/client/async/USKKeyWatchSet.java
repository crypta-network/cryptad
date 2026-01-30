package network.crypta.client.async;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.keys.USK;
import network.crypta.support.RemoveRangeArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tracks edition windows and lookup plans for a single {@link USK} namespace.
 *
 * <p>This watch set aggregates the last known good edition, per-subscriber hints, and persistent
 * hints to decide which editions should be fetched immediately and which can be polled in the
 * background. It maintains short caches of derived document-name hashes so matches against inbound
 * keys and datastore blocks can be resolved without recomputing hashes on each request. State
 * evolves as callers report new hints and as successful lookups advance the baseline slot.
 *
 * <p>All mutable states are guarded by this instance lock. Callers must acquire the lock on this
 * object last and pass in any looked-up values; do not perform external lookups while holding this
 * lock.
 *
 * <ul>
 *   <li>Compute fetch and poll plans for upcoming editions.
 *   <li>Maintain per-subscriber and persistent hint tracking.
 *   <li>Match keys or blocks to editions using cached hashes.
 * </ul>
 */
final class USKKeyWatchSet {
  /** Default number of edition slots probed per lookup window. */
  static final int WATCH_KEYS = 50;

  /** Logger for watch-set diagnostics and trace output. */
  private static final Logger LOG = LoggerFactory.getLogger(USKKeyWatchSet.class);

  /** USK, whose editions are being monitored and expanded into SSK lookups. */
  private final USK origUSK;

  /** Minimum number of failed edition probes to schedule beyond {@code lookedUp}. */
  private final int origMinFailures;

  /** Whether new lookups should be scheduled as background polls instead of immediate fetches. */
  private final boolean backgroundPoll;

  // Common for the whole USK
  /** Public key hash for the USK namespace being tracked. */
  private final byte[] pubKeyHash;

  /** Crypto algorithm identifier for derived SSKs. */
  private final byte cryptoAlgorithm;

  // List of slots since the USKManager's current last known good edition.
  /** Key list anchored at the last known good slot. */
  private final KeyList fromLastKnownSlot;

  /** Per-subscriber key lists keyed by the hinted edition. */
  private final TreeMap<Long, KeyList> fromSubscribers;

  /** Persistent hint editions that outlive transient subscribers. */
  private final TreeSet<Long> persistentHints = new TreeSet<>();

  /**
   * Creates a watch set seeded from the current manager slot and USK hints.
   *
   * <p>The constructor initializes the shared hash cache for the last known good edition and
   * records the configuration used to plan future lookups. If the USK already suggests an edition
   * ahead of {@code lookedUp}, a subscriber list is seeded so that edition is fetched even before
   * explicit hint updates arrive.
   *
   * @param origUSK base USK, whose editions and keys will be tracked, must not be null
   * @param lookedUp current best-known slot from the manager; {@code -1} means unknown
   * @param origMinFailures minimum number of failed edition probes to schedule past {@code
   *     lookedUp}
   * @param backgroundPoll whether newly scheduled lookups should be polled rather than fetched
   */
  USKKeyWatchSet(USK origUSK, long lookedUp, int origMinFailures, boolean backgroundPoll) {
    this.origUSK = origUSK;
    this.origMinFailures = origMinFailures;
    this.backgroundPoll = backgroundPoll;
    this.pubKeyHash = origUSK.getPubKeyHash();
    this.cryptoAlgorithm = origUSK.cryptoAlgorithm;
    if (LOG.isDebugEnabled()) LOG.debug("init watch list: base slot {}", lookedUp);
    fromLastKnownSlot = new KeyList(lookedUp);
    fromSubscribers = new TreeMap<>();
    if (origUSK.suggestedEdition > lookedUp)
      fromSubscribers.put(origUSK.suggestedEdition, new KeyList(origUSK.suggestedEdition));
  }

  /**
   * Bundles lookup descriptors to fetch immediately and to poll in the background.
   *
   * <p>The two arrays represent a single planning cycle produced by {@link #getEditionsToFetch}.
   * Callers typically enqueue the {@link #fetch} entries for immediate network fetches and schedule
   * {@link #poll} entries for lower-priority background polling. The arrays are immutable snapshots
   * of the lists provided to the constructor.
   */
  static class ToFetch {

    /**
     * Creates a fetch plan from the provided lookup lists.
     *
     * <p>The constructor copies the list contents into fixed arrays. The original lists are not
     * retained, so callers may continue to mutate them after construction without affecting the
     * stored plan. The ordering of entries is preserved from the input lists.
     *
     * @param toFetch2 lookups to fetch immediately; non-null, in planned execution order
     * @param toPoll2 lookups to poll without immediate fetch; non-null, in planned order
     */
    public ToFetch(List<Lookup> toFetch2, List<Lookup> toPoll2) {
      fetch = toFetch2.toArray(new Lookup[0]);
      poll = toPoll2.toArray(new Lookup[0]);
    }

    /**
     * Lookups to fetch immediately.
     *
     * <p>This array represents higher-priority fetches that should be started right away. Entries
     * are unique for a given planning cycle and already filtered against the running set. The array
     * is owned by this instance and should be treated as read-only by callers.
     */
    public final Lookup[] fetch;

    /**
     * Lookups to poll in background cycles.
     *
     * <p>This array represents lower-priority probes suitable for periodic polling. Entries are
     * stable for the planning cycle and already deduplicated against active lookups. The array is
     * owned by this instance and should be treated as read-only by callers.
     */
    public final Lookup[] poll;
  }

  /**
   * Builds a plan of editions to fetch immediately and to poll in the background.
   *
   * <p>The plan is derived from the last known good slot, active subscriber hints, and optional
   * random sampling. The method removes lookups that are already running from the supplied list, so
   * callers can reuse that list as a deduplication set. When background polling is enabled, the
   * method prefers polling new editions rather than immediate fetches. The returned plan is a
   * snapshot; later updates to hints do not retroactively change it.
   *
   * @param lookedUp current best-known slot from the manager; {@code -1} when unknown
   * @param random random source used for optional sampling; must not be null when {@code doRandom}
   * @param alreadyRunning lookups already in flight; entries that remain valid are removed in-place
   * @param doRandom whether to include randomized probes beyond deterministic windows
   * @param isFirstLoop whether this is the first polling loop of a watch cycle
   * @return plan containing lookups to fetch immediately and to poll later
   */
  public synchronized ToFetch getEditionsToFetch(
      long lookedUp,
      Random random,
      List<Lookup> alreadyRunning,
      boolean doRandom,
      boolean isFirstLoop) {

    if (LOG.isDebugEnabled())
      LOG.debug("plan fetch list: latest slot {} running lookups {}", lookedUp, alreadyRunning);

    List<Lookup> toFetch = new ArrayList<>();
    List<Lookup> toPoll = new ArrayList<>();

    boolean probeFromLastKnownGood =
        lookedUp > -1 || (backgroundPoll && !isFirstLoop) || fromSubscribers.isEmpty();

    if (probeFromLastKnownGood)
      fromLastKnownSlot.getNextEditions(toFetch, toPoll, lookedUp, alreadyRunning);

    collectFromSubscribers(lookedUp, toFetch, toPoll, alreadyRunning);

    if (doRandom) {
      collectRandomEditions(
          probeFromLastKnownGood, lookedUp, random, toFetch, toPoll, alreadyRunning);
    }

    return new ToFetch(toFetch, toPoll);
  }

  /**
   * Collects editions contributed by subscribers into fetch and poll lists.
   *
   * @param lookedUp current best-known slot from the manager
   * @param toFetch destination list for immediate fetches; entries are appended
   * @param toPoll destination list for polling attempts; entries are appended
   * @param alreadyRunning lookups already in flight; may be modified by this method
   */
  private void collectFromSubscribers(
      long lookedUp, List<Lookup> toFetch, List<Lookup> toPoll, List<Lookup> alreadyRunning) {
    // If we have moved past the origUSK, then clear the KeyList for it.
    for (Iterator<Entry<Long, KeyList>> it = fromSubscribers.entrySet().iterator();
        it.hasNext(); ) {
      Entry<Long, KeyList> entry = it.next();
      long l = entry.getKey() - 1;
      if (l <= lookedUp) {
        it.remove();
      }
      if (l == 0) {
        // add a check for edition 0: this happens if -1 is suggested.
        // Needed because we cannot set -0 for exhaustive search (-0 == 0 in Java).
        entry.getValue().getEditionIfNotAlreadyRunning(toFetch, alreadyRunning, l, false);
      }
      entry.getValue().getNextEditions(toFetch, toPoll, l - 1, alreadyRunning);
    }
  }

  /**
   * Adds randomized edition probes to the fetch/poll lists.
   *
   * @param probeFromLastKnownGood whether to seed probe from the last known good slot
   * @param lookedUp the current best-known slot used to bias sampling
   * @param random random source used to sample editions; must not be null
   * @param toFetch destination list for immediate fetches; entries are appended
   * @param toPoll destination list for polling attempts; entries are appended
   * @param alreadyRunning lookups already in flight; may be modified by this method
   */
  private void collectRandomEditions(
      boolean probeFromLastKnownGood,
      long lookedUp,
      Random random,
      List<Lookup> toFetch,
      List<Lookup> toPoll,
      List<Lookup> alreadyRunning) {
    // Now getRandomEditions
    int runningRandom = countRunningRandom(alreadyRunning, toFetch, toPoll);

    int allowedRandom = 1 + fromSubscribers.size();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "random probe budget: running {} allowed {} lookedUp {} for {}",
          runningRandom,
          allowedRandom,
          lookedUp,
          origUSK);

    allowedRandom -= runningRandom;

    if (allowedRandom > 0 && probeFromLastKnownGood) {
      fromLastKnownSlot.getRandomEditions(toFetch, lookedUp, alreadyRunning, random, 1);
      allowedRandom -= 1;
    }

    for (Iterator<KeyList> it = fromSubscribers.values().iterator();
        allowedRandom >= 2 && it.hasNext(); ) {
      KeyList k = it.next();
      k.getRandomEditions(toFetch, lookedUp, alreadyRunning, random, 1);
      allowedRandom -= 1;
    }
  }

  /**
   * Counts random probes that are already running but not in the current plan.
   *
   * @param alreadyRunning lookups already in flight
   * @param toFetch lookups planned for immediate fetch
   * @param toPoll lookups planned for polling
   * @return number of random probes already running outside the current plan
   */
  private static int countRunningRandom(
      List<Lookup> alreadyRunning, List<Lookup> toFetch, List<Lookup> toPoll) {
    int runningRandom = 0;
    for (Lookup l : alreadyRunning) {
      if (toFetch.contains(l) || toPoll.contains(l)) continue;
      runningRandom++;
    }
    return runningRandom;
  }

  /**
   * Reconciles subscriber hints with persisted and derived hints for this watch set.
   *
   * <p>The supplied hint array is sorted and deduplicated, then merged with persistent hints and
   * the USK's suggested edition when it is still ahead of {@code lookedUp}. Any hints at or below
   * the current slot are discarded. The subscriber map is then updated to reflect the surviving
   * hints, creating or removing {@link KeyList} instances as needed.
   *
   * @param hints latest subscriber hint values; non-null, may contain duplicates
   * @param lookedUp current best-known slot used to discard stale hints and prune lists
   */
  public synchronized void updateSubscriberHints(Long[] hints, long lookedUp) {
    List<Long> surviving = collectSurvivingHints(hints, lookedUp);
    mergePersistentHints(surviving, lookedUp);
    ensureSuggestedEditionIncluded(surviving, lookedUp);
    reconcileSubscribersWithSurviving(surviving);
  }

  /**
   * Filters subscriber hints to those that remain relevant beyond {@code lookedUp}.
   *
   * @param hints subscriber hint values to filter; must not be null
   * @param lookedUp current best-known slot used as a cutoff
   * @return list of surviving hints in ascending order
   */
  private static List<Long> collectSurvivingHints(Long[] hints, long lookedUp) {
    List<Long> surviving = new ArrayList<>();
    Arrays.sort(hints);
    long prev = -1;
    for (Long hint : hints) {
      if (hint <= lookedUp) {
        prev = hint;
      } else if (hint != prev) {
        surviving.add(hint);
        prev = hint;
      }
    }
    return surviving;
  }

  /**
   * Merges persistent hints into the surviving list while dropping stale entries.
   *
   * @param surviving list of surviving hints to update; must not be null
   * @param lookedUp current best-known slot used to drop stale hints
   */
  private void mergePersistentHints(List<Long> surviving, long lookedUp) {
    for (Iterator<Long> i = persistentHints.iterator(); i.hasNext(); ) {
      Long hint = i.next();
      if (hint <= lookedUp) {
        i.remove();
      }
      if (surviving.contains(hint)) continue;
      surviving.add(hint);
    }
  }

  /**
   * Ensures the USK's suggested edition is present when it is still ahead.
   *
   * @param surviving list of surviving hints to update; must not be null
   * @param lookedUp current best-known slot used as a cutoff
   */
  private void ensureSuggestedEditionIncluded(List<Long> surviving, long lookedUp) {
    if (origUSK.suggestedEdition > lookedUp && !surviving.contains(origUSK.suggestedEdition))
      surviving.add(origUSK.suggestedEdition);
  }

  /**
   * Reconciles the subscriber map to match the surviving hints list.
   *
   * @param surviving list of surviving hint editions; must not be null
   */
  private void reconcileSubscribersWithSurviving(List<Long> surviving) {
    for (Iterator<Long> it = fromSubscribers.keySet().iterator(); it.hasNext(); ) {
      Long l = it.next();
      if (surviving.contains(l)) continue;
      it.remove();
    }
    for (Long l : surviving) {
      if (fromSubscribers.containsKey(l)) continue;
      fromSubscribers.put(l, new KeyList(l));
    }
  }

  /**
   * Adds a persistent hint edition that is ahead of the current lookup.
   *
   * <p>The hint is stored in the persistent set so it survives transient subscribers. If the hint
   * is new and still ahead of {@code lookedUp}, a {@link KeyList} is created to schedule fetches
   * for that edition. Hints at or behind the current slot are ignored.
   *
   * @param suggestedEdition edition number to add; must be greater than {@code lookedUp}
   * @param lookedUp the current best-known slot used to ignore stale hints
   */
  public synchronized void addHintEdition(long suggestedEdition, long lookedUp) {
    if (suggestedEdition <= lookedUp) return;
    if (!persistentHints.add(suggestedEdition)) return;
    if (fromSubscribers.containsKey(suggestedEdition)) return;
    fromSubscribers.put(suggestedEdition, new KeyList(suggestedEdition));
  }

  /**
   * Estimates the number of watched keys based on the current subscriber state.
   *
   * <p>The returned value multiplies the configured watch window by the number of active subscriber
   * lists, plus the base watch list. The estimate does not account for overlapping editions across
   * lists, so callers should treat it as an upper bound for scheduling heuristics.
   *
   * @return estimated count of watched keys for scheduling and load decisions
   */
  public synchronized long size() {
    return WATCH_KEYS + (long) fromSubscribers.size() * WATCH_KEYS; // Note: does not account for
    // overlap
  }

  /**
   * Builds datastore sub-checkers for the current watch lists.
   *
   * <p>The method creates sub-checkers that cover a window of {@link #WATCH_KEYS} editions for the
   * last known good slot and any subscriber-provided hints. Each sub-checker encapsulates the set
   * of {@link NodeSSK} keys that should be checked in the datastore. When no checks are required,
   * the method returns {@code null} to avoid unnecessary work.
   *
   * @param lastSlot the last known good edition used to seed checks and prune stale lists
   * @return datastore sub-checkers to run, or {@code null} when no checks are required
   */
  public synchronized List<KeyList.StoreSubChecker> getDatastoreCheckers(long lastSlot) {
    // Check WATCH_KEYS from last known good slot.
    // Note: does not currently take origUSK or subscribers into account.
    if (LOG.isDebugEnabled())
      LOG.debug("datastore check plan from slot {} for {}", lastSlot, origUSK);
    List<KeyList.StoreSubChecker> checkers = new ArrayList<>();
    KeyList.StoreSubChecker c = fromLastKnownSlot.checkStore(lastSlot + 1);
    if (c != null) checkers.add(c);
    // If we have moved past the origUSK, then clear the KeyList for it.
    for (Iterator<Entry<Long, KeyList>> it = fromSubscribers.entrySet().iterator();
        it.hasNext(); ) {
      Entry<Long, KeyList> entry = it.next();
      long l = entry.getKey();
      if (l <= lastSlot) it.remove();
      c = entry.getValue().checkStore(l);
      if (c != null) checkers.add(c);
    }
    return checkers.isEmpty() ? null : checkers;
  }

  /**
   * Decodes a low-level {@link SSKBlock} into a client-level block for the given edition.
   *
   * <p>The method derives the expected {@link ClientSSK} from the USK and verifies that the
   * document-name hash in the block matches the derived value. On success, the block is wrapped in
   * a {@link ClientSSKBlock} for higher-level consumers. Verification is strict and will throw when
   * the block does not correspond to the expected edition.
   *
   * @param block low-level block to decode; must not be null and must be an SSK block
   * @param edition edition number that the block is expected to represent
   * @return decoded client block for the edition, ready for higher-level processing
   * @throws SSKVerifyException if the block does not match the expected document-name hash
   */
  public ClientSSKBlock decode(SSKBlock block, long edition) throws SSKVerifyException {
    ClientSSK csk = origUSK.getSSK(edition);
    if (!Arrays.equals(csk.ehDocname, block.getKey().getKeyBytes())) {
      throw new SSKVerifyException("Docname hash mismatch for decoded block");
    }
    return ClientSSKBlock.construct(block, csk);
  }

  /**
   * Attempts to match the provided node key against watched key lists.
   *
   * <p>The method checks the base watch list anchored at the last known good slot and then scans
   * any subscriber-provided lists. Subscriber lists whose edition anchors are at or behind {@code
   * lastSlot} are discarded as stale. Matching is performed against cached document-name hashes and
   * returns the edition number when the key corresponds to a watched slot.
   *
   * @param key node key to match; must not be null and must belong to the same USK
   * @param lastSlot the last known good edition used to prune stale lists and bound matching
   * @return matched edition number, or {@code -1} when no match is found
   */
  public synchronized long match(NodeSSK key, long lastSlot) {
    if (LOG.isDebugEnabled())
      LOG.debug("match key against watch list: key {} lastSlot {} for {}", key, lastSlot, origUSK);
    long ret = fromLastKnownSlot.match(key, lastSlot);
    if (ret != -1) return ret;

    for (Iterator<Entry<Long, KeyList>> it = fromSubscribers.entrySet().iterator();
        it.hasNext(); ) {
      Entry<Long, KeyList> entry = it.next();
      long l = entry.getKey();
      if (l <= lastSlot) it.remove();
      ret = entry.getValue().match(key, l);
      if (ret != -1) return ret;
    }
    return -1;
  }

  /**
   * Reports whether a key is definitely wanted by this watch set.
   *
   * <p>The check is strict: the key must be a {@link NodeSSK} that shares the USK public key hash
   * and must match one of the currently watched editions. When a match is found, the supplied
   * {@code progressPriority} is returned so callers can preserve their scheduling class.
   *
   * @param key candidate key to evaluate; must not be null and must be a {@link NodeSSK}
   * @param lastSlot the last known good edition used to bound the match
   * @param progressPriority priority class to return on match
   * @return priority class when wanted, or {@code -1} when not wanted
   */
  public short definitelyWantKey(Key key, long lastSlot, short progressPriority) {
    if (!(key instanceof NodeSSK k)) return -1;
    if (!origUSK.samePubKeyHash(k)) return -1;
    synchronized (this) {
      if (match(k, lastSlot) != -1) return progressPriority;
    }
    return -1;
  }

  /**
   * Reports whether a key is probably wanted by this watch set.
   *
   * <p>This check is a softer version of {@link #definitelyWantKey(Key, long, short)} and returns
   * only a boolean. The key must be a {@link NodeSSK} for the same USK and must match a watched
   * edition. The result reflects the current watch lists and may change as hints are updated.
   *
   * @param key candidate key to evaluate; must not be null and must be a {@link NodeSSK}
   * @param lastSlot the last known good edition used to bound the match
   * @return {@code true} if the key appears relevant, {@code false} otherwise
   */
  @SuppressWarnings("unused")
  public boolean probablyWantKey(Key key, long lastSlot) {
    if (!(key instanceof NodeSSK k)) return false;
    if (!origUSK.samePubKeyHash(k)) return false;
    synchronized (this) {
      return match(k, lastSlot) != -1;
    }
  }

  /**
   * Attempts to match and decode a found block against the watch lists.
   *
   * <p>The method first verifies that the incoming key and block are of the SSK type, then attempts
   * to match the key against the watched editions. If a match is found, the block is decoded and
   * verified against the expected document-name hash for that edition. Verification failures return
   * a {@link MatchedBlock} with a {@code null} payload to indicate the match but failed to decode.
   *
   * @param key key associated with the found block; must be a {@link NodeSSK}
   * @param found block returned from the datastore; must be an {@link SSKBlock}
   * @param lastSlot the last known good edition used to bound the match
   * @return a matched block result, or {@code null} when no match was found
   */
  public MatchedBlock matchBlock(Key key, KeyBlock found, long lastSlot) {
    if (!(found instanceof SSKBlock sskBlock)) return null;
    if (!(key instanceof NodeSSK nodeSSK)) return null;
    long edition;
    synchronized (this) {
      edition = match(nodeSSK, lastSlot);
    }
    if (edition == -1) return null;
    if (LOG.isDebugEnabled()) LOG.debug("matched block edition {} for {}", edition, origUSK);

    ClientSSKBlock data;
    try {
      data = decode(sskBlock, edition);
    } catch (SSKVerifyException _) {
      data = null;
    }
    return new MatchedBlock(edition, data);
  }

  /**
   * Describes a matched block and its resolved edition number.
   *
   * @param edition resolved edition value that matched the watch list
   * @param block decoded client block, or {@code null} when verification failed
   */
  record MatchedBlock(long edition, ClientSSKBlock block) {}

  /**
   * Caches derived document-name hashes for a sliding window of editions.
   *
   * <p>Each {@code KeyList} is anchored at a specific base edition and maintains a fixed-size
   * window of {@link #WATCH_KEYS} hashes derived from the owning USK. The cache is stored in a weak
   * reference, so it can be reclaimed when memory is tight, with regeneration on demand. The list
   * is used to match incoming {@link NodeSSK} keys or to build datastore checkers without
   * recomputing hashes for every request.
   */
  class KeyList {

    /**
     * USK edition number represented by cache index 0.
     *
     * <p>This value advances as the cache is realigned to newer base editions. It is always greater
     * than or equal to zero and acts as the base offset for indexing into {@link #cache}.
     */
    long firstSlot;

    /**
     * Weakly referenced cache of document-name hashes for each watched slot.
     *
     * <p>The list contains {@code WATCH_KEYS} entries whenever populated. It can be cleared by the
     * garbage collector, in which case it is regenerated on the next access.
     */
    private WeakReference<RemoveRangeArrayList<byte[]>> cache;

    /**
     * The lowest edition for which datastore checks have been confirmed.
     *
     * <p>Initialized to {@code -1} to represent "unchecked". Updated as sub-checkers report
     * completion in {@link StoreSubChecker#checked()}.
     */
    private long checkedDatastoreFrom = -1;

    /**
     * The highest edition (exclusive) for which datastore checks have been confirmed.
     *
     * <p>Initialized to {@code -1} to represent "unchecked". Updated as sub-checkers report
     * completion in {@link StoreSubChecker#checked()}.
     */
    private long checkedDatastoreTo = -1;

    /**
     * Creates a key list anchored at the provided slot.
     *
     * <p>The cache window is initialized immediately with {@link #WATCH_KEYS} hashes derived from
     * the USK. The window can later be realigned as newer base editions are reported, preserving
     * any overlapping entries when possible.
     *
     * @param slot the first slot to include in the cache; must be zero or higher
     */
    public KeyList(long slot) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "init key list cache at slot {} for {} {}",
            slot,
            origUSK,
            this,
            new Exception("debug"));
      firstSlot = slot;
      RemoveRangeArrayList<byte[]> ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
      cache = new WeakReference<>(ehDocnames);
      generate(firstSlot, WATCH_KEYS, ehDocnames);
    }

    /**
     * Adds the next set of editions to either {@code toFetch} or {@code toPoll}.
     *
     * <p>The method advances forward from {@code lookedUp}, scheduling up to {@code
     * origMinFailures} editions. Already-running lookups are removed from {@code alreadyRunning} to
     * avoid duplicate scheduling. When background polling is enabled, the editions are appended to
     * the poll list instead of the immediate fetch list.
     *
     * @param toFetch destination list for editions that should be fetched immediately when not in
     *     background polling mode; entries are appended, not cleared
     * @param toPoll destination list for editions that should be polled (no immediate fetch) when
     *     in background polling mode; entries are appended, not cleared
     * @param lookedUp current best known slot (edition) used as a base for computing the next
     *     candidate editions; values below zero are treated as zero
     * @param alreadyRunning list of lookups currently in progress; this method removes any edition
     *     that remains valid so it is not scheduled twice
     */
    public synchronized void getNextEditions(
        List<Lookup> toFetch, List<Lookup> toPoll, long lookedUp, List<Lookup> alreadyRunning) {
      if (LOG.isDebugEnabled()) LOG.debug("schedule next editions after {}", lookedUp);
      if (lookedUp < 0) lookedUp = 0;
      for (int i = 1; i <= origMinFailures; i++) {
        long ed = i + lookedUp;
        if (backgroundPoll) {
          getEditionIfNotAlreadyRunning(toPoll, alreadyRunning, ed, true);
        } else {
          getEditionIfNotAlreadyRunning(toFetch, alreadyRunning, ed, true);
        }
      }
    }

    /**
     * Adds an edition lookup if it is not already running.
     *
     * <p>The lookup is deduplicated against both the target list and the already-running list. If a
     * matching lookup is found in {@code alreadyRunning}, it is removed and no new entry is added.
     * The resulting {@link Lookup} contains the derived {@link ClientSSK} key for the edition.
     *
     * @param lookupList destination list for new lookups; entries are appended in order
     * @param alreadyRunning list of lookups already in progress; this method removes matches
     * @param ed edition number to add as a lookup candidate
     * @param ignoreStore whether this lookup should bypass store checks
     * @return {@code true} when the edition was added, {@code false} when deduplicated
     */
    public boolean getEditionIfNotAlreadyRunning(
        List<Lookup> lookupList, List<Lookup> alreadyRunning, long ed, boolean ignoreStore) {
      Lookup l = new Lookup();
      l.val = ed;
      l.label = origUSK.toString();
      if (lookupList.contains(l)) {
        if (LOG.isTraceEnabled()) LOG.trace("skip duplicate lookup in planned list: {}", l);
        return false;
      }
      if (alreadyRunning.remove(l)) {
        if (LOG.isTraceEnabled()) LOG.trace("skip lookup already running: {}", l);
        return false;
      }
      ClientSSK key;
      // Note: consider reusing ehDocnames where possible
      // The problem is we need a ClientSSK for the high level stuff.
      key = origUSK.getSSK(ed);
      l.key = key;
      l.ignoreStore = ignoreStore;
      if (lookupList.contains(l)) {
        if (LOG.isTraceEnabled()) LOG.trace("skip lookup after key fill: {}", l);
        return false;
      }
      return lookupList.add(l);
    }

    /**
     * Adds random edition probes to the provided list.
     *
     * <p>The method samples future editions using {@link #sampleGeometric(long, Random)} and adds
     * them to {@code toFetch} until {@code allowed} entries are accepted. Each sampled edition is
     * deduplicated against the running set. The random probes help catch up to fast-moving editions
     * without needing to scan every intermediate slot.
     *
     * @param toFetch destination list for random probes; entries are appended
     * @param lookedUp current best-known slot used as a base for sampling
     * @param alreadyRunning list of lookups already in progress; used for deduplication
     * @param random random source used for sampling; must not be null
     * @param allowed maximum number of random editions to add
     */
    public synchronized void getRandomEditions(
        List<Lookup> toFetch,
        long lookedUp,
        List<Lookup> alreadyRunning,
        Random random,
        int allowed) {
      // Then add a couple of random editions for catch-up.
      long baseEdition = lookedUp + origMinFailures;
      for (int i = 0; i < allowed; i++) {
        while (true) { // Note: consider switching to limited for-loop to ensure there can be no
          // infinite loop
          long fetch = sampleGeometric(baseEdition, random);
          if (tryAddRandomEdition(toFetch, lookedUp, alreadyRunning, fetch)) break;
        }
      }
    }

    /**
     * Samples a future edition using a geometric distribution.
     *
     * <p>The sampling uses a mix of means to bias toward nearer editions while still allowing
     * larger jumps. The returned edition is always greater than or equal to {@code baseEdition}.
     *
     * @param baseEdition base edition offset for sampling; must be zero or higher
     * @param random random source used to sample; must not be null
     * @return sampled edition number at or above {@code baseEdition}
     */
    private static long sampleGeometric(long baseEdition, Random random) {
      // Geometric distribution.
      // 20% chance of mean 100, 80% chance of mean 10. Thanks evanbd.
      while (true) {
        int mean = random.nextInt(5) == 0 ? 100 : 10;
        double u = uniform01FromLong(random);
        long fetch = baseEdition + (long) Math.floor(Math.log(u) / Math.log(1.0 - 1.0 / mean));
        if (fetch >= baseEdition) return fetch;
      }
    }

    /**
     * Creates a uniform random value in (0,1] using {@link Random#nextLong()}.
     *
     * <p>The helper converts the positive {@code long} range into a floating-point value in the
     * open interval (0,1]. It never returns zero, which avoids taking {@code log(0)} when sampling.
     *
     * @param random random source used for sampling; must not be null
     * @return uniform value in the open interval (0,1]
     */
    private static double uniform01FromLong(Random random) {
      long bits = random.nextLong() & Long.MAX_VALUE; // 0 .. 2^63-1
      return (bits + 1.0) / (Long.MAX_VALUE + 1.0);
    }

    /**
     * Attempts to add a random edition if it is not already scheduled.
     *
     * <p>The lookup is deduplicated against the running set and uses the {@code ignoreStore} flag
     * when the sampled edition is close enough to {@code lookedUp}. The method logs diagnostic
     * information when debug logging is enabled.
     *
     * @param toFetch destination list for random probes; entries are appended
     * @param lookedUp current best-known slot used for range decisions
     * @param alreadyRunning list of lookups already in progress; used for deduplication
     * @param fetch sampled edition to add
     * @return {@code true} when the edition was added to the fetch list
     */
    private boolean tryAddRandomEdition(
        List<Lookup> toFetch, long lookedUp, List<Lookup> alreadyRunning, long fetch) {
      if (LOG.isDebugEnabled())
        LOG.debug("random probe candidate {} for {} (lookedUp {})", fetch, origUSK, lookedUp);
      return getEditionIfNotAlreadyRunning(
          toFetch, alreadyRunning, fetch, (fetch - lookedUp) < WATCH_KEYS);
    }

    /**
     * Represents a sub-range of datastore keys to check.
     *
     * <p>The sub-checker encapsulates a contiguous range of editions and the corresponding {@link
     * NodeSSK} keys. Once the caller verifies those keys against the datastore, it should invoke
     * {@link #checked()} to update the parent {@link KeyList} state.
     */
    public class StoreSubChecker {

      /**
       * Keys to check in the datastore for this range.
       *
       * <p>The array is ordered by increasing edition and is owned by the sub-checker.
       */
      final NodeSSK[] keysToCheck;

      /**
       * The edition from which the datastore will be checked after execution.
       *
       * <p>This value is inclusive and marks the start of the checked range.
       */
      private final long checkedFrom;

      /**
       * The edition up to which the datastore will be checked after execution.
       *
       * <p>This value is exclusive and marks the end of the checked range.
       */
      private final long checkedTo;

      /**
       * Creates a sub-checker for a contiguous range of editions.
       *
       * <p>The caller is responsible for running datastore checks for each key in {@code
       * keysToCheck} and then calling {@link #checked()} to advance the cached datastore bounds.
       *
       * @param keysToCheck node keys to check; must not be null and in ascending edition order
       * @param checkFrom starting edition of the range, inclusive
       * @param checkTo ending edition of the range, exclusive
       */
      private StoreSubChecker(NodeSSK[] keysToCheck, long checkFrom, long checkTo) {
        this.keysToCheck = keysToCheck;
        this.checkedFrom = checkFrom;
        this.checkedTo = checkTo;
        if (LOG.isDebugEnabled())
          LOG.debug("datastore check range {}..{} for {} on {}", checkFrom, checkTo, origUSK, this);
      }

      /**
       * Marks this checker as completed and updates datastore bounds.
       *
       * <p>The method updates the parent {@link KeyList} with the completed range. It keeps the
       * existing lower bound if it already covers {@code checkedFrom}, but always advances the
       * upper bound to {@code checkedTo}. Callers should invoke this once per sub-checker after all
       * keys have been verified.
       */
      void checked() {
        synchronized (KeyList.this) {
          // Update the start bound only when the previous range does not already cover it.
          if (!(checkedDatastoreTo >= checkedFrom && checkedDatastoreFrom <= checkedFrom)) {
            checkedDatastoreFrom = checkedFrom;
          }
          checkedDatastoreTo = checkedTo;
          if (LOG.isDebugEnabled())
            LOG.debug(
                "datastore check complete {}..{}, overall {}..{} for {}",
                checkedFrom,
                checkedTo,
                checkedDatastoreFrom,
                checkedDatastoreTo,
                origUSK);
        }
      }
    }

    /**
     * Builds a datastore checker for a window of slots starting at {@code lastSlot}.
     *
     * <p>The checker describes a contiguous range of editions beginning at {@code lastSlot} and
     * spanning up to {@link #WATCH_KEYS} entries. The method reuses cached hashes whenever possible
     * and skips work already covered by prior datastore checks. When no new range remains, the
     * method returns {@code null}.
     *
     * @param lastSlot starting edition to check from; values below zero are treated as zero
     * @return a sub-checker describing keys to check, or {@code null} when no work is needed
     */
    public synchronized StoreSubChecker checkStore(long lastSlot) {
      if (LOG.isDebugEnabled())
        LOG.debug("build store checker from {} (firstSlot {})", lastSlot, firstSlot);
      long checkFrom = lastSlot;
      long checkTo = lastSlot + WATCH_KEYS;
      if (checkedDatastoreTo >= checkFrom) {
        checkFrom = checkedDatastoreTo;
      }
      if (checkFrom >= checkTo) return null; // Nothing to check.
      // Update the cache.
      RemoveRangeArrayList<byte[]> ehDocnames = updateCache(lastSlot);
      // Now create NodeSSK[] from the part of the cache that
      // ehDocnames[0] is firstSlot
      // ehDocnames[checkFrom-firstSlot] is checkFrom
      int offset = (int) (checkFrom - firstSlot);
      NodeSSK[] keysToCheck = new NodeSSK[WATCH_KEYS - offset];
      for (int x = 0, i = offset; i < WATCH_KEYS; i++, x++) {
        keysToCheck[x] = new NodeSSK(pubKeyHash, ehDocnames.get(i), cryptoAlgorithm);
      }
      return new StoreSubChecker(keysToCheck, checkFrom, checkTo);
    }

    /**
     * Updates the cached document-name hashes based on a new base edition.
     *
     * <p>The cache is regenerated if it has been reclaimed by the garbage collector. Otherwise, the
     * existing list is realigned to {@code curBaseEdition} by trimming or extending entries as
     * needed. The returned cache is always populated with {@link #WATCH_KEYS} entries.
     *
     * @param curBaseEdition base edition used to realign the cache
     * @return updated cache containing hashes for the current window
     */
    synchronized RemoveRangeArrayList<byte[]> updateCache(long curBaseEdition) {
      if (LOG.isDebugEnabled())
        LOG.debug("realign cache to base {} (firstSlot {})", curBaseEdition, firstSlot);
      RemoveRangeArrayList<byte[]> ehDocnames;
      if (cache == null || (ehDocnames = cache.get()) == null) {
        ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
        cache = new WeakReference<>(ehDocnames);
        firstSlot = curBaseEdition;
        if (LOG.isDebugEnabled()) LOG.debug("Regenerating because lost cached keys");
        generate(firstSlot, WATCH_KEYS, ehDocnames);
        return ehDocnames;
      }
      match(null, curBaseEdition, ehDocnames);
      return ehDocnames;
    }

    /**
     * Updates the cache if needed and attempts to match the provided key.
     *
     * <p>If the cache is missing, it is regenerated for {@code curBaseEdition}. Otherwise, the
     * method checks the current cache first and only performs a realignment when needed. A {@code
     * null} key skips matching and simply ensures the cache is aligned.
     *
     * @param key key to match, or {@code null} to only update the cache
     * @param curBaseEdition new base edition used to realign the cache
     * @return edition number for the key, or {@code -1} when not matched
     */
    public synchronized long match(NodeSSK key, long curBaseEdition) {
      if (LOG.isDebugEnabled())
        LOG.debug("match request base {} (firstSlot {})", curBaseEdition, firstSlot);
      RemoveRangeArrayList<byte[]> ehDocnames;
      if (cache == null || (ehDocnames = cache.get()) == null) {
        ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
        cache = new WeakReference<>(ehDocnames);
        firstSlot = curBaseEdition;
        generate(firstSlot, WATCH_KEYS, ehDocnames);
        return key == null ? -1 : innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
      }
      // Might as well check first.
      long x = innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
      if (x != -1) return x;
      return match(key, curBaseEdition, ehDocnames);
    }

    /**
     * Updates the cache for a new base edition and matches only the changed segments.
     *
     * <p>This helper avoids rechecking the entire cache by updating only the sections that changed
     * due to the base edition moving forward or backward. When the base edition regresses, the
     * cache is left intact and matching uses the existing window.
     *
     * @param key key to match; may be {@code null} to skip matching
     * @param curBaseEdition edition to align the cache with
     * @param ehDocnames cached document-name hashes to update
     * @return edition number for the key, or {@code -1} when not matched
     */
    private long match(NodeSSK key, long curBaseEdition, RemoveRangeArrayList<byte[]> ehDocnames) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "match against cache: key {} base {} firstSlot {} for {} on {}",
            key,
            curBaseEdition,
            firstSlot,
            origUSK,
            this);
      if (firstSlot < curBaseEdition) {
        return handleFirstSlotBehind(key, curBaseEdition, ehDocnames);
      } else if (firstSlot > curBaseEdition) {
        return handleFirstSlotAhead(key, ehDocnames, curBaseEdition);
      }
      return -1;
    }

    /**
     * Handles the case where {@code firstSlot} is behind the new base edition.
     *
     * <p>If the new base edition is beyond the cached window, the cache is rebuilt from scratch. If
     * there is overlap, the cache is trimmed at the front and extended at the end. Matching is
     * limited to the updated window when a key is provided.
     *
     * @param key key to match; may be {@code null} to skip matching
     * @param curBaseEdition new base edition
     * @param ehDocnames cached document-name hashes to update
     * @return edition number for the key, or {@code -1} when not matched
     */
    private long handleFirstSlotBehind(
        NodeSSK key, long curBaseEdition, RemoveRangeArrayList<byte[]> ehDocnames) {
      if (firstSlot + ehDocnames.size() <= curBaseEdition) {
        // No overlap. Clear it and start again.
        ehDocnames.clear();
        firstSlot = curBaseEdition;
        generate(curBaseEdition, WATCH_KEYS, ehDocnames);
        return key == null ? -1 : innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
      } else {
        // There is some overlap. Delete the first part of the array, then add stuff at the end.
        // ehDocnames[i] is slot firstSlot + i
        // We want to get rid of anything before curBaseEdition
        // So the first slot that is useful is the slot at i = curBaseEdition - firstSlot
        // Which is the new [0], whose edition is curBaseEdition
        ehDocnames.removeRange(0, (int) (curBaseEdition - firstSlot));
        int size = ehDocnames.size();
        firstSlot = curBaseEdition;
        generate(curBaseEdition + size, WATCH_KEYS - size, ehDocnames);
        return key == null ? -1 : innerMatch(key, ehDocnames, WATCH_KEYS - size, size, firstSlot);
      }
    }

    /**
     * Handles the case where {@code firstSlot} is ahead of the new base edition.
     *
     * <p>The method treats the regression as a transient condition and continues to use the current
     * cache window. Matching is therefore performed against the existing cache rather than
     * rebuilding it for the older base edition.
     *
     * @param key key to match; may be {@code null} to skip matching
     * @param ehDocnames cached document-name hashes to consult
     * @param curBaseEdition new base edition that lags behind {@code firstSlot}
     * @return edition number for the key, or {@code -1} when not matched
     */
    private long handleFirstSlotAhead(
        NodeSSK key, RemoveRangeArrayList<byte[]> ehDocnames, long curBaseEdition) {
      // Normal due to race conditions. We don't always report the new edition to the USKManager
      // immediately.
      // So ignore it.
      if (LOG.isTraceEnabled())
        LOG.trace("ignore base regression in match: {} -> {}", curBaseEdition, firstSlot);
      return key == null ? -1 : innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
    }

    /**
     * Matches a key against a slice of the cached hash list.
     *
     * <p>The method compares the key's bytes against the cached hash window between {@code offset}
     * and {@code offset + size}. It returns the edition number derived from {@code firstSlot} when
     * a match is found. The scan is linear over the specified slice.
     *
     * @param key key to match; must not be null
     * @param ehDocnames cached document-name hashes to scan
     * @param offset start offset within the cache
     * @param size number of entries to scan
     * @param firstSlot edition represented by cache index 0
     * @return matched edition number, or {@code -1} when not found
     */
    private long innerMatch(
        NodeSSK key,
        RemoveRangeArrayList<byte[]> ehDocnames,
        int offset,
        int size,
        long firstSlot) {
      byte[] data = key.getKeyBytes();
      for (int i = offset; i < (offset + size); i++) {
        if (Arrays.equals(data, ehDocnames.get(i))) {
          if (LOG.isDebugEnabled())
            LOG.debug("match hit edition {} for {}", firstSlot + i, origUSK);
          return firstSlot + i;
        }
      }
      return -1;
    }

    /**
     * Appends a series of document-name hashes to the cache.
     *
     * <p>The method derives {@link ClientSSK} instances for each edition starting at {@code
     * baseEdition} and appends their document-name hashes to {@code ehDocnames}. The caller is
     * responsible for ensuring the cache size does not exceed {@link #WATCH_KEYS}.
     *
     * @param baseEdition edition to start from
     * @param keys number of keys to add
     * @param ehDocnames cache to append to; must not be null
     */
    private void generate(long baseEdition, int keys, RemoveRangeArrayList<byte[]> ehDocnames) {
      if (LOG.isDebugEnabled()) LOG.debug("populate cache from {} for {}", baseEdition, origUSK);
      assert (baseEdition >= 0);
      for (int i = 0; i < keys; i++) {
        long ed = baseEdition + i;
        ehDocnames.add(origUSK.getSSK(ed).ehDocname);
      }
    }
  }

  /**
   * Describes a specific edition lookup and its derived key.
   *
   * <p>Lookup instances are value-like and are considered equal based on their edition value.
   * Callers populate {@link #key} and {@link #ignoreStore} when scheduling network fetches or
   * datastore checks. The {@link #label} is used for log output only and may be null.
   */
  static class Lookup {
    /**
     * Edition value represented by this lookup.
     *
     * <p>Equality and hashing are based solely on this value.
     */
    long val;

    /**
     * Client SSK key derived for the edition.
     *
     * <p>Set when the lookup is scheduled so callers can initiate fetches without recomputing.
     */
    ClientSSK key;

    /**
     * Whether this lookup should bypass store checks.
     *
     * <p>When {@code true}, the lookup is intended for direct fetch without checking the datastore.
     */
    boolean ignoreStore;

    /**
     * Descriptive label for logging, usually the owning USK.
     *
     * <p>This field is optional and may be {@code null}.
     */
    String label;

    /**
     * Creates an empty lookup descriptor.
     *
     * <p>Fields are populated by the scheduling methods that construct lookups.
     */
    Lookup() {}

    @Override
    public boolean equals(Object o) {
      if (o instanceof Lookup lookup) {
        return lookup.val == val;
      } else return false;
    }

    @Override
    public int hashCode() {
      return Long.hashCode(val);
    }

    @Override
    public String toString() {
      return (label == null ? "?" : label) + ":" + val;
    }
  }
}
