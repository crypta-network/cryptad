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
 * Tracks the list of editions that we want to fetch, from various sources - subscribers, origUSK,
 * last known slot from USKManager, etc.
 *
 * <p>LOCKING: Take the lock on this class last and always pass in lookup values. Do not look up
 * values in USKManager inside this class's lock.
 */
final class USKKeyWatchSet {
  static final int WATCH_KEYS = 50;

  private static final Logger LOG = LoggerFactory.getLogger(USKKeyWatchSet.class);

  private final USK origUSK;
  private final int origMinFailures;
  private final boolean backgroundPoll;

  // Common for whole USK
  /** Public key hash for the USK namespace being tracked. */
  private final byte[] pubKeyHash;

  /** Crypto algorithm identifier for derived SSKs. */
  private final byte cryptoAlgorithm;

  // List of slots since the USKManager's current last known good edition.
  /** Key list anchored at the last known good slot. */
  private final KeyList fromLastKnownSlot;

  /** Per-subscriber key lists keyed by hinted edition. */
  private final TreeMap<Long, KeyList> fromSubscribers;

  /** Persistent hint editions that outlive transient subscribers. */
  private final TreeSet<Long> persistentHints = new TreeSet<>();

  USKKeyWatchSet(USK origUSK, long lookedUp, int origMinFailures, boolean backgroundPoll) {
    this.origUSK = origUSK;
    this.origMinFailures = origMinFailures;
    this.backgroundPoll = backgroundPoll;
    this.pubKeyHash = origUSK.getPubKeyHash();
    this.cryptoAlgorithm = origUSK.cryptoAlgorithm;
    if (LOG.isDebugEnabled()) LOG.debug("Creating KeyList from last known good: {}", lookedUp);
    fromLastKnownSlot = new KeyList(lookedUp);
    fromSubscribers = new TreeMap<>();
    if (origUSK.suggestedEdition > lookedUp)
      fromSubscribers.put(origUSK.suggestedEdition, new KeyList(origUSK.suggestedEdition));
  }

  /** Bundles lookup descriptors to fetch immediately and to poll in the background. */
  static class ToFetch {

    /**
     * Creates a fetch plan from the provided lookup lists.
     *
     * @param toFetch2 lookups to fetch immediately; must not be null
     * @param toPoll2 lookups to poll without immediate fetch; must not be null
     */
    public ToFetch(List<Lookup> toFetch2, List<Lookup> toPoll2) {
      fetch = toFetch2.toArray(new Lookup[0]);
      poll = toPoll2.toArray(new Lookup[0]);
    }

    /** Lookups to fetch immediately. */
    public final Lookup[] fetch;

    /** Lookups to poll in background cycles. */
    public final Lookup[] poll;
  }

  /**
   * Get a bunch of editions to probe for.
   *
   * @param lookedUp The current best known slot, from USKManager.
   * @param random The random number generator.
   * @param alreadyRunning This will be modified: We will remove anything that should still be
   *     running from it.
   * @param doRandom whether to include random probes in the returned plan
   * @param isFirstLoop whether this is the first polling loop
   * @return Editions to fetch and editions to poll for.
   */
  public synchronized ToFetch getEditionsToFetch(
      long lookedUp,
      Random random,
      List<Lookup> alreadyRunning,
      boolean doRandom,
      boolean isFirstLoop) {

    if (LOG.isDebugEnabled())
      LOG.debug("Get editions to fetch, latest slot is {} running is {}", lookedUp, alreadyRunning);

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
        // add check for edition 0: this happens if -1 is suggested.
        // Needed because we cannot set -0 for exhaustive search (-0 == 0 in Java).
        entry.getValue().getEditionIfNotAlreadyRunning(toFetch, alreadyRunning, l, false);
      }
      entry.getValue().getNextEditions(toFetch, toPoll, l - 1, alreadyRunning);
    }
  }

  /**
   * Adds randomized edition probes to the fetch/poll lists.
   *
   * @param probeFromLastKnownGood whether to seed probes from the last known good slot
   * @param lookedUp current best-known slot used to bias sampling
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
          "Running random requests: {} total allowed: {} looked up is {} for {}",
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
   * Reconciles subscriber hints with current persisted and derived hints.
   *
   * @param hints latest subscriber hint values; must not be null
   * @param lookedUp current best-known slot used to discard stale hints
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
   * @param suggestedEdition edition number to add; must be greater than {@code lookedUp}
   * @param lookedUp current best-known slot used to ignore stale hints
   */
  public synchronized void addHintEdition(long suggestedEdition, long lookedUp) {
    if (suggestedEdition <= lookedUp) return;
    if (!persistentHints.add(suggestedEdition)) return;
    if (fromSubscribers.containsKey(suggestedEdition)) return;
    fromSubscribers.put(suggestedEdition, new KeyList(suggestedEdition));
  }

  /**
   * Estimates the number of watched keys based on current subscriber state.
   *
   * @return estimated count of watched keys for scheduling decisions
   */
  public synchronized long size() {
    return WATCH_KEYS + (long) fromSubscribers.size() * WATCH_KEYS; // Note: does not account for
    // overlap
  }

  /**
   * Builds datastore sub-checkers for the current watch lists.
   *
   * @param lastSlot last known good edition used to seed checks
   * @return datastore sub-checkers to run, or {@code null} when no checks are required
   */
  public synchronized List<KeyList.StoreSubChecker> getDatastoreCheckers(long lastSlot) {
    // Check WATCH_KEYS from last known good slot.
    // Note: does not currently take origUSK or subscribers into account.
    if (LOG.isDebugEnabled())
      LOG.debug("Getting datastore checker from {} for {}", lastSlot, origUSK);
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
   * @param block low-level block to decode; must not be null
   * @param edition edition number that the block is expected to represent
   * @return decoded client block for the edition
   * @throws SSKVerifyException if the block does not match the expected docname hash
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
   * @param key node key to match; must not be null
   * @param lastSlot last known good edition used to prune stale lists
   * @return matched edition number, or {@code -1} when no match is found
   */
  public synchronized long match(NodeSSK key, long lastSlot) {
    if (LOG.isDebugEnabled())
      LOG.debug("Trying to match {} from slot {} for {}", key, lastSlot, origUSK);
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
   * @param key candidate key to evaluate; must not be null
   * @param lastSlot last known good edition used to bound the match
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
   * @param key candidate key to evaluate; must not be null
   * @param lastSlot last known good edition used to bound the match
   * @return {@code true} if the key appears relevant
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
   * @param key key associated with the found block
   * @param found block returned from the datastore
   * @param lastSlot last known good edition used to bound the match
   * @return a matched block result, or {@code null} when no match was found
   */
  public MatchedBlock matchBlock(Key key, KeyBlock found, long lastSlot) {
    if (!(found instanceof SSKBlock sskBlock)) return null;
    if (!(key instanceof NodeSSK)) return null;
    long edition;
    synchronized (this) {
      edition = match((NodeSSK) key, lastSlot);
    }
    if (edition == -1) return null;
    if (LOG.isDebugEnabled()) LOG.debug("Matched edition {} for {}", edition, origUSK);

    ClientSSKBlock data;
    try {
      data = decode(sskBlock, edition);
    } catch (SSKVerifyException _) {
      data = null;
    }
    return new MatchedBlock(edition, data);
  }

  /** Describes a matched block and its edition. */
  record MatchedBlock(long edition, ClientSSKBlock block) {}

  /**
   * A precomputed list of E(H(docname))'s for each slot we might match. This is from an edition
   * number which might be out of date.
   */
  class KeyList {

    /** The USK edition number of the first slot */
    long firstSlot;

    /** The precomputed E(H(docname)) for each such slot. */
    private WeakReference<RemoveRangeArrayList<byte[]>> cache;

    /** We have checked the datastore from this point. */
    private long checkedDatastoreFrom = -1;

    /** We have checked the datastore up to this point. */
    private long checkedDatastoreTo = -1;

    /**
     * Creates a key list anchored at the provided slot.
     *
     * @param slot first slot to include in the cache
     */
    public KeyList(long slot) {
      if (LOG.isDebugEnabled())
        LOG.debug("Creating KeyList from {} on {} {}", slot, origUSK, this, new Exception("debug"));
      firstSlot = slot;
      RemoveRangeArrayList<byte[]> ehDocnames = new RemoveRangeArrayList<>(WATCH_KEYS);
      cache = new WeakReference<>(ehDocnames);
      generate(firstSlot, WATCH_KEYS, ehDocnames);
    }

    /**
     * Add the next set of editions to either {@code toFetch} or {@code toPoll}. If any of those
     * editions are already running, remove them from {@code alreadyRunning}.
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
      if (LOG.isDebugEnabled()) LOG.debug("Getting next editions from {}", lookedUp);
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
     * @param lookupList destination list for new lookups; entries are appended
     * @param alreadyRunning list of lookups already in progress; this method removes matches
     * @param ed edition number to add
     * @param ignoreStore whether this lookup should bypass store checks
     * @return whether the edition was added
     */
    public boolean getEditionIfNotAlreadyRunning(
        List<Lookup> lookupList, List<Lookup> alreadyRunning, long ed, boolean ignoreStore) {
      Lookup l = new Lookup();
      l.val = ed;
      l.label = origUSK.toString();
      if (lookupList.contains(l)) {
        if (LOG.isTraceEnabled()) LOG.trace("Ignoring {}", l);
        return false;
      }
      if (alreadyRunning.remove(l)) {
        if (LOG.isTraceEnabled()) LOG.trace("Ignoring (2): {}", l);
        return false;
      }
      ClientSSK key;
      // Note: consider reusing ehDocnames where feasible
      // The problem is we need a ClientSSK for the high level stuff.
      key = origUSK.getSSK(ed);
      l.key = key;
      l.ignoreStore = ignoreStore;
      if (lookupList.contains(l)) {
        if (LOG.isTraceEnabled()) LOG.trace("Ignoring (3): {}", l);
        return false;
      }
      return lookupList.add(l);
    }

    /**
     * Adds random edition probes to the provided list.
     *
     * @param toFetch destination list for random probes; entries are appended
     * @param lookedUp current best-known slot used as a base
     * @param alreadyRunning list of lookups already in progress; used for de-duplication
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
     * @param baseEdition base edition offset for sampling
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
     * @param toFetch destination list for random probes; entries are appended
     * @param lookedUp current best-known slot used for range decisions
     * @param alreadyRunning list of lookups already in progress; used for de-duplication
     * @param fetch sampled edition to add
     * @return {@code true} when the edition was added to the fetch list
     */
    private boolean tryAddRandomEdition(
        List<Lookup> toFetch, long lookedUp, List<Lookup> alreadyRunning, long fetch) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Trying random future edition {} for {} current edition {}", fetch, origUSK, lookedUp);
      return getEditionIfNotAlreadyRunning(
          toFetch, alreadyRunning, fetch, (fetch - lookedUp) < WATCH_KEYS);
    }

    /** Represents a sub-range of datastore keys to check. */
    public class StoreSubChecker {

      /** Keys to check */
      final NodeSSK[] keysToCheck;

      /** The edition from which we will have checked after we have executed this. */
      private final long checkedFrom;

      /** The edition up to which we have checked after we have executed this. */
      private final long checkedTo;

      /**
       * Creates a sub-checker for a contiguous range of editions.
       *
       * @param keysToCheck node keys to check; must not be null
       * @param checkFrom starting edition of the range
       * @param checkTo ending edition (exclusive) of the range
       */
      private StoreSubChecker(NodeSSK[] keysToCheck, long checkFrom, long checkTo) {
        this.keysToCheck = keysToCheck;
        this.checkedFrom = checkFrom;
        this.checkedTo = checkTo;
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Checking datastore from {} to {} for {} on {}", checkFrom, checkTo, origUSK, this);
      }

      /** The keys have been checked. */
      void checked() {
        synchronized (KeyList.this) {
          // Update the start bound only when the previous range does not already cover it.
          if (!(checkedDatastoreTo >= checkedFrom && checkedDatastoreFrom <= checkedFrom)) {
            checkedDatastoreFrom = checkedFrom;
          }
          checkedDatastoreTo = checkedTo;
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Checked from {} to {} (now overall is {} to {}) for {}",
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
     * <p>The method reuses and extends the cached document-name hashes as needed and returns a
     * sub-checker describing the keys to check in the datastore.
     *
     * @param lastSlot starting edition to check from
     * @return a sub-checker describing keys to check, or {@code null} when no work is needed
     */
    public synchronized StoreSubChecker checkStore(long lastSlot) {
      if (LOG.isDebugEnabled())
        LOG.debug("check store from {} current first slot {}", lastSlot, firstSlot);
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
     * @param curBaseEdition base edition used to realign the cache
     * @return updated cache containing hashes for the current window
     */
    synchronized RemoveRangeArrayList<byte[]> updateCache(long curBaseEdition) {
      if (LOG.isDebugEnabled())
        LOG.debug("update cache from {} current first slot {}", curBaseEdition, firstSlot);
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
     * @param key key to match, or {@code null} to only update the cache
     * @param curBaseEdition new base edition used to realign the cache
     * @return edition number for the key, or {@code -1} when not matched
     */
    public synchronized long match(NodeSSK key, long curBaseEdition) {
      if (LOG.isDebugEnabled())
        LOG.debug("match from {} current first slot {}", curBaseEdition, firstSlot);
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
     * @param key key to match; may be {@code null} to skip matching
     * @param curBaseEdition edition to align the cache with
     * @param ehDocnames cached document-name hashes to update
     * @return edition number for the key, or {@code -1} when not matched
     */
    private long match(NodeSSK key, long curBaseEdition, RemoveRangeArrayList<byte[]> ehDocnames) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Matching {} cur base edition {} first slot was {} for {} on {}",
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
        // There is some overlap. Delete the first part of the array then add stuff at the end.
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
        LOG.trace("Ignoring regression in match() from {} to {}", curBaseEdition, firstSlot);
      return key == null ? -1 : innerMatch(key, ehDocnames, 0, ehDocnames.size(), firstSlot);
    }

    /**
     * Matches a key against a slice of the cached hash list.
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
          if (LOG.isDebugEnabled()) LOG.debug("Found edition {} for {}", firstSlot + i, origUSK);
          return firstSlot + i;
        }
      }
      return -1;
    }

    /**
     * Appends a series of document-name hashes to the cache.
     *
     * @param baseEdition edition to start from
     * @param keys number of keys to add
     * @param ehDocnames cache to append to; must not be null
     */
    private void generate(long baseEdition, int keys, RemoveRangeArrayList<byte[]> ehDocnames) {
      if (LOG.isDebugEnabled()) LOG.debug("generate() from {} for {}", baseEdition, origUSK);
      assert (baseEdition >= 0);
      for (int i = 0; i < keys; i++) {
        long ed = baseEdition + i;
        ehDocnames.add(origUSK.getSSK(ed).ehDocname);
      }
    }
  }

  /** Describes a specific edition lookup and its derived key. */
  static class Lookup {
    /** Edition value represented by this lookup. */
    long val;

    /** Client SSK key derived for the edition. */
    ClientSSK key;

    /** Whether this lookup should bypass store checks. */
    boolean ignoreStore;

    /** Descriptive label for logging, usually the owning USK. */
    String label;

    /** Creates an empty lookup descriptor. */
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
