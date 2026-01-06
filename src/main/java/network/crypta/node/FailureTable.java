package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import network.crypta.io.comm.ByteCounter;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.NotConnectedException;
import network.crypta.io.xfer.BlockTransmitter;
import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.support.LRUMap;
import network.crypta.support.ListUtils;
import network.crypta.support.SerialExecutor;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Privacy note: Delete ULPR-related state (e.g., requestors) once a key is found. Keeping
// stale mappings would make it easier to correlate a request after compromise. Offers are
// authenticated using an HMAC carried with the offer.

// LOCKING: Always take the FailureTable lock first if you need both. Take the
// FailureTableEntry lock only for cheap internal operations to avoid deadlocks.

/**
 * Maintains recent failures and lightweight interest for keys to improve routing and enable
 * Ultra‑Lightweight Persistent Requests (ULPR).
 *
 * <p>The table records, per {@link Key}, where requests were routed and which peers expressed
 * interest (requestors). It enforces short-term refusal after a "DNF" (did not find) and, once a
 * key is found, offers the data to peers that recently asked for it. Time windows are bounded by
 * the constants in this class; values are in milliseconds unless otherwise stated.
 *
 * <p>Threading and locking: - Methods synchronize on the {@code FailureTable} instance when
 * mutating or consulting the main maps. Never acquire a {@link PeerNode} lock before calling into
 * this class; doing so can deadlock with callbacks that also touch {@code PeerNode}. - Disk I/O for
 * offer handling is serialized via a {@link SerialExecutor} to reduce latency spikes; network I/O
 * is scheduled onto separate threads when necessary.
 *
 * <p>Privacy: ULPR state associated with a key is dropped as soon as the key is found to avoid
 * making post‑compromise correlation easier.
 */
public class FailureTable {
  private static final Logger LOG = LoggerFactory.getLogger(FailureTable.class);

  /** FailureTableEntry's by key. Note that we push an entry only when sentTime changes. */
  private final LRUMap<Key, FailureTableEntry> entriesByKey;

  /** BlockOfferList by key. Synchronized on self, as it doesn't interact with the main FT. */
  private final LRUMap<Key, BlockOfferList> blockOfferListByKey;

  private final Node node;

  /** Maximum number of keys to track */
  static final int MAX_ENTRIES = 20 * 1000;

  /** Maximum number of offers to track */
  static final int MAX_OFFERS = 10 * 1000;

  /**
   * Terminate a request if there was a DNF on the same key less than this time ago. Maximum time
   * for any FailureTable i.e. for this period after a DNF, we will avoid the node that DNFed.
   */
  static final long REJECT_TIME = MINUTES.toMillis(3);

  static final long REJECT_TIME_BEFORE_BUILD_1498 = MINUTES.toMillis(5);

  /**
   * Maximum time for a RecentlyFailed. I.e. until this period expires, we take a request into
   * account when deciding whether we have recently failed to this peer. If we get a DNF, we use
   * this figure. If we get an RF, we use what it tells us, which can be less than this. Most other
   * failures use shorter periods.
   */
  static final long RECENTLY_FAILED_TIME = MINUTES.toMillis(5);

  static final long RECENTLY_FAILED_TIME_BEFORE_BUILD_1498 = MINUTES.toMillis(30);

  /** Offers expire after 10 minutes */
  static final long OFFER_EXPIRY_TIME = MINUTES.toMillis(10);

  /** HMAC key for the offer authenticator */
  final byte[] offerAuthenticatorKey;

  /** Clean up old data every 10 minutes to save memory and improve privacy */
  static final long CLEANUP_PERIOD = MINUTES.toMillis(10);

  /**
   * Creates a failure table bound to the provided node.
   *
   * @param node owning node instance
   */
  public FailureTable(Node node) {
    entriesByKey = LRUMap.createSafeMap();
    blockOfferListByKey = LRUMap.createSafeMap();
    this.node = node;
    offerAuthenticatorKey = new byte[32];
    node.bootstrap().random().nextBytes(offerAuthenticatorKey);
    offerExecutor = new SerialExecutor(NativeThread.PriorityLevel.HIGH_PRIORITY.value);
    node.network().ticker().queueTimedJob(new FailureTableCleaner(), CLEANUP_PERIOD);
  }

  /**
   * Starts the executor used to process offers. Call once during node startup after {@link Node}
   * has initialized its executors.
   */
  public void start() {
    offerExecutor.start(
        node.network().executor(),
        "FailureTable offers executor for " + node.network().darknetPortNumber());
  }

  /**
   * Records an intermediate failure while the request continues.
   *
   * <p>The timeouts are clamped to implementation limits. {@code rfTimeout} is the time window
   * during which the peer counts as recently failed; {@code ftTimeout} is the refusal window for
   * routing to the same peer for this key.
   *
   * <p>Locking: Do not hold a {@link PeerNode} lock when calling this method.
   *
   * @param key the requested key (non-null)
   * @param routedTo the peer that failed for this attempt
   * @param htl the HTL at the time of failure
   * @param rfTimeout recently-failed window in milliseconds; clamped to {@link
   *     #RECENTLY_FAILED_TIME}
   * @param ftTimeout refusal window in milliseconds; clamped to {@link #REJECT_TIME}
   */
  public void onFailed(Key key, PeerNode routedTo, short htl, long rfTimeout, long ftTimeout) {
    if (ftTimeout < 0 || ftTimeout > REJECT_TIME) {
      if (ftTimeout
          > REJECT_TIME_BEFORE_BUILD_1498) { // only log an error if the time is invalid for 1497,
        // too
        LOG.info("Bogus timeout ftTimeout={} ms; clamping", ftTimeout);
      }
      ftTimeout = Math.clamp(ftTimeout, 0, REJECT_TIME);
    }
    if (rfTimeout < 0 || rfTimeout > RECENTLY_FAILED_TIME) {
      if (rfTimeout
          > RECENTLY_FAILED_TIME_BEFORE_BUILD_1498) { // only log an error if the time is invalid
        // for 1497, too
        LOG.info("Bogus timeout rfTimeout={} ms; clamping", rfTimeout);
      }
      rfTimeout = Math.clamp(rfTimeout, 0, RECENTLY_FAILED_TIME);
    }
    if (!(node.isEnableULPRDataPropagation() || node.isEnablePerNodeFailureTables())) return;
    long now = System.currentTimeMillis();
    FailureTableEntry entry;
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) entry = new FailureTableEntry(key);
      entriesByKey.push(key, entry);
      // LOCKING: Taking PeerNode then FT/FTE will deadlock.
      // However, this should not happen.
      // We have to do this inside the lock to prevent race condition with the cleaner causing us to
      // get dropped because isEmpty() before updating.
      entry.failedTo(routedTo, rfTimeout, ftTimeout, now, htl);

      trimEntries();
    }
  }

  /**
   * Records a final failure and the requestor that originated the request.
   *
   * <p>Use this to avoid routing to {@code routedTo} for a short period and to remember the
   * requestor so the key can be offered back if later found elsewhere.
   *
   * <p>Ordering: Call before the surrounding request's {@code finish()} to ensure the bookkeeping
   * is not lost. Locking: Never synchronize on {@link PeerNode} before calling this method.
   *
   * @param key the requested key (non-null)
   * @param routedTo the peer that failed the request, or {@code null}
   * @param htl the HTL at failure
   * @param origHTL the original HTL at request creation (used for offer decisions)
   * @param rfTimeout recently-failed window in milliseconds; clamped to {@link
   *     #RECENTLY_FAILED_TIME}
   * @param ftTimeout refusal window in milliseconds; {@code -1} is a no-op; otherwise clamped to
   *     {@link #REJECT_TIME}
   * @param requestor the peer that originated the request, or {@code null}
   */
  public void onFinalFailure(
      Key key,
      PeerNode routedTo,
      short htl,
      short origHTL,
      long rfTimeout,
      long ftTimeout,
      PeerNode requestor) {
    if (ftTimeout < -1 || ftTimeout > REJECT_TIME) {
      // -1 is a valid no-op.
      LOG.info("Bogus timeout ftTimeout={} ms; clamping", ftTimeout);
      ftTimeout = Math.clamp(ftTimeout, 0, REJECT_TIME);
    }
    if (rfTimeout < 0 || rfTimeout > RECENTLY_FAILED_TIME) {
      if (rfTimeout > 0) LOG.info("Bogus timeout rfTimeout={} ms; clamping", rfTimeout);
      rfTimeout = Math.clamp(rfTimeout, 0, RECENTLY_FAILED_TIME);
    }
    if (!(node.isEnableULPRDataPropagation() || node.isEnablePerNodeFailureTables())) return;
    long now = System.currentTimeMillis();
    FailureTableEntry entry;
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) entry = new FailureTableEntry(key);
      entriesByKey.push(key, entry);

      // LOCKING: Taking PeerNode then FT/FTE will deadlock.
      // However, this should not happen.
      // We have to do this inside the lock to prevent race condition with the cleaner causing us to
      // get dropped because isEmpty() before updating.

      if (routedTo != null) entry.failedTo(routedTo, rfTimeout, ftTimeout, now, htl);
      if (requestor != null) entry.addRequestor(requestor, now, origHTL);

      trimEntries();
    }
  }

  private synchronized void trimEntries() {
    while (entriesByKey.size() > MAX_ENTRIES) {
      entriesByKey.popKey();
    }
  }

  // LOCKING: Synchronized on FailureTable because deleteOffer() may remove this list from the
  // outer map; do not hold PeerNode locks while operating on a BlockOfferList.
  private final class BlockOfferList {
    private BlockOffer[] offers;
    final FailureTableEntry entry;

    BlockOfferList(FailureTableEntry entry, BlockOffer offer) {
      this.entry = entry;
      this.offers = new BlockOffer[] {offer};
    }

    public long expires() {
      synchronized (blockOfferListByKey) {
        long last = 0;
        for (BlockOffer offer : offers) {
          if (offer.offeredTime > last) last = offer.offeredTime;
        }
        return last + OFFER_EXPIRY_TIME;
      }
    }

    public boolean isEmpty(long now) {
      synchronized (blockOfferListByKey) {
        for (BlockOffer offer : offers) {
          if (!offer.isExpired(now)) return false;
        }
        return true;
      }
    }

    public void deleteOffer(BlockOffer offer) {
      if (LOG.isDebugEnabled()) LOG.debug("Deleting {} from {}", offer, this);
      synchronized (blockOfferListByKey) {
        int idx = -1;
        final int offerLength = offers.length;
        for (int i = 0; i < offerLength; i++) {
          if (offers[i] == offer) idx = i;
        }
        if (idx < 0) return;
        BlockOffer[] newOffers = new BlockOffer[offerLength - 1];
        if (idx > 0) System.arraycopy(offers, 0, newOffers, 0, idx);
        if (idx < newOffers.length)
          System.arraycopy(offers, idx + 1, newOffers, idx, offers.length - idx - 1);
        offers = newOffers;
        if (offers.length > 1) return;
        blockOfferListByKey.removeKey(entry.key);
      }
      node.services().clientCore().dequeueOfferedKey(entry.key);
    }

    public void addOffer(BlockOffer offer) {
      synchronized (blockOfferListByKey) {
        offers = Arrays.copyOf(offers, offers.length + 1);
        offers[offers.length - 1] = offer;
      }
    }

    @Override
    public String toString() {
      return super.toString() + "(" + offers.length + ")";
    }
  }

  /**
   * A single offer for a key made by or to a peer.
   *
   * <p>Offers expire after {@link #OFFER_EXPIRY_TIME}. The peer is held via a {@link
   * WeakReference}; an offer becomes expired if the reference clears.
   */
  public static final class BlockOffer {
    final long offeredTime;

    /** Either offered by or offered to this node. */
    final WeakReference<PeerNode> nodeRef;

    /** Authenticator for the offer (HMAC or similar). */
    final byte[] authenticator;

    /** Node boot identifier at the time the offer was made. */
    final long bootID;

    BlockOffer(PeerNode pn, long now, byte[] authenticator, long bootID) {
      this.nodeRef = pn.myRef;
      this.offeredTime = now;
      this.authenticator = authenticator;
      this.bootID = bootID;
    }

    /**
     * Returns the peer associated with this offer.
     *
     * @return the peer, or {@code null} if it has been garbage collected
     */
    public PeerNode getPeerNode() {
      return nodeRef.get();
    }

    /**
     * Returns whether this offer is expired at a given time.
     *
     * @param now the current time in milliseconds since the epoch
     * @return {@code true} if the offer is no longer valid
     */
    public boolean isExpired(long now) {
      return nodeRef.get() == null || now > (offeredTime + OFFER_EXPIRY_TIME);
    }

    /**
     * Convenience overload using {@link System#currentTimeMillis()}.
     *
     * @return {@code true} if the offer is no longer valid now
     */
    public boolean isExpired() {
      return isExpired(System.currentTimeMillis());
    }
  }

  /**
   * Notifies the table that a block was found and should be offered to recent requestors.
   *
   * <p>This removes any stale offer lists associated with the key and, when ULPR is enabled,
   * schedules offers to peers that recently asked for it. Locking: do not hold a {@link PeerNode}
   * lock when calling; schedule off-thread if other locks are held.
   *
   * @param block the located {@link KeyBlock}
   */
  public void onFound(KeyBlock block) {
    if (LOG.isDebugEnabled()) LOG.debug("Found {}", block.getKey());
    if (!(node.isEnableULPRDataPropagation() || node.isEnablePerNodeFailureTables())) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Ignoring onFound because enable ULPR = {} and enable failure tables = {}",
            node.isEnableULPRDataPropagation(),
            node.isEnablePerNodeFailureTables());
      return;
    }
    Key key = block.getKey();
    if (key == null) throw new NullPointerException();
    FailureTableEntry entry;
    synchronized (blockOfferListByKey) {
      blockOfferListByKey.removeKey(key);
    }
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) {
        if (LOG.isDebugEnabled()) LOG.debug("Key not found in entriesByKey");
        return; // Nobody cares
      }
      entriesByKey.removeKey(key);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Offering key");
    if (!node.isEnableULPRDataPropagation()) return;
    entry.offer();
  }

  /**
   * Executes {@code onOffer()} tasks on a dedicated executor. Disk I/O is performed on this
   * executor to avoid latency spikes; network I/O is delegated to separate threads when needed.
   */
  private final SerialExecutor offerExecutor;

  /**
   * Handles an incoming offer for a key.
   *
   * <p>For SSKs we only accept if we previously requested the key; for CHKs we may accept based on
   * recent interest.
   *
   * @param key the offered key
   * @param peer the offering peer
   * @param authenticator an authenticator carried with the offer
   */
  void onOffer(final Key key, final PeerNode peer, final byte[] authenticator) {
    if (!node.isEnableULPRDataPropagation()) return;
    if (LOG.isDebugEnabled()) LOG.debug("Offered key {} by peer {}", key, peer);
    FailureTableEntry entry;
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) {
        if (LOG.isDebugEnabled()) LOG.debug("We didn't ask for the key");
        return; // we haven't asked for it
      }
    }
    offerExecutor.execute(() -> innerOnOffer(key, peer, authenticator), "onOffer()");
  }

  /**
   * Processes a validated offer on the {@link #offerExecutor} thread.
   *
   * <p>Blocking disk I/O occurs on this thread to keep ordering predictable; blocking network I/O
   * is scheduled separately.
   *
   * @param key the offered key
   * @param peer the offering peer
   * @param authenticator an authenticator carried with the offer
   */
  protected void innerOnOffer(Key key, PeerNode peer, byte[] authenticator) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Inner on offer for {} from {} on {}", key, peer, node.network().darknetPortNumber());
    if (key.getRoutingKey() == null) throw new NullPointerException();
    // NB: node.storage().hasKey() executes a datastore fetch
    // If we have the key in the datastore (store or cache), we don't want it.
    // If we have the key in the client cache, we might want it for other nodes,
    // although hopefully the client layer was tripped when we got it.
    if (node.storage().hasKey(key, false, true)) {
      LOG.debug("Already have key");
      return;
    }

    // Re-check after potentially long disk I/O.
    FailureTableEntry entry;
    long now = System.currentTimeMillis();
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) {
        if (LOG.isDebugEnabled()) LOG.debug("We didn't ask for the key");
        return; // we haven't asked for it
      }
    }

    /*
     * Accept (subject to later checks) if we asked for it.
     * Should we accept it if we were asked for it? This is "bidirectional propagation".
     * It's good because it makes the whole structure much more reliable; it's bad because
     * it's not entirely under our control - we didn't choose to route it to the node, the node
     * routed it to us. Now it's found it before we did...
     *
     * Attacks:
     * - Frost spamming etc.: Is it easier to offer data to our peers rather than inserting it? Will
     * it result in it being propagated further? The peer node would then do the request, rather than
     * this node doing an insert. Is that beneficial?
     *
     * Not relevant with CHKs anyway.
     *
     * On the plus side, propagation to nodes that have asked is worthwhile because reduced polling
     * cost enables more secure messaging systems e.g. outbox polling...
     * - Social engineering: If a key is unpopular, you can put a different copy of it on different
     * nodes. You can then use this to trace the requestor - identify that he is or isn't on the target.
     * You can't do this with a regular insert because it will often go several nodes even at htl 0.
     * With subscriptions, you might be able to bypass this - but only if you know no other nodes in the
     * neighbourhood are subscribed. Easier with SSKs; with CHKs you have only binary information of
     * whether the person got the key (with social engineering). Hard to exploit on darknet; if you're
     * that close to the suspect there are easier ways to get at them e.g. correlation attacks.
     *
     * Conclusion: We should accept the request if:
     * - We asked for it from that node. (Note that a node might both have asked us and been asked).
     * - That node asked for it, and it's a CHK.
     */

    boolean weAsked = entry.askedFromPeer(peer, now);
    boolean heAsked = entry.askedByPeer(peer, now);
    if (!either(weAsked, heAsked)) {
      if (LOG.isDebugEnabled())
        //noinspection ConstantValue
        LOG.debug("Not propagating key: weAsked={} heAsked={}", weAsked, heAsked);
      removeEntryIfEmpty(entry, key);
      return;
    }
    removeEntryIfEmpty(entry, key);

    // Valid offer.

    // Add to offers list

    synchronized (blockOfferListByKey) {
      if (LOG.isDebugEnabled()) LOG.debug("Valid offer");
      BlockOfferList bl = blockOfferListByKey.get(key);
      BlockOffer offer = new BlockOffer(peer, now, authenticator, peer.getBootID());
      if (bl == null) {
        bl = new BlockOfferList(entry, offer);
      } else {
        bl.addOffer(offer);
      }
      blockOfferListByKey.push(key, bl);
      trimOffersList(now);
    }

    // Accept the offer.
    // Either a peer wants it, in which case we want it for them,
    // or we want it, or we have requested it in the past, in which case
    // we will probably want it in the future.
    // Note: Queuing offered keys as realtime may be unsafe for similar reasons to
    // prioritization; if enabling, consider doing so only at low priorities.
    node.services().clientCore().queueOfferedKey(key, false);
  }

  private void trimOffersList(long now) {
    synchronized (blockOfferListByKey) {
      while (true) {
        if (blockOfferListByKey.isEmpty()) return;
        BlockOfferList bl = blockOfferListByKey.peekValue();
        if (bl == null) {
          // Defensive: map reported non-empty but has no head value; drop head key.
          blockOfferListByKey.popKey();
          continue;
        }
        if (bl.isEmpty(now) || bl.expires() < now || blockOfferListByKey.size() > MAX_OFFERS) {
          if (LOG.isDebugEnabled())
            LOG.debug(
                "Removing block offer list {} list size now {}", bl, blockOfferListByKey.size());
          blockOfferListByKey.popKey();
        } else {
          return;
        }
      }
    }
  }

  private static boolean either(boolean a, boolean b) {
    return a || b;
  }

  private void removeEntryIfEmpty(FailureTableEntry entry, Key key) {
    if (entry.isEmpty()) {
      synchronized (this) {
        entriesByKey.removeKey(key);
      }
    }
  }

  /**
   * Sends data for a previously offered key in response to a peer request.
   *
   * <p>Runs the heavy work on the offers executor; always releases {@code tag}'s lock before
   * returning from the asynchronous task.
   *
   * @param key the key to send
   * @param isSSK whether the key is an SSK
   * @param needPubKey whether to send the publisher key (SSK only)
   * @param uid the per-request UID used on the wire
   * @param source the requesting peer
   * @param tag unlock handler associated with this send
   * @param realTimeFlag whether to mark payload packets as realtime
   * @throws NotConnectedException if the sender is no longer connected
   */
  @SuppressWarnings("java:S1181")
  public void sendOfferedKey(
      final Key key,
      final boolean isSSK,
      final boolean needPubKey,
      final long uid,
      final PeerNode source,
      final OfferReplyTag tag,
      final boolean realTimeFlag)
      throws NotConnectedException {
    this.offerExecutor.execute(
        () -> {
          try {
            innerSendOfferedKey(key, isSSK, needPubKey, uid, source, tag, realTimeFlag);
          } catch (NotConnectedException _) {
            tag.unlockHandler();
            // Too bad.
          } catch (Throwable t) {
            tag.unlockHandler();
            LOG.error("Caught {} sending offered key", t, t);
          }
        },
        "sendOfferedKey");
  }

  /**
   * Implements the send logic on the {@link #offerExecutor} thread.
   *
   * <p>Performs datastore fetches and emits the appropriate DMT messages. Network sends that may
   * block are delegated to the node executor.
   *
   * @param key the key to send
   * @param isSSK whether the key is an SSK
   * @param needPubKey whether to include the publisher key (SSK only)
   * @param uid the per-request UID used on the wire
   * @param source the requesting peer
   * @param tag unlock handler associated with this send
   * @param realTimeFlag whether to mark payload packets as realtime
   * @throws NotConnectedException if the sender is no longer connected
   */
  protected void innerSendOfferedKey(
      Key key,
      final boolean isSSK,
      boolean needPubKey,
      final long uid,
      final PeerNode source,
      final OfferReplyTag tag,
      final boolean realTimeFlag)
      throws NotConnectedException {
    if (isSSK) {
      SSKBlock block = node.storage().fetch((NodeSSK) key, false, false, false, false, true, null);
      if (block == null) {
        // Don't have the key
        source
            .transport()
            .sendAsync(
                DMT.createFNPGetOfferedKeyInvalid(uid, DMT.GET_OFFERED_KEY_REJECTED_NO_KEY),
                null,
                senderCounter);
        tag.unlockHandler();
        return;
      }

      final Message data = DMT.createFNPSSKDataFoundData(uid, block.getRawData(), realTimeFlag);
      Message headers = DMT.createFNPSSKDataFoundHeaders(uid, block.getRawHeaders(), realTimeFlag);
      final int dataLength = block.getRawData().length;

      source.transport().sendAsync(headers, null, senderCounter);

      node.network()
          .executor()
          .execute(
              new PrioRunnable() {

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
                }

                @Override
                public void run() {
                  try {
                    source.transport().sendSync(data, senderCounter, realTimeFlag);
                    senderCounter.sentPayload(dataLength);
                  } catch (NotConnectedException | SyncSendWaitedTooLongException _) {
                    // Ignored
                  } finally {
                    tag.unlockHandler();
                  }
                }
              },
              "Send offered SSK");

      if (needPubKey) {
        Message pk = DMT.createFNPSSKPubKey(uid, block.getPubKey(), realTimeFlag);
        source.transport().sendAsync(pk, null, senderCounter);
      }
    } else {
      CHKBlock block = node.storage().fetch((NodeCHK) key, false, false, false, false, true, null);
      if (block == null) {
        // Don't have the key
        source
            .transport()
            .sendAsync(
                DMT.createFNPGetOfferedKeyInvalid(uid, DMT.GET_OFFERED_KEY_REJECTED_NO_KEY),
                null,
                senderCounter);
        tag.unlockHandler();
        return;
      }
      Message df = DMT.createFNPCHKDataFound(uid, block.getRawHeaders());
      source.transport().sendAsync(df, null, senderCounter);
      PartiallyReceivedBlock prb =
          new PartiallyReceivedBlock(Node.PACKETS_IN_BLOCK, Node.PACKET_SIZE, block.getRawData());
      final BlockTransmitter bt =
          new BlockTransmitter(
              node.network().usm(),
              node.network().ticker(),
              source,
              uid,
              prb,
              senderCounter,
              BlockTransmitter.NEVER_CASCADE,
              success -> tag.unlockHandler(),
              realTimeFlag,
              node.network().stats());
      node.network()
          .executor()
          .execute(
              new PrioRunnable() {

                @Override
                public int getPriority() {
                  return NativeThread.PriorityLevel.HIGH_PRIORITY.value;
                }

                @Override
                public void run() {
                  bt.sendAsync();
                }
              },
              "CHK offer sender");
    }
  }

  /**
   * Byte counter used for accounting of offered-key traffic.
   *
   * <p>Updates node statistics for bytes sent/received and offsets payload bytes from the
   * sender-side accounting.
   */
  public final ByteCounter senderCounter = new OfferedKeysByteCounter();

  class OfferedKeysByteCounter implements ByteCounter {

    @Override
    public void receivedBytes(int x) {
      node.network().stats().offeredKeysSenderReceivedBytes(x);
    }

    @Override
    public void sentBytes(int x) {
      node.network().stats().offeredKeysSenderSentBytes(x);
    }

    @Override
    public void sentPayload(int x) {
      node.sentPayload(x);
      node.network().stats().offeredKeysSenderSentBytes(-x);
    }
  }

  /**
   * Read-only view over the offers for a key with helpers to iterate and retire items.
   *
   * <p>Instances split the current list into recent and expired offers at construction time. Calls
   * to {@link #getFirstOffer()} return one offer at a time; use {@link #deleteLastOffer()} after a
   * successful attempt or {@link #keepLastOffer()} to release the claim without deletion.
   */
  public class OfferList {

    OfferList(BlockOfferList offerList) {
      this.blockOffers = offerList;
      recentOffers = new ArrayList<>();
      expiredOffers = new ArrayList<>();
      long now = System.currentTimeMillis();
      for (BlockOffer offer : blockOffers.offers) {
        if (!offer.isExpired(now)) recentOffers.add(offer);
        else expiredOffers.add(offer);
      }
      if (LOG.isDebugEnabled())
        LOG.debug("Offers: {} recent {} expired", recentOffers.size(), expiredOffers.size());
    }

    private final BlockOfferList blockOffers;

    private final List<BlockOffer> recentOffers;
    private final List<BlockOffer> expiredOffers;

    /** The last offer we returned */
    private BlockOffer lastOffer;

    /**
     * Returns an offer to try next.
     *
     * @return a recent or expired offer, or {@code null} if none remain
     * @throws IllegalStateException if the previous offer has not been released via {@link
     *     #deleteLastOffer()} or {@link #keepLastOffer()}
     */
    public BlockOffer getFirstOffer() {
      if (lastOffer != null) {
        throw new IllegalStateException("Last offer not dealt with");
      }
      if (!recentOffers.isEmpty()) {
        lastOffer = ListUtils.removeRandomBySwapLastSimple(node.bootstrap().random(), recentOffers);
        return lastOffer;
      }
      if (!expiredOffers.isEmpty()) {
        lastOffer =
            ListUtils.removeRandomBySwapLastSimple(node.bootstrap().random(), expiredOffers);
        return lastOffer;
      }
      // No more offers.
      return null;
    }

    /** Delete the last returned offer; call after success or an unrecoverable failure. */
    public void deleteLastOffer() {
      blockOffers.deleteOffer(lastOffer);
      lastOffer = null;
    }

    /** Releases the claim on the last returned offer without deleting it so it may be retried. */
    public void keepLastOffer() {
      lastOffer = null;
    }
  }

  /**
   * Returns whether any offers exist for the given key.
   *
   * @param key the key to check
   * @return {@code true} if there are any offers, {@code false} otherwise
   */
  public boolean hadAnyOffers(Key key) {
    synchronized (blockOfferListByKey) {
      return blockOfferListByKey.get(key) != null;
    }
  }

  /**
   * Returns an {@link OfferList} view for the given key, or {@code null} when there are no offers
   * or ULPR propagation is disabled.
   *
   * @param key the key to query
   * @return an offer iterator, or {@code null}
   */
  public OfferList getOffers(Key key) {
    if (!node.isEnableULPRDataPropagation()) return null;
    BlockOfferList bl;
    synchronized (blockOfferListByKey) {
      bl = blockOfferListByKey.get(key);
      if (bl == null) return null;
    }
    return new OfferList(bl);
  }

  /**
   * Called when a peer disconnects. Currently, a no-op reserved for future cleanup hooks.
   *
   * @param pn the peer that disconnected (may be {@code null})
   */
  public void onDisconnect(final PeerNode pn) {
    if (pn != null && LOG.isTraceEnabled()) {
      LOG.trace("onDisconnect {}", pn);
    }
    // Intentionally no-op. If this becomes expensive, schedule off-thread work.
  }

  /**
   * Returns the timeouts list for a key if per-node failure tables are enabled.
   *
   * @param key the key to query
   * @return a {@link TimedOutNodesList}, or {@code null} if disabled or absent
   */
  public TimedOutNodesList getTimedOutNodesList(Key key) {
    if (!node.isEnablePerNodeFailureTables()) return null;
    synchronized (this) {
      return entriesByKey.get(key);
    }
  }

  /** Periodic cleanup task that prunes expired entries and reschedules itself. */
  @SuppressWarnings("java:S1181")
  public class FailureTableCleaner implements Runnable {

    @Override
    public void run() {
      try {
        realRun();
      } catch (Throwable t) {
        LOG.error("FailureTableCleaner caught {}", t, t);
      } finally {
        node.network().ticker().queueTimedJob(this, CLEANUP_PERIOD);
      }
    }

    private void realRun() {
      if (LOG.isDebugEnabled()) LOG.debug("Starting FailureTable cleanup");
      long startTime = System.currentTimeMillis();
      FailureTableEntry[] entries;
      synchronized (FailureTable.this) {
        entries = new FailureTableEntry[entriesByKey.size()];
        entriesByKey.valuesToArray(entries);
      }
      for (FailureTableEntry entry : entries) {
        if (entry.cleanup()) {
          synchronized (FailureTable.this) {
            if (entry.isEmpty()) {
              if (LOG.isDebugEnabled()) LOG.debug("Removing entry for {}", entry.key);
              entriesByKey.removeKey(entry.key);
            }
          }
        }
      }
      long endTime = System.currentTimeMillis();
      if (LOG.isDebugEnabled())
        LOG.debug("Finished FailureTable cleanup took {}ms", endTime - startTime);
    }
  }

  /**
   * Returns whether any peer other than {@code apartFrom} has recently requested {@code key}.
   *
   * @param key the key to check
   * @param apartFrom an optional peer to exclude from the check
   * @return {@code true} if another peer wants the key
   */
  public boolean peersWantKey(Key key, PeerNode apartFrom) {
    FailureTableEntry entry;
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) return false; // Nobody cares
    }
    if (apartFrom == null) {
      return entry.othersWant();
    }
    long now = System.currentTimeMillis();
    return entry.othersWantExcept(apartFrom, now);
  }

  /**
   * Returns the minimum HTL recently observed among requestors for the key.
   *
   * @param key the key to query
   * @param htl a default HTL to return when no requestors exist
   * @return the lowest HTL seen, or {@code htl} if none
   */
  public short minOfferedHTL(Key key, short htl) {
    FailureTableEntry entry;
    synchronized (this) {
      entry = entriesByKey.get(key);
      if (entry == null) return htl;
    }
    return entry.minRequestorHTL(htl);
  }
}
