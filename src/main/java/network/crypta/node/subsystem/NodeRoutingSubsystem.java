package network.crypta.node.subsystem;

import network.crypta.io.xfer.PartiallyReceivedBlock;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.node.CHKInsertSender;
import network.crypta.node.FailureTable;
import network.crypta.node.InsertTag;
import network.crypta.node.Location;
import network.crypta.node.Node;
import network.crypta.node.PeerNode;
import network.crypta.node.RequestSender;
import network.crypta.node.RequestTag;
import network.crypta.node.RequestTracker;
import network.crypta.node.SSKInsertSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Routing subsystem facade (request/insert senders, failure tables). */
public final class NodeRoutingSubsystem {
  private static final Logger LOG = LoggerFactory.getLogger(NodeRoutingSubsystem.class);

  private final Node node;
  private RequestTracker tracker;
  private FailureTable failureTable;
  private boolean decrementAtMax;
  private boolean decrementAtMin;

  public NodeRoutingSubsystem(Node node) {
    this.node = node;
  }

  public void init() {
    tracker = new RequestTracker(node.network().peers(), node.network().ticker());
    failureTable = new FailureTable(node);
  }

  public void initDecrementPolicy() {
    decrementAtMax = node.bootstrap().random().nextDouble() <= Node.DECREMENT_AT_MAX_PROB;
    decrementAtMin = node.bootstrap().random().nextDouble() <= Node.DECREMENT_AT_MIN_PROB;
  }

  /**
   * Determines whether a block should be stored in the main store (deep) rather than a cache.
   *
   * <p>The decision is based on relative proximity to the target key compared with the source and
   * the set of peers the request was routed to, discounting low‑uptime peers.
   *
   * @param key the key being inserted or fetched.
   * @param source the previous hop (may be {@code null} for local originators).
   * @param routedTo peers selected for onward routing of the request.
   * @return {@code true} if the node is closer to the target than the considered peers and should
   *     therefore store deeply; {@code false} otherwise.
   */
  public boolean shouldStoreDeep(Key key, PeerNode source, PeerNode[] routedTo) {
    double myLoc = node.network().location();
    double target = key.toNormalizedDouble();
    double myDist = Location.distance(myLoc, target);

    if (LOG.isDebugEnabled()) LOG.debug("Should store for {} ?", key);
    if (isCloserAndHighUptime(source, target, myDist)) {
      if (LOG.isDebugEnabled())
        LOG.debug("Not storing because source is closer to target for {} : {}", key, source);
      return false;
    }
    for (PeerNode pn : routedTo) {
      if (isCloserAndHighUptime(pn, target, myDist)) {
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Not storing because peer {} is closer to target for {} his loc {} my loc {} target"
                  + " is {}",
              pn,
              key,
              pn.getLocation(),
              myLoc,
              target);
        return false;
      }
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Should store maybe, peer {} loc = {} my loc is {} target is {} low uptime is {}",
            pn,
            pn.getLocation(),
            myLoc,
            target,
            pn.isLowUptime());
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Should store returning true for {} target={} myLoc={} peers: {}",
          key,
          target,
          myLoc,
          routedTo.length);
    return true;
  }

  private boolean isCloserAndHighUptime(PeerNode pn, double target, double myDist) {
    if (pn == null || pn.isLowUptime()) return false;
    return Location.distance(pn, target) < myDist;
  }

  public RequestTracker tracker() {
    return tracker;
  }

  public FailureTable failureTable() {
    return failureTable;
  }

  public record RequestSenderOptions(
      boolean localOnly,
      boolean ignoreStore,
      boolean offersOnly,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean realTimeFlag) {

    public static RequestSenderOptions of(
        boolean localOnly,
        boolean ignoreStore,
        boolean offersOnly,
        boolean canReadClientCache,
        boolean canWriteClientCache,
        boolean realTimeFlag) {
      return new RequestSenderOptions(
          localOnly,
          ignoreStore,
          offersOnly,
          canReadClientCache,
          canWriteClientCache,
          realTimeFlag);
    }
  }

  public Object makeRequestSender(
      Key key, short htl, long uid, RequestTag tag, PeerNode source, RequestSenderOptions opts) {
    boolean canWriteDatastore = canWriteDatastoreRequest(htl);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "makeRequestSender({},{},{},{}) on {}",
          key,
          htl,
          uid,
          source,
          node.network().darknetPortNumber());
    boolean localOnly = opts.localOnly();
    boolean ignoreStore = opts.ignoreStore();
    boolean offersOnly = opts.offersOnly();
    boolean canReadClientCache = opts.canReadClientCache();
    boolean canWriteClientCache = opts.canWriteClientCache();
    boolean realTimeFlag = opts.realTimeFlag();

    if (!ignoreStore) {
      KeyBlock kb =
          makeRequestLocal(
              key, uid, canReadClientCache, canWriteClientCache, canWriteDatastore, offersOnly);
      if (kb != null) return kb;
    }
    if (localOnly) return null;
    if (LOG.isDebugEnabled()) LOG.debug("Not in store locally");

    RequestSender existing = findCoalescedSender(key, realTimeFlag);
    if (existing != null) {
      existing.setTransferCoalesced();
      tag.setSender(existing, true);
      return existing;
    }

    if (htl == 0) {
      if (LOG.isDebugEnabled()) LOG.debug("No HTL");
      return null;
    }

    RequestSender created =
        new RequestSender(
            key,
            null,
            htl,
            uid,
            tag,
            node,
            source,
            offersOnly,
            canWriteClientCache,
            canWriteDatastore,
            realTimeFlag);
    tag.setSender(created, false);
    created.start();
    if (LOG.isDebugEnabled()) LOG.debug("Created new sender: {}", created);
    return created;
  }

  private RequestSender findCoalescedSender(Key key, boolean realTimeFlag) {
    if (key instanceof NodeCHK nchk)
      return tracker.getTransferringRequestSenderByKey(nchk, realTimeFlag);
    return null;
  }

  private KeyBlock makeRequestLocal(
      Key key,
      long uid,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean offersOnly) {
    if (key instanceof NodeCHK chk) {
      return node.storage()
          .fetch(
              chk,
              true,
              canReadClientCache,
              canWriteClientCache,
              canWriteDatastore,
              offersOnly,
              null);
    } else {
      return tryFetchLocalForSSK(
          (NodeSSK) key,
          uid,
          canReadClientCache,
          canWriteClientCache,
          canWriteDatastore,
          offersOnly);
    }
  }

  private KeyBlock tryFetchLocalForSSK(
      NodeSSK key,
      long uid,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean offersOnly) {
    SSKBlock kb =
        node.storage()
            .fetch(
                key,
                true,
                canReadClientCache,
                canWriteClientCache,
                canWriteDatastore,
                offersOnly,
                null);
    if (kb != null) {
      tripPendingSchedulers(kb);
    }
    return kb;
  }

  private void tripPendingSchedulers(KeyBlock kb) {
    if (node.services().clientCore() == null
        || node.services().clientCore().getRequestStarters() == null) return;
    if (kb instanceof CHKBlock chk) {
      node.services().clientCore().getRequestStarters().chkFetchSchedulerBulk.tripPendingKey(chk);
      node.services().clientCore().getRequestStarters().chkFetchSchedulerRT.tripPendingKey(chk);
    } else if (kb instanceof SSKBlock ssk) {
      node.services().clientCore().getRequestStarters().sskFetchSchedulerBulk.tripPendingKey(ssk);
      node.services().clientCore().getRequestStarters().sskFetchSchedulerRT.tripPendingKey(ssk);
    }
  }

  public boolean canWriteDatastoreRequest(short htl) {
    return htl <= (node.maxHTL() - 2);
  }

  public boolean canWriteDatastoreInsert(short htl) {
    return htl <= (node.maxHTL() - 3);
  }

  public short decrementHTL(PeerNode source, short htl) {
    if (source != null) return source.decrementHTL(htl);
    if (htl >= node.maxHTL()) htl = node.maxHTL();
    if (htl <= 0) {
      return 0;
    }
    if (htl == node.maxHTL()) {
      if (decrementAtMax || node.isDisableProbabilisticHTLs()) htl--;
      return htl;
    }
    if (htl == 1) {
      if (decrementAtMin || node.isDisableProbabilisticHTLs()) htl--;
      return htl;
    }
    return --htl;
  }

  public static final class ChkInsertOptions {
    public final byte[] headers;
    public final PartiallyReceivedBlock prb;
    public final boolean fromStore;
    public final boolean canWriteClientCache;
    public final boolean forkOnCacheable;
    public final boolean preferInsert;
    public final boolean ignoreLowBackoff;
    public final boolean realTimeFlag;

    @SuppressWarnings("PointlessBitwiseExpression")
    private static final int F_FROM_STORE = 1 << 0;

    private static final int F_CAN_WRITE_CLIENT_CACHE = 1 << 1;
    private static final int F_FORK_ON_CACHEABLE = 1 << 2;
    private static final int F_PREFER_INSERT = 1 << 3;
    private static final int F_IGNORE_LOW_BACKOFF = 1 << 4;
    private static final int F_REALTIME = 1 << 5;

    private ChkInsertOptions(byte[] headers, PartiallyReceivedBlock prb, int flags) {
      this.headers = headers;
      this.prb = prb;
      this.fromStore = (flags & F_FROM_STORE) != 0;
      this.canWriteClientCache = (flags & F_CAN_WRITE_CLIENT_CACHE) != 0;
      this.forkOnCacheable = (flags & F_FORK_ON_CACHEABLE) != 0;
      this.preferInsert = (flags & F_PREFER_INSERT) != 0;
      this.ignoreLowBackoff = (flags & F_IGNORE_LOW_BACKOFF) != 0;
      this.realTimeFlag = (flags & F_REALTIME) != 0;
    }

    public static ChkInsertOptions of(byte[] headers, PartiallyReceivedBlock prb) {
      return new ChkInsertOptions(headers, prb, 0);
    }

    private ChkInsertOptions withFlag(int flag, boolean value) {
      int current = 0;
      if (fromStore) current |= F_FROM_STORE;
      if (canWriteClientCache) current |= F_CAN_WRITE_CLIENT_CACHE;
      if (forkOnCacheable) current |= F_FORK_ON_CACHEABLE;
      if (preferInsert) current |= F_PREFER_INSERT;
      if (ignoreLowBackoff) current |= F_IGNORE_LOW_BACKOFF;
      if (realTimeFlag) current |= F_REALTIME;
      int updated = value ? (current | flag) : (current & ~flag);
      return new ChkInsertOptions(headers, prb, updated);
    }

    public ChkInsertOptions withFromStore(boolean v) {
      return withFlag(F_FROM_STORE, v);
    }

    public ChkInsertOptions withCanWriteClientCache(boolean v) {
      return withFlag(F_CAN_WRITE_CLIENT_CACHE, v);
    }

    public ChkInsertOptions withForkOnCacheable(boolean v) {
      return withFlag(F_FORK_ON_CACHEABLE, v);
    }

    public ChkInsertOptions withPreferInsert(boolean v) {
      return withFlag(F_PREFER_INSERT, v);
    }

    public ChkInsertOptions withIgnoreLowBackoff(boolean v) {
      return withFlag(F_IGNORE_LOW_BACKOFF, v);
    }

    public ChkInsertOptions withRealTimeFlag(boolean v) {
      return withFlag(F_REALTIME, v);
    }
  }

  public CHKInsertSender makeInsertSender(
      NodeCHK key, short htl, long uid, InsertTag tag, PeerNode source, ChkInsertOptions opts) {
    if (LOG.isDebugEnabled())
      LOG.debug("makeInsertSender({},{},{},{},...,{}", key, htl, uid, source, opts.fromStore);
    CHKInsertSender is;
    is =
        new CHKInsertSender(
            key,
            uid,
            tag,
            opts.headers,
            htl,
            source,
            node,
            opts.prb,
            opts.fromStore,
            opts.forkOnCacheable,
            opts.preferInsert,
            opts.ignoreLowBackoff,
            opts.realTimeFlag);
    is.start();
    return is;
  }

  public static final class SskInsertOptions {
    public final boolean fromStore;
    public final boolean canWriteClientCache;
    public final boolean canWriteDatastore;
    public final boolean forkOnCacheable;
    public final boolean preferInsert;
    public final boolean ignoreLowBackoff;
    public final boolean realTimeFlag;

    @SuppressWarnings("PointlessBitwiseExpression")
    private static final int F_FROM_STORE = 1 << 0;

    private static final int F_CAN_WRITE_CLIENT_CACHE = 1 << 1;
    private static final int F_CAN_WRITE_DATASTORE = 1 << 2;
    private static final int F_FORK_ON_CACHEABLE = 1 << 3;
    private static final int F_PREFER_INSERT = 1 << 4;
    private static final int F_IGNORE_LOW_BACKOFF = 1 << 5;
    private static final int F_REALTIME = 1 << 6;

    private SskInsertOptions(int flags) {
      this.fromStore = (flags & F_FROM_STORE) != 0;
      this.canWriteClientCache = (flags & F_CAN_WRITE_CLIENT_CACHE) != 0;
      this.canWriteDatastore = (flags & F_CAN_WRITE_DATASTORE) != 0;
      this.forkOnCacheable = (flags & F_FORK_ON_CACHEABLE) != 0;
      this.preferInsert = (flags & F_PREFER_INSERT) != 0;
      this.ignoreLowBackoff = (flags & F_IGNORE_LOW_BACKOFF) != 0;
      this.realTimeFlag = (flags & F_REALTIME) != 0;
    }

    public static SskInsertOptions of() {
      return new SskInsertOptions(0);
    }

    private int currentFlags() {
      int f = 0;
      if (fromStore) f |= F_FROM_STORE;
      if (canWriteClientCache) f |= F_CAN_WRITE_CLIENT_CACHE;
      if (canWriteDatastore) f |= F_CAN_WRITE_DATASTORE;
      if (forkOnCacheable) f |= F_FORK_ON_CACHEABLE;
      if (preferInsert) f |= F_PREFER_INSERT;
      if (ignoreLowBackoff) f |= F_IGNORE_LOW_BACKOFF;
      if (realTimeFlag) f |= F_REALTIME;
      return f;
    }

    private SskInsertOptions withFlag(int flag, boolean v) {
      int f = currentFlags();
      int updated = v ? (f | flag) : (f & ~flag);
      return new SskInsertOptions(updated);
    }

    public SskInsertOptions withFromStore(boolean v) {
      return withFlag(F_FROM_STORE, v);
    }

    public SskInsertOptions withCanWriteClientCache(boolean v) {
      return withFlag(F_CAN_WRITE_CLIENT_CACHE, v);
    }

    public SskInsertOptions withCanWriteDatastore(boolean v) {
      return withFlag(F_CAN_WRITE_DATASTORE, v);
    }

    public SskInsertOptions withForkOnCacheable(boolean v) {
      return withFlag(F_FORK_ON_CACHEABLE, v);
    }

    public SskInsertOptions withPreferInsert(boolean v) {
      return withFlag(F_PREFER_INSERT, v);
    }

    public SskInsertOptions withIgnoreLowBackoff(boolean v) {
      return withFlag(F_IGNORE_LOW_BACKOFF, v);
    }

    public SskInsertOptions withRealTimeFlag(boolean v) {
      return withFlag(F_REALTIME, v);
    }
  }

  public SSKInsertSender makeInsertSender(
      SSKBlock block, short htl, long uid, InsertTag tag, PeerNode source, SskInsertOptions opts) {
    NodeSSK key = block.getKey();
    if (key.getPubKey() == null) {
      throw new IllegalArgumentException("No pub key when inserting");
    }

    node.storage()
        .getPubKey()
        .cacheKey(
            key.getPubKeyHash(),
            key.getPubKey(),
            false,
            opts.canWriteClientCache,
            opts.canWriteDatastore,
            false,
            node.storage().isWriteLocalToDatastore());
    if (LOG.isDebugEnabled())
      LOG.debug("makeInsertSender({},{},{},{},...,{}", key, htl, uid, source, opts.fromStore);
    SSKInsertSender is;
    is =
        new SSKInsertSender(
            block,
            uid,
            tag,
            htl,
            source,
            node,
            opts.fromStore,
            opts.forkOnCacheable,
            opts.preferInsert,
            opts.ignoreLowBackoff,
            opts.realTimeFlag);
    is.start();
    return is;
  }
}
