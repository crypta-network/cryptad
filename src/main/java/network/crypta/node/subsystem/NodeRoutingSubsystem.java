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
import network.crypta.node.RequestSenderContext;
import network.crypta.node.RequestTag;
import network.crypta.node.RequestTracker;
import network.crypta.node.SSKInsertSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Routing subsystem facade that wires request/insert senders with routing metadata.
 *
 * <p>This subsystem is the node-facing entry point for creating request senders, insert senders,
 * and related routing helpers. Callers use it to decide whether a block should be stored deeply, to
 * instantiate sender objects for CHK/SSK traffic, and to access per-node tracking structures like
 * {@link RequestTracker} and {@link FailureTable}. Typical call flow is to construct the subsystem
 * during {@link Node} setup, call {@link #init()} and {@link #initDecrementPolicy()} during
 * startup, then route each request or insert through {@link #makeRequestSender(Key, short, long,
 * RequestTag, PeerNode, RequestSenderOptions)} or the appropriate insert factory.
 *
 * <p>The class maintains a simple mutable state (tracker, failure table, and decrement policy
 * flags) but does not implement its own synchronization. It relies on the thread-safety of the
 * collaborating components and the node's startup sequencing. The routing decisions are
 * deterministic given inputs, except for the probabilistic HTL decrement flags which are fixed at
 * initialization time and reused thereafter.
 *
 * <ul>
 *   <li>Responsibilities: instantiate senders, expose routing helpers, and apply HTL policy.
 *   <li>Notable behaviors: coalesces CHK requests when possible; may short-circuit on local data.
 * </ul>
 */
public final class NodeRoutingSubsystem {
  private static final Logger LOG = LoggerFactory.getLogger(NodeRoutingSubsystem.class);

  private final Node node;
  private RequestTracker tracker;
  private FailureTable failureTable;
  private boolean decrementAtMax;
  private boolean decrementAtMin;

  /**
   * Creates a routing subsystem bound to a specific node instance.
   *
   * <p>This constructor only stores the node reference; it does not create the request tracker or
   * failure table. Call {@link #init()} during node startup to finish wiring, and then call {@link
   * #initDecrementPolicy()} to freeze the probabilistic HTL decrement flags. The node reference
   * must remain valid for the lifetime of this subsystem.
   *
   * @param node owning node instance used for network, storage, and bootstrap access; must not be
   *     {@code null} and should be fully constructed.
   */
  public NodeRoutingSubsystem(Node node) {
    this.node = node;
  }

  /**
   * Initializes routing trackers and failure tables for this subsystem.
   *
   * <p>This method constructs a {@link RequestTracker} using the node's peer manager and ticker,
   * and it constructs a {@link FailureTable} bound to the node. Call it once during startup before
   * any routing operations are attempted. Re-invoking, it replaces existing instances and may
   * discard in-flight tracking state, so it is not intended to be idempotent.
   */
  public void init() {
    tracker = new RequestTracker(node.network().peers(), node.network().ticker());
    failureTable = new FailureTable(node);
  }

  /**
   * Initializes probabilistic HTL decrement behavior for the current process.
   *
   * <p>This method samples the node's bootstrap random source once to decide whether decrementing
   * at the HTL maximum and minimum boundaries should occur for this runtime. The chosen flags are
   * stored and reused by {@link #decrementHTL(PeerNode, short)} to avoid per-request randomness.
   * Invoke it after {@link #init()} and before handling requests so the policy is stable.
   */
  public void initDecrementPolicy() {
    decrementAtMax = node.bootstrap().random().nextDouble() <= Node.DECREMENT_AT_MAX_PROB;
    decrementAtMin = node.bootstrap().random().nextDouble() <= Node.DECREMENT_AT_MIN_PROB;
  }

  /**
   * Determines whether a block should be stored in the main store (deep) rather than a cache.
   *
   * <p>The decision is based on relative proximity to the target key compared with the source and
   * the set of peers the request was routed to, discounting low‑uptime peers. A local node that is
   * at least as close as the considered peers is treated as a good long-term storage candidate,
   * while a closer source or routed peer suppresses deep storage. The method performs only local
   * computations and has no side effects, so it is safe to call repeatedly with the same inputs.
   *
   * @param key the target key used for distance calculations; must be non-null and normalized.
   * @param source the previous hop peer, or {@code null} for locally originated requests.
   * @param routedTo peers selected for onward routing; an array may be empty but not null.
   * @return {@code true} when this node is strictly closer than all high-uptime peers considered,
   *     indicating deep storage eligibility; {@code false} otherwise.
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

  /**
   * Returns the request tracker constructed by {@link #init()}.
   *
   * <p>The tracker is a shared, mutable object used by request senders and handlers. Callers should
   * treat it as read-mostly and avoid replacing it directly. If {@link #init()} has not yet been
   * called, this method returns {@code null}.
   *
   * @return the current request tracker instance, or {@code null} before initialization.
   */
  public RequestTracker tracker() {
    return tracker;
  }

  /**
   * Returns the failure table constructed by {@link #init()}.
   *
   * <p>The failure table tracks recent routing failures and request interest. It is initialized
   * once at startup and then shared across the routing stack. If {@link #init()} has not yet been
   * invoked, this method returns {@code null}.
   *
   * @return the current failure table instance, or {@code null} before initialization.
   */
  public FailureTable failureTable() {
    return failureTable;
  }

  /**
   * Immutable flags for configuring request sender behavior.
   *
   * <p>This record groups the boolean switches used by {@link #makeRequestSender(Key, short, long,
   * RequestTag, PeerNode, RequestSenderOptions)}. It is a compact value object that callers can
   * construct via {@link #of(boolean, boolean, boolean, boolean, boolean, boolean)} for clarity.
   * Instances are immutable and may be reused across requests when the same policy is desired.
   *
   * @param localOnly whether routing should be suppressed and local lookups only are allowed.
   * @param ignoreStore whether local storage should be skipped when resolving the request.
   * @param offersOnly whether routing should target offers only rather than full retrieval.
   * @param canReadClientCache whether the client cache may be consulted for lookup results.
   * @param canWriteClientCache whether the client cache may be populated by a local hit.
   * @param realTimeFlag whether the request should be treated as real-time for scheduling.
   */
  public record RequestSenderOptions(
      boolean localOnly,
      boolean ignoreStore,
      boolean offersOnly,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      boolean realTimeFlag) {

    /**
     * Creates a new options record with the provided flag values.
     *
     * <p>This factory is a convenience to make call sites explicit about flag order. It performs no
     * validation and returns a new {@link RequestSenderOptions} instance with the supplied values.
     * Callers should pass consistent policy values across a request to avoid ambiguous behavior.
     *
     * @param localOnly whether routing should be suppressed and local lookups only are allowed.
     * @param ignoreStore whether local storage should be skipped when resolving the request.
     * @param offersOnly whether routing should target offers only rather than full retrieval.
     * @param canReadClientCache whether the client cache may be consulted for lookup results.
     * @param canWriteClientCache whether the client cache may be populated by a local hit.
     * @param realTimeFlag whether the request should be treated as real-time for scheduling.
     * @return a new immutable {@link RequestSenderOptions} instance carrying these flags.
     */
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

  /**
   * Creates or reuses a request sender, optionally short-circuiting on local data.
   *
   * <p>The method first checks whether the request can be satisfied locally, honoring the cache and
   * datastore flags in {@code opts}. If a local {@link KeyBlock} is found, it is returned
   * immediately. When routing is allowed, the method attempts to coalesce with an existing
   * in-flight request sender for CHK keys, or it creates and starts a new {@link RequestSender}
   * when needed. Requests with {@code htl == 0} or {@code localOnly} set to {@code true} return
   * {@code null} when no local result exists.
   *
   * <pre>{@code
   * var opts = NodeRoutingSubsystem.RequestSenderOptions.of(false, false, false, true, true, true);
   * Object senderOrBlock = routing.makeRequestSender(key, (short) 5, uid, tag, peer, opts);
   * }</pre>
   *
   * @param key the target key to request; must be a CHK or SSK key instance.
   * @param htl hop-to-live value, typically positive and bounded by {@link Node#maxHTL()}.
   * @param uid unique request identifier used by tracking and logging; must be stable per request.
   * @param tag the request tag that is populated with the created or coalesced sender reference.
   * @param source previous hop peer, or {@code null} when the request originates locally.
   * @param opts policy flags governing storage, cache usage, and routing mode.
   * @return a {@link KeyBlock} for local hits, a {@link RequestSender} for routed requests, or
   *     {@code null} when routing is disallowed or HTL is exhausted.
   */
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
              key, canReadClientCache, canWriteClientCache, canWriteDatastore, offersOnly);
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
            new RequestSenderContext(key, null, htl, uid, tag, node, source),
            opts,
            canWriteDatastore);
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
          (NodeSSK) key, canReadClientCache, canWriteClientCache, canWriteDatastore, offersOnly);
    }
  }

  private KeyBlock tryFetchLocalForSSK(
      NodeSSK key,
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

  /**
   * Determines whether a request may write to the datastore at the given HTL.
   *
   * <p>The policy is a simple threshold: requests may write when the provided HTL is at most {@code
   * maxHTL - 2}. The method does not clamp the input and does not mutate state, so it is safe to
   * call repeatedly with the same arguments.
   *
   * @param htl hop-to-live value to evaluate; typically non-negative and bounded by max HTL.
   * @return {@code true} when datastore writes are permitted under the request policy.
   */
  public boolean canWriteDatastoreRequest(short htl) {
    return htl <= (node.maxHTL() - 2);
  }

  /**
   * Determines whether an insert may write to the datastore at the given HTL.
   *
   * <p>Insert operations are slightly more conservative: writes are allowed only when {@code htl <=
   * maxHTL - 3}. This helps preserve storage balance by reducing write intensity at high HTL
   * values. The method is pure and does not modify any state.
   *
   * @param htl hop-to-live value for the insert; typically non-negative and bounded by max HTL.
   * @return {@code true} when datastore writes are permitted for the insert operation.
   */
  public boolean canWriteDatastoreInsert(short htl) {
    return htl <= (node.maxHTL() - 3);
  }

  /**
   * Decrements the HTL according to source and probabilistic boundary policy.
   *
   * <p>If a source peer is provided, its HTL decrement logic is delegated to and returned
   * unchanged. For local-originated requests, the method clamps HTL to the node maximum and then
   * applies a probabilistic decrement at the maximum and minimum boundaries, unless probabilistic
   * HTLs are disabled. For intermediate values, the HTL is always decremented by one. Negative
   * values are treated as exhausted and return zero.
   *
   * @param source the previous hop peer, or {@code null} for locally originated requests.
   * @param htl hop-to-live value to decrement; values outside the expected range are tolerated.
   * @return the decremented HTL value, never negative, possibly unchanged at boundaries.
   */
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

  /**
   * Immutable configuration flags for CHK insert senders.
   *
   * <p>This value object encapsulates optional headers, a partially received block, and a set of
   * boolean flags that influence CHK insert behavior. Instances are immutable; each {@code with*}
   * method returns a new instance, preserving existing fields and updating exactly one flag. This
   * makes it safe to share a base options instance across multiple inserts.
   */
  public static final class ChkInsertOptions {
    /**
     * Optional block headers to attach to the insert, or {@code null} when none are provided.
     *
     * <p>The headers are passed directly to the sender and are treated as opaque bytes. Callers
     * retain ownership of the array; avoid mutating it after passing it to this options instance.
     */
    public final byte[] headers;

    /**
     * Partially received block used to seed the insert, or {@code null} if not applicable.
     *
     * <p>This value allows the sender to reuse previously received data. When {@code null}, the
     * sender behaves as a full insert without a partial reuse.
     */
    public final PartiallyReceivedBlock prb;

    /**
     * Whether this insert originates from the local store rather than a client request.
     *
     * <p>This flag influences routing and accounting behavior. It is immutable and must be set by
     * constructing a new options instance via a {@code with*} method.
     */
    public final boolean fromStore;

    /**
     * Whether the client cache may be updated as part of this insert.
     *
     * <p>This flag is an advisory to the sender and may be ignored when cache writes are
     * unavailable. The value is fixed in the options instance and is not mutated after
     * construction.
     */
    public final boolean canWriteClientCache;

    /**
     * Whether to fork the insert when a cacheable response is detected.
     *
     * <p>Forking can improve throughput but may increase the network load. The flag is immutable
     * and should be enabled only when the caller expects cacheable results.
     */
    public final boolean forkOnCacheable;

    /**
     * Whether to prefer inserting locally over forwarding the request onward.
     *
     * <p>The sender uses this hint to bias its behavior. It is immutable and is applied
     * consistently throughout the insert lifecycle.
     */
    public final boolean preferInsert;

    /**
     * Whether to ignore low-backoff routing signals when choosing peers.
     *
     * <p>This flag relaxes backoff constraints and can increase routing aggressiveness. The value
     * is fixed for the lifetime of the options instance.
     */
    public final boolean ignoreLowBackoff;

    /**
     * Whether the insert should be treated as real-time for scheduling decisions.
     *
     * <p>Real-time inserts may receive higher scheduling priority than bulk operations. The flag is
     * immutable and does not change once the options instance is created.
     */
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

    /**
     * Creates a new options instance with no flags set.
     *
     * <p>This factory is a convenience for constructing a baseline configuration with optional
     * header and partial block data. Callers can then use {@code with*} methods to enable
     * additional flags as needed.
     *
     * @param headers optional insert headers; may be {@code null} when none are available.
     * @param prb partially received block to reuse, or {@code null} for a full insert.
     * @return a new immutable options instance with all flags disabled.
     */
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

    /**
     * Returns a new options instance with the {@code fromStore} flag updated.
     *
     * <p>This method does not mutate the current instance; it returns a copy with the requested
     * flag set or cleared. All other fields, including headers and partial blocks, are preserved.
     *
     * @param v {@code true} to mark the insert as store-originated; {@code false} otherwise.
     * @return a new options instance with the updated {@code fromStore} flag value.
     */
    public ChkInsertOptions withFromStore(boolean v) {
      return withFlag(F_FROM_STORE, v);
    }

    /**
     * Returns a new options instance with the {@code canWriteClientCache} flag updated.
     *
     * <p>The existing instance is left unchanged. This is a pure functional update that preserves
     * all other fields and flags.
     *
     * @param v {@code true} to allow client cache writes; {@code false} to prohibit them.
     * @return a new options instance with the updated client cache write behavior.
     */
    public ChkInsertOptions withCanWriteClientCache(boolean v) {
      return withFlag(F_CAN_WRITE_CLIENT_CACHE, v);
    }

    /**
     * Returns a new options instance with the {@code forkOnCacheable} flag updated.
     *
     * <p>Forking behavior can affect routing fan-out; this method updates only that flag while
     * preserving all other states.
     *
     * @param v {@code true} to fork when cacheable; {@code false} to disable forking.
     * @return a new options instance with updated fork-on-cacheable behavior.
     */
    public ChkInsertOptions withForkOnCacheable(boolean v) {
      return withFlag(F_FORK_ON_CACHEABLE, v);
    }

    /**
     * Returns a new options instance with the {@code preferInsert} flag updated.
     *
     * <p>This functional update is useful when callers want to bias inserts without modifying their
     * base options object.
     *
     * @param v {@code true} to prefer inserting locally; {@code false} to avoid that bias.
     * @return a new options instance with the updated preference.
     */
    public ChkInsertOptions withPreferInsert(boolean v) {
      return withFlag(F_PREFER_INSERT, v);
    }

    /**
     * Returns a new options instance with the {@code ignoreLowBackoff} flag updated.
     *
     * <p>The method preserves all other fields and returns a new instance, so callers can reuse the
     * original options safely.
     *
     * @param v {@code true} to ignore low-backoff signals; {@code false} to respect them.
     * @return a new options instance with updated backoff handling.
     */
    public ChkInsertOptions withIgnoreLowBackoff(boolean v) {
      return withFlag(F_IGNORE_LOW_BACKOFF, v);
    }

    /**
     * Returns a new options instance with the {@code realTimeFlag} value updated.
     *
     * <p>Schedulers may prioritize real-time inserts differently. This method updates only that
     * flag and keeps all other fields intact.
     *
     * @param v {@code true} for real-time scheduling; {@code false} for bulk scheduling.
     * @return a new options instance with the updated real-time flag.
     */
    public ChkInsertOptions withRealTimeFlag(boolean v) {
      return withFlag(F_REALTIME, v);
    }
  }

  /**
   * Creates and starts a CHK insert sender for the provided key.
   *
   * <p>This method constructs a {@link CHKInsertSender} using the supplied key, tag, and options,
   * then starts it immediately. It does not perform local caching itself; behavior is controlled by
   * the sender and the flags in {@code opts}. The returned sender is already running by the time
   * this method returns.
   *
   * @param key CHK key identifying the content to insert; must be non-null and valid.
   * @param htl hop-to-live for routing; typically positive and bounded by {@link Node#maxHTL()}.
   * @param uid unique insert identifier used for tracking and logging; must be stable per insert.
   * @param tag an insert tag that tracks lifecycle and success/failure outcomes.
   * @param source previous hop peer, or {@code null} for locally originated inserts.
   * @param opts immutable insert options controlling cache and routing behavior.
   * @return the started {@link CHKInsertSender} instance responsible for the insert.
   */
  public CHKInsertSender makeInsertSender(
      NodeCHK key, short htl, long uid, InsertTag tag, PeerNode source, ChkInsertOptions opts) {
    if (LOG.isDebugEnabled())
      LOG.debug("makeInsertSender({},{},{},{},...,{}", key, htl, uid, source, opts.fromStore);
    CHKInsertSender is;
    is = new CHKInsertSender(key, uid, tag, htl, source, node, opts);
    is.start();
    return is;
  }

  /**
   * Immutable configuration flags for SSK insert senders.
   *
   * <p>This value object holds boolean flags that influence SSK insert behavior. Instances are
   * immutable; callers should use {@code with*} methods to create updated copies instead of
   * mutating in place. This allows a shared baseline configuration to be reused safely.
   */
  public static final class SskInsertOptions {
    /**
     * Whether this insert originates from the local store rather than a client request.
     *
     * <p>This flag is immutable and influences routing and accounting behavior for the sender.
     */
    public final boolean fromStore;

    /**
     * Whether the client cache may be updated as part of this insert.
     *
     * <p>This flag is advisory and may be ignored when cache writes are unavailable or disabled.
     */
    public final boolean canWriteClientCache;

    /**
     * Whether the datastore may be updated as part of this insert.
     *
     * <p>This value is typically derived from HTL policy and remains constant for the insert.
     */
    public final boolean canWriteDatastore;

    /**
     * Whether to fork the insert when a cacheable response is detected.
     *
     * <p>Forking can increase throughput but may increase network load and resource usage.
     */
    public final boolean forkOnCacheable;

    /**
     * Whether to prefer inserting locally over forwarding to other peers.
     *
     * <p>This hint biases the sender's routing choices but does not guarantee local insertion.
     */
    public final boolean preferInsert;

    /**
     * Whether to ignore low-backoff routing signals when selecting peers.
     *
     * <p>Ignoring backoff increases aggressiveness and can lead to more retries.
     */
    public final boolean ignoreLowBackoff;

    /**
     * Whether the insert should be treated as real-time for scheduling decisions.
     *
     * <p>Real-time inserts may receive higher priority than bulk operations.
     */
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

    /**
     * Creates a new options instance with all flags disabled.
     *
     * <p>This factory is a convenience for building a base configuration that can later be
     * customized with {@code with*} methods.
     *
     * @return a new immutable options instance with every flag set to {@code false}.
     */
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

    /**
     * Returns a new options instance with the {@code fromStore} flag updated.
     *
     * <p>This method preserves all other fields and returns a distinct instance.
     *
     * @param v {@code true} to mark the insert as store-originated; {@code false} otherwise.
     * @return a new options instance with the updated {@code fromStore} flag value.
     */
    public SskInsertOptions withFromStore(boolean v) {
      return withFlag(F_FROM_STORE, v);
    }

    /**
     * Returns a new options instance with the {@code canWriteClientCache} flag updated.
     *
     * <p>The current instance remains unchanged; only the requested flag differs in the result.
     *
     * @param v {@code true} to allow client cache writes; {@code false} to disable them.
     * @return a new options instance with updated client cache write behavior.
     */
    public SskInsertOptions withCanWriteClientCache(boolean v) {
      return withFlag(F_CAN_WRITE_CLIENT_CACHE, v);
    }

    /**
     * Returns a new options instance with the {@code canWriteDatastore} flag updated.
     *
     * <p>This update is functional and preserves all other options and flags.
     *
     * @param v {@code true} to permit datastore writes; {@code false} to prohibit them.
     * @return a new options instance with updated datastore write behavior.
     */
    public SskInsertOptions withCanWriteDatastore(boolean v) {
      return withFlag(F_CAN_WRITE_DATASTORE, v);
    }

    /**
     * Returns a new options instance with the {@code forkOnCacheable} flag updated.
     *
     * <p>This method does not mutate the existing options instance, making it safe to reuse.
     *
     * @param v {@code true} to fork on cacheable responses; {@code false} to disable forking.
     * @return a new options instance with updated fork-on-cacheable behavior.
     */
    public SskInsertOptions withForkOnCacheable(boolean v) {
      return withFlag(F_FORK_ON_CACHEABLE, v);
    }

    /**
     * Returns a new options instance with the {@code preferInsert} flag updated.
     *
     * <p>Prefer-insert biases routing toward local insertion without guaranteeing it.
     *
     * @param v {@code true} to prefer inserts locally; {@code false} to remove the bias.
     * @return a new options instance with an updated preference value.
     */
    public SskInsertOptions withPreferInsert(boolean v) {
      return withFlag(F_PREFER_INSERT, v);
    }

    /**
     * Returns a new options instance with the {@code ignoreLowBackoff} flag updated.
     *
     * <p>This is a functional update that preserves other flags and fields.
     *
     * @param v {@code true} to ignore low-backoff signals; {@code false} to respect them.
     * @return a new options instance with updated backoff handling behavior.
     */
    public SskInsertOptions withIgnoreLowBackoff(boolean v) {
      return withFlag(F_IGNORE_LOW_BACKOFF, v);
    }

    /**
     * Returns a new options instance with the {@code realTimeFlag} value updated.
     *
     * <p>Real-time scheduling may affect priorities and timeouts compared to bulk inserts.
     *
     * @param v {@code true} to mark the insert as real-time; {@code false} for bulk mode.
     * @return a new options instance with an updated real-time flag value.
     */
    public SskInsertOptions withRealTimeFlag(boolean v) {
      return withFlag(F_REALTIME, v);
    }
  }

  /**
   * Creates and starts an SSK insert sender for the provided block.
   *
   * <p>The method validates that the block's public key is available, caches the public key in the
   * local pubkey store, and then constructs and starts a {@link SSKInsertSender}. The returned
   * sender is already running when this method returns. Cache behavior is controlled by {@code
   * opts}, including whether client cache and datastore writes are permitted.
   *
   * @param block SSK block containing the key and payload to insert; must be non-null.
   * @param htl hop-to-live for routing; typically positive and bounded by {@link Node#maxHTL()}.
   * @param uid unique insert identifier used for tracking and logging; must be stable per insert.
   * @param tag an insert tag that tracks lifecycle and success/failure outcomes.
   * @param source previous hop peer, or {@code null} for locally originated inserts.
   * @param opts immutable insert options controlling cache and routing behavior.
   * @return the started {@link SSKInsertSender} instance responsible for the insert.
   * @throws IllegalArgumentException if the block's public key is missing.
   */
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
    is = new SSKInsertSender(block, uid, tag, htl, source, node, opts);
    is.start();
    return is;
  }
}
