package network.crypta.node;

import static java.util.concurrent.TimeUnit.SECONDS;

import network.crypta.crypt.RandomSource;
import network.crypta.io.xfer.AbortedException;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import network.crypta.store.KeyCollisionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates client-side fetch and insert operations for a {@link NodeClientCore} instance.
 *
 * <p>This helper acts as the transfer-focused companion to the core, translating high-level
 * requests into concrete sender workflows. It allocates and tracks UIDs, consults the datastore and
 * client cache, and reports routing and transfer costs to node statistics. The instance is
 * intentionally stateful and bound to a single {@link Node}; it does not reset or share state
 * between cores. Asynchronous entry points return after scheduling work, while synchronous get/put
 * methods block until completion and always release tracking resources before returning.
 *
 * <p>Thread safety follows the underlying node components; this class adds no extra synchronization
 * beyond local bookkeeping.
 *
 * <ul>
 *   <li>Schedules asynchronous fetches and forwards completion callbacks.
 *   <li>Performs blocking CHK/SSK fetches with verification.
 *   <li>Runs blocking inserts with caching and collision handling.
 *   <li>Queues background reinserts and records transfer metrics.
 * </ul>
 *
 * @see NodeClientCore
 * @see RequestSender
 * @see CHKInsertSender
 * @see SSKInsertSender
 */
public final class NodeClientCoreTransfers {
  private static final Logger LOG = LoggerFactory.getLogger(NodeClientCoreTransfers.class);
  private static final String LOG_BYTES_OPEN = " bytes (";
  private static final String MSG_CANNOT_LOCK_UID = "Could not lock UID just randomly generated: ";
  private static final String MSG_BROKEN_PRNG = " - probably indicates broken PRNG";
  private static final String LOG_DOES_NOT_VERIFY = "Does not verify: ";

  private final NodeClientCore core;
  private final Node node;
  private final RandomSource random;
  private final RequestStarterGroup requestStarters;

  NodeClientCoreTransfers(NodeClientCore core) {
    this.core = core;
    this.node = core.getNode();
    this.random = core.getRandom();
    this.requestStarters = core.getRequestStarters();
  }

  /**
   * Schedules a non-blocking fetch for the supplied key and arranges completion callbacks.
   *
   * <p>This call generates a new request UID, locks it with the tracker, and optionally consults
   * the datastore before routing. If the data is found locally, the listener is notified and no
   * network request is started. Otherwise, a {@link RequestSender} is created and the listener is
   * notified on completion or failure; some successful outcomes may be delivered via the
   * pending-keys mechanism instead of the listener. The method returns after scheduling work and
   * does not wait for completion. Each invocation is independent, even for repeated keys.
   *
   * @param key key to fetch; typically a {@link Key} or {@link NodeSSK}.
   * @param offersOnly true to fetch only from offered-key sources.
   * @param listener callback notified for success, failure, or local-store hits.
   * @param canReadClientCache whether the request may read from the client cache.
   * @param canWriteClientCache whether the request may write into the client cache.
   * @param realTimeFlag true for latency-optimized routing; false for bulk throughput.
   * @param localOnly true to consult only local storage and skip routing.
   * @param ignoreStore true to bypass the datastore and always create a request.
   */
  public void asyncGet(
      final Key key,
      boolean offersOnly,
      final RequestCompletionListener listener,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      final boolean realTimeFlag,
      boolean localOnly,
      boolean ignoreStore) {
    final long uid = makeUID();
    final boolean isSSK = key instanceof NodeSSK;
    final RequestTag tag =
        new RequestTag(isSSK, RequestTag.START.ASYNC_GET, null, realTimeFlag, uid, node);
    if (!node.routing().tracker().lockUID(uid, isSSK, false, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      listener.onFailed(
          new LowLevelGetException(
              LowLevelGetException.INTERNAL_ERROR,
              "Could not lock random UID - serious PRNG problem???"));
      return;
    }
    tag.setAccepted();
    short htl = node.maxHTL();
    // If another node requested it within the ULPR period at a lower HTL, that may allow
    // us to cache it in the datastore. Find the lowest HTL fetching the key in that period,
    // and use that for purposes of deciding whether to cache it in the store.
    if (offersOnly) {
      htl = node.routing().failureTable().minOfferedHTL(key, htl);
      if (LOG.isDebugEnabled()) LOG.debug("Using old HTL for GetOfferedKey: {}", htl);
    }
    final long startTime = System.currentTimeMillis();
    startAsyncGet(
        key,
        offersOnly,
        uid,
        listener,
        tag,
        canReadClientCache,
        canWriteClientCache,
        htl,
        realTimeFlag,
        localOnly,
        ignoreStore,
        isSSK,
        startTime);
  }

  /**
   * Start an asynchronous fetch of the key in question, which will complete to the datastore. It
   * will not decode the data because we don't provide a ClientKey. It will not return anything and
   * will run asynchronously. Caller is responsible for unlocking the UID.
   *
   * @param key The key being fetched.
   * @param offersOnly If true, only fetch the key from nodes that have offered it, using
   *     GetOfferedKeys, don't do a normal fetch for it.
   * @param uid The UID of the request. This should already be locked before calling.
   * @param requestTag The RequestTag for the request; used for request lifecycle callbacks.
   * @param listener Will be called by the request sender, if a request is started. However, for
   *     example, if we fetch it from the store, it will be returned via the tripPendingKeys
   *     mechanism.
   * @param canReadClientCache Can this request read the client-cache?
   * @param canWriteClientCache Can this request write the client-cache?
   * @param htl The HTL to start the request at. See the caller, this can be modified in the case of
   *     fetching an offered key.
   * @param realTimeFlag Is this a real-time request? False = this is a bulk request.
   * @param localOnly If true, only check the datastore, don't create a request if nothing is found.
   * @param ignoreStore If true, don't check the datastore, create a request immediately.
   * @param isSSK Whether the request targets an SSK key type.
   * @param startTime Start time in milliseconds since epoch for metrics.
   */
  @SuppressWarnings("java:S1181")
  private void startAsyncGet(
      Key key,
      boolean offersOnly,
      long uid,
      RequestCompletionListener listener,
      Object requestTag,
      boolean canReadClientCache,
      boolean canWriteClientCache,
      short htl,
      boolean realTimeFlag,
      boolean localOnly,
      boolean ignoreStore,
      boolean isSSK,
      long startTime) {
    RequestTag tag = (RequestTag) requestTag;
    RequestSenderListener senderListener =
        new RequestSenderListener() {

          private boolean rejectedOverload;

          @Override
          public void onCHKTransferBegins() {
            // Ignore
          }

          @Override
          public void onReceivedRejectOverload() {
            synchronized (this) {
              if (rejectedOverload) return;
              rejectedOverload = true;
            }
            requestStarters.rejectedOverload(isSSK, false, realTimeFlag);
          }

          @Override
          public void onDataFoundLocally() {
            tag.unlockHandler();
            listener.onSucceeded();
          }

          /**
           * The RequestSender finished.
           *
           * @param status The completion status code reported by the sender.
           * @param fromOfferedKey {@code true} if this completion originated from an offered-key
           *     fetch path (GetOfferedKeys); {@code false} for a normal fetch.
           * @param rs The sender that completed and reported the status.
           */
          @Override
          public void onRequestSenderFinished(
              int status, boolean fromOfferedKey, RequestSender rs) {
            tag.unlockHandler();
            boolean rejectedOverloadLocal;
            synchronized (this) {
              rejectedOverloadLocal = this.rejectedOverload;
            }
            handleAsyncGetFinished(
                isSSK, listener, startTime, key, realTimeFlag, rs, rejectedOverloadLocal);
          }

          @Override
          public void onNotStarted(boolean internalError) {
            if (internalError)
              listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
            else
              listener.onFailed(
                  new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND_IN_STORE));
          }
        };
    try {
      Object o =
          node.routing()
              .makeRequestSender(
                  key,
                  htl,
                  uid,
                  tag,
                  null,
                  NodeRoutingSubsystem.RequestSenderOptions.of(
                      localOnly,
                      ignoreStore,
                      offersOnly,
                      canReadClientCache,
                      canWriteClientCache,
                      realTimeFlag));
      if (o instanceof KeyBlock) {
        tag.setServedFromDatastore();
        senderListener.onDataFoundLocally();
        return; // Already have it.
      }
      if (o == null) {
        senderListener.onNotStarted(false);
        tag.unlockHandler();
        return;
      }
      RequestSender rs = (RequestSender) o;
      rs.addListener(senderListener);
      if (rs.uid != uid) tag.unlockHandler();
      // Else it has started a request.
      if (LOG.isDebugEnabled()) LOG.debug("Started {} for {} for {}", o, uid, key);
    } catch (RuntimeException | Error e) {
      LOG.error("Caught error trying to start request: {}", e, e);
      senderListener.onNotStarted(true);
    }
  }

  private void handleAsyncGetFinished(
      boolean isSSK,
      RequestCompletionListener listener,
      long startTime,
      Key key,
      boolean realTimeFlag,
      RequestSender rs,
      boolean rejectedOverload) {
    int status = rs.getStatus();
    if (status == RequestSender.NOT_FINISHED) {
      LOG.error("Bogus status in onRequestSenderFinished for {}", rs, new Exception("error"));
      listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
      return;
    }

    if (isNonErrorStatus(status)) reportFetchCosts(isSSK, rs, status);

    if (status == RequestSender.TIMED_OUT || status == RequestSender.GENERATED_REJECTED_OVERLOAD) {
      handleTimeoutOrRejected(isSSK, realTimeFlag, startTime, key, rejectedOverload);
    } else if (rs.hasForwarded() && isForwardedTerminalStatus(status)) {
      handleForwardedStatuses(isSSK, realTimeFlag, startTime, key, status);
    }

    if (status == RequestSender.SUCCESS) {
      listener.onSucceeded();
      return;
    }
    handleStatusResult(isSSK, listener, rs, status);
  }

  private boolean isNonErrorStatus(int status) {
    return status != RequestSender.TIMED_OUT
        && status != RequestSender.GENERATED_REJECTED_OVERLOAD
        && status != RequestSender.INTERNAL_ERROR;
  }

  private void reportFetchCosts(boolean isSSK, RequestSender rs, int status) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "{} fetch cost {}/{}" + LOG_BYTES_OPEN + "{})",
          isSSK ? "SSK" : "CHK",
          rs.getTotalSentBytes(),
          rs.getTotalReceivedBytes(),
          status);
    (isSSK
            ? node.network().stats().localSskFetchBytesSentAverage
            : node.network().stats().localChkFetchBytesSentAverage)
        .report(rs.getTotalSentBytes());
    (isSSK
            ? node.network().stats().localSskFetchBytesReceivedAverage
            : node.network().stats().localChkFetchBytesReceivedAverage)
        .report(rs.getTotalReceivedBytes());
    if (status == RequestSender.SUCCESS)
      (isSSK
              ? node.network().stats().successfulSskFetchBytesReceivedAverage
              : node.network().stats().successfulChkFetchBytesReceivedAverage)
          .report(rs.getTotalReceivedBytes());
  }

  private boolean isForwardedTerminalStatus(int status) {
    return status == RequestSender.DATA_NOT_FOUND
        || status == RequestSender.RECENTLY_FAILED
        || status == RequestSender.SUCCESS
        || status == RequestSender.ROUTE_NOT_FOUND
        || status == RequestSender.VERIFY_FAILURE
        || status == RequestSender.GET_OFFER_VERIFY_FAILURE;
  }

  private void handleTimeoutOrRejected(
      boolean isSSK, boolean realTimeFlag, long startTime, Key key, boolean rejectedOverload) {
    if (rejectedOverload) return;
    requestStarters.rejectedOverload(isSSK, false, realTimeFlag);
    long rtt = System.currentTimeMillis() - startTime;
    double targetLocation = key.toNormalizedDouble();
    if (isSSK) node.network().stats().reportSSKOutcome(rtt, false, realTimeFlag);
    else node.network().stats().reportCHKOutcome(rtt, false, targetLocation, realTimeFlag);
  }

  private void handleForwardedStatuses(
      boolean isSSK, boolean realTimeFlag, long startTime, Key key, int status) {
    long rtt = System.currentTimeMillis() - startTime;
    double targetLocation = key.toNormalizedDouble();
    requestStarters.requestCompleted(isSSK, false, key, realTimeFlag);
    requestStarters.getThrottle(isSSK, false, realTimeFlag).successfulCompletion(rtt);
    if (isSSK)
      node.network().stats().reportSSKOutcome(rtt, status == RequestSender.SUCCESS, realTimeFlag);
    else
      node.network()
          .stats()
          .reportCHKOutcome(rtt, status == RequestSender.SUCCESS, targetLocation, realTimeFlag);
    if (status == RequestSender.SUCCESS) {
      LOG.debug("Successful {} fetch took {}", isSSK ? "SSK" : "CHK", rtt);
    }
  }

  private void handleStatusResult(
      boolean isSSK, RequestCompletionListener listener, RequestSender rs, int status) {
    switch (status) {
      case RequestSender.NOT_FINISHED:
        LOG.error("RS still running in get{}!: {}", isSSK ? "SSK" : "CHK", rs);
        listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
        return;
      case RequestSender.DATA_NOT_FOUND:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND));
        return;
      case RequestSender.RECENTLY_FAILED:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.RECENTLY_FAILED));
        return;
      case RequestSender.ROUTE_NOT_FOUND:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.ROUTE_NOT_FOUND));
        return;
      case RequestSender.TRANSFER_FAILED, RequestSender.GET_OFFER_TRANSFER_FAILED:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.TRANSFER_FAILED));
        return;
      case RequestSender.VERIFY_FAILURE, RequestSender.GET_OFFER_VERIFY_FAILURE:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.VERIFY_FAILED));
        return;
      case RequestSender.GENERATED_REJECTED_OVERLOAD, RequestSender.TIMED_OUT:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.REJECTED_OVERLOAD));
        return;
      case RequestSender.INTERNAL_ERROR:
        listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
        return;
      default:
        LOG.error(
            "Unknown RequestSender code in get{}: {} on {}", isSSK ? "SSK" : "CHK", status, rs);
        listener.onFailed(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR));
    }
  }

  /**
   * Synchronously fetches and verifies a client key block.
   *
   * <p>This method blocks until the fetch completes or fails. It routes to the CHK or SSK path
   * based on the key type and uses {@code localOnly} and {@code ignoreStore} to decide whether to
   * consult the datastore or issue a network request. The call generates and locks a request UID,
   * releases tracking resources before returning, and throws a {@link LowLevelGetException} on any
   * failure. If the key type is unsupported, it throws {@link IllegalArgumentException}.
   *
   * @param key client key to fetch; must be {@link ClientCHK} or {@link ClientSSK}.
   * @param localOnly true to consult only the datastore and stop on miss.
   * @param ignoreStore true to bypass the datastore and route immediately.
   * @param canWriteClientCache whether the request may write into the client cache.
   * @param realTimeFlag true for latency-optimized routing; false for bulk routing.
   * @return verified client block, owned by the caller for use.
   * @throws LowLevelGetException when the fetch fails, verification fails, or internal errors
   *     occur.
   * @throws IllegalArgumentException if the key is not a CHK or SSK.
   */
  public ClientKeyBlock realGetKey(
      ClientKey key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    return switch (key) {
      case ClientCHK hK ->
          realGetCHK(hK, localOnly, ignoreStore, canWriteClientCache, realTimeFlag);
      case ClientSSK sK ->
          realGetSSK(sK, localOnly, ignoreStore, canWriteClientCache, realTimeFlag);
      default -> throw new IllegalArgumentException("Not a CHK or SSK: " + key);
    };
  }

  /**
   * Fetches a CHK block, optionally via the network.
   *
   * @param key the client CHK to fetch.
   * @param localOnly when {@code true}, check only the datastore and do not create a network
   *     request on miss.
   * @param ignoreStore when {@code true}, skip the datastore and create a network request
   *     immediately.
   * @param canWriteClientCache whether the request may write the client cache. Reads from the
   *     client cache are always allowed for local requests; some callers disable writes to avoid
   *     cache pollution.
   * @param realTimeFlag {@code true} for latency-optimized routing; {@code false} for bulk.
   * @return the verified client block.
   * @throws LowLevelGetException if the data is not found, recently failed, transfer fails, verify
   *     fails, or on internal error.
   */
  ClientKeyBlock realGetCHK(
      ClientCHK key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    long startTime = System.currentTimeMillis();
    long uid = makeUID();
    RequestTag tag = new RequestTag(false, RequestTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!node.routing().tracker().lockUID(uid, false, false, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    RequestSender rs;
    try {
      Object o =
          node.routing()
              .makeRequestSender(
                  key.getNodeCHK(),
                  node.maxHTL(),
                  uid,
                  tag,
                  null,
                  NodeRoutingSubsystem.RequestSenderOptions.of(
                      localOnly, ignoreStore, false, true, canWriteClientCache, realTimeFlag));
      if (o instanceof CHKBlock block)
        try {
          tag.setServedFromDatastore();
          return NodeClientCoreSupport.buildClientChkBlock(block, key);
        } catch (CHKVerifyException e) {
          LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
          throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
        }
      if (o == null) throw new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND_IN_STORE);
      rs = (RequestSender) o;
      return processChkRequestLoop(rs, key, startTime, realTimeFlag);
    } finally {
      tag.unlockHandler();
    }
  }

  private ClientKeyBlock processChkRequestLoop(
      RequestSender rs, ClientCHK key, long startTime, boolean realTimeFlag)
      throws LowLevelGetException {
    boolean rejectedOverload = false;
    short waitStatus = 0;
    while (true) {
      waitStatus = rs.waitUntilStatusChange(waitStatus);
      rejectedOverload =
          checkAndReportRejectedOverload(rejectedOverload, waitStatus, false, realTimeFlag);

      int status = rs.getStatus();
      if (status == RequestSender.NOT_FINISHED) continue;

      maybeReportFetchCosts(false, rs, status);

      if (status == RequestSender.TIMED_OUT
          || status == RequestSender.GENERATED_REJECTED_OVERLOAD
          || (rs.hasForwarded() && isForwardedTerminalStatus(status))) {
        maybeHandleTimeoutOrForwarded(
            false, realTimeFlag, startTime, key.getNodeCHK(), rs, status, rejectedOverload);
      }

      ClientKeyBlock maybe = tryReturnChkBlock(rs, key, status);
      if (maybe != null) return maybe;
      throwForGetStatus(status, rs);
    }
  }

  private boolean checkAndReportRejectedOverload(
      boolean alreadyRejected, short waitStatus, boolean isSSK, boolean realTimeFlag) {
    if (!alreadyRejected && (waitStatus & RequestSender.WAIT_REJECTED_OVERLOAD) != 0) {
      requestStarters.rejectedOverload(isSSK, false, realTimeFlag);
      return true;
    }
    return alreadyRejected;
  }

  private void maybeReportFetchCosts(boolean isSSK, RequestSender rs, int status) {
    if (isNonErrorStatus(status)) {
      reportFetchCosts(isSSK, rs, status);
    }
  }

  private void maybeHandleTimeoutOrForwarded(
      boolean isSSK,
      boolean realTimeFlag,
      long startTime,
      Key key,
      RequestSender rs,
      int status,
      boolean rejectedOverload) {
    if (status == RequestSender.TIMED_OUT || status == RequestSender.GENERATED_REJECTED_OVERLOAD) {
      handleTimeoutOrRejected(isSSK, realTimeFlag, startTime, key, rejectedOverload);
    } else if (rs.hasForwarded() && isForwardedTerminalStatus(status)) {
      handleForwardedStatuses(isSSK, realTimeFlag, startTime, key, status);
    }
  }

  private ClientKeyBlock tryReturnChkBlock(RequestSender rs, ClientCHK key, int status)
      throws LowLevelGetException {
    if (status == RequestSender.SUCCESS)
      try {
        return NodeClientCoreSupport.buildClientChkBlock(
            rs.getPRB().getBlock(), rs.getHeaders(), key);
      } catch (CHKVerifyException e) {
        LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
        throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
      } catch (AbortedException e) {
        LOG.error("Impossible: {}", e, e);
        throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
      }
    return null;
  }

  private void throwForGetStatus(int status, RequestSender rs) throws LowLevelGetException {
    switch (status) {
      case RequestSender.NOT_FINISHED:
        LOG.error("RS still running in get!: {}", rs);
        throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
      case RequestSender.DATA_NOT_FOUND:
        throw new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND);
      case RequestSender.RECENTLY_FAILED:
        throw new LowLevelGetException(LowLevelGetException.RECENTLY_FAILED);
      case RequestSender.ROUTE_NOT_FOUND:
        throw new LowLevelGetException(LowLevelGetException.ROUTE_NOT_FOUND);
      case RequestSender.TRANSFER_FAILED, RequestSender.GET_OFFER_TRANSFER_FAILED:
        throw new LowLevelGetException(LowLevelGetException.TRANSFER_FAILED);
      case RequestSender.VERIFY_FAILURE, RequestSender.GET_OFFER_VERIFY_FAILURE:
        throw new LowLevelGetException(LowLevelGetException.VERIFY_FAILED);
      case RequestSender.GENERATED_REJECTED_OVERLOAD, RequestSender.TIMED_OUT:
        throw new LowLevelGetException(LowLevelGetException.REJECTED_OVERLOAD);
      case RequestSender.INTERNAL_ERROR:
      default:
        LOG.error("Unknown RequestSender code in get: {} on {}", status, rs);
        throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
    }
  }

  ClientKeyBlock realGetSSK(
      ClientSSK key,
      boolean localOnly,
      boolean ignoreStore,
      boolean canWriteClientCache,
      boolean realTimeFlag)
      throws LowLevelGetException {
    long startTime = System.currentTimeMillis();
    long uid = makeUID();
    RequestTag tag = new RequestTag(true, RequestTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!node.routing().tracker().lockUID(uid, true, false, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    RequestSender rs;
    try {
      Object o =
          node.routing()
              .makeRequestSender(
                  key.getNodeKey(true),
                  node.maxHTL(),
                  uid,
                  tag,
                  null,
                  NodeRoutingSubsystem.RequestSenderOptions.of(
                      localOnly, ignoreStore, false, true, canWriteClientCache, realTimeFlag));
      if (o instanceof SSKBlock block)
        try {
          tag.setServedFromDatastore();
          key.setPublicKey(block.getPubKey());
          return NodeClientCoreSupport.buildClientSskBlock(block, key);
        } catch (SSKVerifyException e) {
          LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
          throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
        }
      if (o == null) throw new LowLevelGetException(LowLevelGetException.DATA_NOT_FOUND_IN_STORE);
      rs = (RequestSender) o;
      return processSskRequestLoop(rs, key, startTime, realTimeFlag);
    } finally {
      tag.unlockHandler();
    }
  }

  private ClientKeyBlock processSskRequestLoop(
      RequestSender rs, ClientSSK key, long startTime, boolean realTimeFlag)
      throws LowLevelGetException {
    boolean rejectedOverload = false;
    short waitStatus = 0;
    while (true) {
      waitStatus = rs.waitUntilStatusChange(waitStatus);
      rejectedOverload =
          checkAndReportRejectedOverload(rejectedOverload, waitStatus, true, realTimeFlag);

      int status = rs.getStatus();
      if (status == RequestSender.NOT_FINISHED) continue;

      maybeReportFetchCosts(true, rs, status);

      if (status == RequestSender.TIMED_OUT
          || status == RequestSender.GENERATED_REJECTED_OVERLOAD
          || (rs.hasForwarded() && isForwardedTerminalStatus(status))) {
        maybeHandleTimeoutOrForwarded(
            true, realTimeFlag, startTime, key.getNodeKey(true), rs, status, rejectedOverload);
      }

      if (status == RequestSender.SUCCESS) {
        try {
          SSKBlock block = rs.getSSKBlock();
          key.setPublicKey(block.getPubKey());
          return NodeClientCoreSupport.buildClientSskBlock(block, key);
        } catch (SSKVerifyException e) {
          LOG.error(LOG_DOES_NOT_VERIFY + "{}", e, e);
          throw new LowLevelGetException(LowLevelGetException.DECODE_FAILED);
        }
      }
      if (status == RequestSender.TRANSFER_FAILED
          || status == RequestSender.GET_OFFER_TRANSFER_FAILED) {
        LOG.error("Unexpected transfer failure on an SSK for uid {}", (Object) null);
      }
      throwForGetStatus(status, rs);
    }
  }

  /**
   * Synchronously inserts a CHK or SSK block into the network.
   *
   * <p>This entry point dispatches to the appropriate insert path based on the concrete block type.
   * It performs local bookkeeping, records transfer costs, and may store the block locally
   * according to caching rules. The call blocks until the insert completes or fails; failures are
   * mapped to {@link LowLevelPutException} codes describing routing, overload, or collision
   * outcomes. Unsupported block types result in {@link IllegalArgumentException}.
   *
   * @param block block to insert; must be a {@link CHKBlock} or {@link SSKBlock}.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable true to fork inserts when the block is cacheable.
   * @param preferInsert true to prefer insert strategies when alternatives exist.
   * @param ignoreLowBackoff true to ignore low backoff during routing decisions.
   * @param realTimeFlag true for latency-optimized inserts; false for bulk routing.
   * @throws LowLevelPutException when routing fails, overload occurs, or internal errors arise.
   * @throws IllegalArgumentException if the block type is unsupported for insert.
   */
  public void realPut(
      KeyBlock block,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag)
      throws LowLevelPutException {
    switch (block) {
      case CHKBlock kBlock1 ->
          realPutCHK(
              kBlock1,
              canWriteClientCache,
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
              realTimeFlag);
      case SSKBlock kBlock ->
          realPutSSK(
              kBlock,
              canWriteClientCache,
              forkOnCacheable,
              preferInsert,
              ignoreLowBackoff,
              realTimeFlag);
      default -> throw new IllegalArgumentException("Unknown put type " + block.getClass());
    }
  }

  /**
   * Synchronously inserts a CHK block and applies local caching rules.
   *
   * <p>This variant constructs a CHK insert sender, waits for completion, reports costs, and stores
   * the block according to cache policy. It blocks until the insert completes and throws a {@link
   * LowLevelPutException} on routing failure, overload, or internal errors. The method generates
   * and locks a request UID internally and releases it before returning to the caller.
   *
   * @param block CHK block to insert and potentially store locally.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable true to fork inserts when the block is cacheable.
   * @param preferInsert true to prefer insert strategies when alternatives exist.
   * @param ignoreLowBackoff true to ignore low backoff during routing decisions.
   * @param realTimeFlag true for latency-optimized inserts; false for bulk routing.
   * @throws LowLevelPutException when routing fails, overload is reported, or internal errors
   *     arise.
   */
  public void realPutCHK(
      CHKBlock block,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag)
      throws LowLevelPutException {
    byte[] data = block.getData();
    byte[] headers = block.getHeaders();
    NodeRoutingSubsystem.ChkInsertOptions options =
        NodeClientCoreSupport.buildChkInsertOptions(
            headers,
            data,
            canWriteClientCache,
            forkOnCacheable,
            preferInsert,
            ignoreLowBackoff,
            realTimeFlag);
    CHKInsertSender is;
    long uid = makeUID();
    InsertTag tag = new InsertTag(false, InsertTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!node.routing().tracker().lockUID(uid, false, true, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    try {
      long startTime = System.currentTimeMillis();
      is = node.routing().makeInsertSender(block.getKey(), node.maxHTL(), uid, tag, null, options);
      boolean hasReceivedRejectedOverload = awaitChkCompletion(is, realTimeFlag);

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Completed {} overload={} {}", uid, hasReceivedRejectedOverload, is.getStatusString());

      maybeReportChkCompleted(is, uid, startTime, realTimeFlag, block);

      // Get status explicitly, *after* completed(), so that it will be RECEIVE_FAILED if the
      // receive failed.
      int status = is.getStatus();
      reportChkInsertCosts(status, is);
      storeChkLocally(is, block, canWriteClientCache);

      logChkInsertResult(status, is, block);
      if (status != CHKInsertSender.SUCCESS) {
        throwForChkPutStatus(is);
      }
    } finally {
      tag.unlockHandler();
    }
  }

  private void maybeReportChkCompleted(
      CHKInsertSender is, long uid, long startTime, boolean realTimeFlag, CHKBlock block) {
    if (is.sentRequest()
        && (is.uid == uid)
        && ((is.getStatus() == CHKInsertSender.ROUTE_NOT_FOUND)
            || (is.getStatus() == CHKInsertSender.SUCCESS))) {
      long endTime = System.currentTimeMillis();
      long len = endTime - startTime;
      requestStarters.getThrottle(false, true, realTimeFlag).successfulCompletion(len);
      requestStarters.requestCompleted(false, true, block.getKey(), realTimeFlag);
    }
  }

  private void reportChkInsertCosts(int status, CHKInsertSender is) {
    if (status != CHKInsertSender.TIMED_OUT
        && status != CHKInsertSender.GENERATED_REJECTED_OVERLOAD
        && status != CHKInsertSender.INTERNAL_ERROR
        && status != CHKInsertSender.ROUTE_REALLY_NOT_FOUND) {
      int sent = is.getTotalSentBytes();
      int received = is.getTotalReceivedBytes();
      if (LOG.isDebugEnabled())
        LOG.debug("Local CHK insert cost {}/{}" + LOG_BYTES_OPEN + "{})", sent, received, status);
      node.network().stats().localChkInsertBytesSentAverage.report(sent);
      node.network().stats().localChkInsertBytesReceivedAverage.report(received);
      if (status == CHKInsertSender.SUCCESS)
        node.network().stats().successfulChkInsertBytesSentAverage.report(sent);
    }
  }

  private void storeChkLocally(CHKInsertSender is, CHKBlock block, boolean canWriteClientCache) {
    boolean deep =
        node.routing()
            .shouldStoreDeep(block.getKey(), null, is == null ? new PeerNode[0] : is.getRoutedTo());
    try {
      node.storage().store(block, deep, canWriteClientCache, false, false);
    } catch (KeyCollisionException _) {
      // CHKs don't collide
    }
  }

  private void logChkInsertResult(int status, CHKInsertSender is, CHKBlock block) {
    if (status == CHKInsertSender.SUCCESS) {
      LOG.info("Succeeded inserting {}", block);
    } else {
      String msg = "Failed inserting " + block + " : " + is.getStatusString();
      if (status == CHKInsertSender.ROUTE_NOT_FOUND)
        msg +=
            " - this is normal on small networks; the data will still be propagated, but it can't"
                + " find the 20+ nodes needed for full success";
      if (is.getStatus() != CHKInsertSender.ROUTE_NOT_FOUND) LOG.error(msg);
      else LOG.info(msg);
    }
  }

  private boolean awaitChkCompletion(CHKInsertSender is, boolean realTimeFlag) {
    boolean overloaded = awaitChkInitialStatus(is, realTimeFlag);
    return awaitChkFinalCompletion(is, realTimeFlag, overloaded);
  }

  private boolean awaitChkInitialStatus(CHKInsertSender is, boolean realTimeFlag) {
    boolean hasReceivedRejectedOverload = false;
    while (true) {
      if (is.getStatus() == CHKInsertSender.NOT_FINISHED) {
        is.waitIfNotFinished(SECONDS.toMillis(5));
      }
      if (is.getStatus() != CHKInsertSender.NOT_FINISHED) break;
      if ((!hasReceivedRejectedOverload) && is.receivedRejectedOverload()) {
        hasReceivedRejectedOverload = true;
        requestStarters.rejectedOverload(false, true, realTimeFlag);
      }
    }
    return hasReceivedRejectedOverload;
  }

  private boolean awaitChkFinalCompletion(
      CHKInsertSender is, boolean realTimeFlag, boolean hasReceivedRejectedOverload) {
    while (!is.completed()) {
      is.waitIfNotCompleted(SECONDS.toMillis(10));
      if (is.anyTransfersFailed() && (!hasReceivedRejectedOverload)) {
        hasReceivedRejectedOverload = true; // not strictly true but same effect
        requestStarters.rejectedOverload(false, true, realTimeFlag);
      }
    }
    return hasReceivedRejectedOverload;
  }

  private void throwForChkPutStatus(CHKInsertSender is) throws LowLevelPutException {
    switch (is.getStatus()) {
      case CHKInsertSender.NOT_FINISHED:
        LOG.error("IS still running in putCHK!: {}", is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
      case CHKInsertSender.GENERATED_REJECTED_OVERLOAD, CHKInsertSender.TIMED_OUT:
        throw new LowLevelPutException(LowLevelPutException.REJECTED_OVERLOAD);
      case CHKInsertSender.ROUTE_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND);
      case CHKInsertSender.ROUTE_REALLY_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_REALLY_NOT_FOUND);
      case CHKInsertSender.INTERNAL_ERROR:
      default:
        LOG.error("Unknown CHKInsertSender code in putCHK: {} on {}", is.getStatus(), is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
  }

  /**
   * Synchronously inserts an SSK block and handles collision checks.
   *
   * <p>This method performs a local collision check using the client cache, starts an SSK insert
   * sender, and waits for completion. It reports costs, stores the block when appropriate, and
   * throws {@link LowLevelPutException} for collisions, routing failures, overload, or internal
   * errors. The call blocks until the insert completes and always releases the request UID before
   * returning.
   *
   * @param block SSK block to insert and potentially store locally.
   * @param canWriteClientCache whether the insert may update the client cache.
   * @param forkOnCacheable true to fork inserts when the block is cacheable.
   * @param preferInsert true to prefer insert strategies when alternatives exist.
   * @param ignoreLowBackoff true to ignore low backoff during routing decisions.
   * @param realTimeFlag true for latency-optimized inserts; false for bulk routing.
   * @throws LowLevelPutException on collision, routing failure, overload, or internal errors.
   */
  public void realPutSSK(
      SSKBlock block,
      boolean canWriteClientCache,
      boolean forkOnCacheable,
      boolean preferInsert,
      boolean ignoreLowBackoff,
      boolean realTimeFlag)
      throws LowLevelPutException {
    SSKInsertSender is;
    long uid = makeUID();
    InsertTag tag = new InsertTag(true, InsertTag.START.LOCAL, null, realTimeFlag, uid, node);
    if (!node.routing().tracker().lockUID(uid, true, true, false, true, realTimeFlag, tag)) {
      LOG.error(MSG_CANNOT_LOCK_UID + "{}" + MSG_BROKEN_PRNG, uid);
      throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
    tag.setAccepted();
    try {
      long startTime = System.currentTimeMillis();
      // Be consistent: use the client cache to check for collisions as this is a local insert.
      SSKBlock altBlock =
          node.storage()
              .fetch(block.getKey(), false, true, canWriteClientCache, false, false, null);
      if (altBlock != null && !altBlock.equals(block)) throw new LowLevelPutException(altBlock);
      is =
          node.routing()
              .makeInsertSender(
                  block,
                  node.maxHTL(),
                  uid,
                  tag,
                  null,
                  NodeRoutingSubsystem.SskInsertOptions.of()
                      .withFromStore(false)
                      .withCanWriteClientCache(canWriteClientCache)
                      .withCanWriteDatastore(false)
                      .withForkOnCacheable(forkOnCacheable)
                      .withPreferInsert(preferInsert)
                      .withIgnoreLowBackoff(ignoreLowBackoff)
                      .withRealTimeFlag(realTimeFlag));
      boolean hasReceivedRejectedOverload = awaitSskCompletion(is, realTimeFlag);

      if (LOG.isDebugEnabled())
        LOG.debug(
            "Completed {} overload={} {}", uid, hasReceivedRejectedOverload, is.getStatusString());

      // Finished?
      maybeReportSskCompleted(is, uid, startTime, realTimeFlag, block, hasReceivedRejectedOverload);

      int status = is.getStatus();

      reportSskInsertCosts(status, is);
      handleSskCollisionOrStore(is, block, canWriteClientCache);

      logSskInsertResult(status, is, block);
      if (status != SSKInsertSender.SUCCESS) {
        throwForSskPutStatus(is);
      }
    } finally {
      tag.unlockHandler();
    }
  }

  private boolean awaitSskCompletion(SSKInsertSender is, boolean realTimeFlag) {
    boolean overloaded = awaitSskInitialStatus(is, realTimeFlag);
    return awaitSskFinalCompletion(is, overloaded);
  }

  private boolean awaitSskInitialStatus(SSKInsertSender is, boolean realTimeFlag) {
    boolean hasReceivedRejectedOverload = false;
    while (true) {
      if (is.getStatus() == SSKInsertSender.NOT_FINISHED) {
        is.waitIfNotFinished(SECONDS.toMillis(5));
      }
      if (is.getStatus() != SSKInsertSender.NOT_FINISHED) break;
      if ((!hasReceivedRejectedOverload) && is.receivedRejectedOverload()) {
        hasReceivedRejectedOverload = true;
        requestStarters.rejectedOverload(true, true, realTimeFlag);
      }
    }
    return hasReceivedRejectedOverload;
  }

  private boolean awaitSskFinalCompletion(SSKInsertSender is, boolean hasReceivedRejectedOverload) {
    while (is.getStatus() == SSKInsertSender.NOT_FINISHED) {
      is.waitIfNotFinished(SECONDS.toMillis(10));
    }
    return hasReceivedRejectedOverload;
  }

  private void throwForSskPutStatus(SSKInsertSender is) throws LowLevelPutException {
    switch (is.getStatus()) {
      case SSKInsertSender.NOT_FINISHED:
        LOG.error("IS still running in putCHK!: {}", is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
      case SSKInsertSender.GENERATED_REJECTED_OVERLOAD, SSKInsertSender.TIMED_OUT:
        throw new LowLevelPutException(LowLevelPutException.REJECTED_OVERLOAD);
      case SSKInsertSender.ROUTE_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND);
      case SSKInsertSender.ROUTE_REALLY_NOT_FOUND:
        throw new LowLevelPutException(LowLevelPutException.ROUTE_REALLY_NOT_FOUND);
      case SSKInsertSender.INTERNAL_ERROR:
      default:
        LOG.error("Unknown CHKInsertSender code in putSSK: {} on {}", is.getStatus(), is);
        throw new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR);
    }
  }

  private void reportSskInsertCosts(int status, SSKInsertSender is) {
    if (status != CHKInsertSender.TIMED_OUT
        && status != CHKInsertSender.GENERATED_REJECTED_OVERLOAD
        && status != CHKInsertSender.INTERNAL_ERROR
        && status != CHKInsertSender.ROUTE_REALLY_NOT_FOUND) {
      int sent = is.getTotalSentBytes();
      int received = is.getTotalReceivedBytes();
      if (LOG.isDebugEnabled())
        LOG.debug("Local SSK insert cost {}/{}" + LOG_BYTES_OPEN + "{})", sent, received, status);
      node.network().stats().localSskInsertBytesSentAverage.report(sent);
      node.network().stats().localSskInsertBytesReceivedAverage.report(received);
      if (status == SSKInsertSender.SUCCESS)
        node.network().stats().successfulSskInsertBytesSentAverage.report(sent);
    }
  }

  private void maybeReportSskCompleted(
      SSKInsertSender is,
      long uid,
      long startTime,
      boolean realTimeFlag,
      SSKBlock block,
      boolean hasReceivedRejectedOverload) {
    if (!hasReceivedRejectedOverload
        && is.sentRequest()
        && (is.uid == uid)
        && ((is.getStatus() == SSKInsertSender.ROUTE_NOT_FOUND)
            || (is.getStatus() == SSKInsertSender.SUCCESS))) {
      long endTime = System.currentTimeMillis();
      long rtt = endTime - startTime;
      requestStarters.requestCompleted(true, true, block.getKey(), realTimeFlag);
      requestStarters.getThrottle(true, true, realTimeFlag).successfulCompletion(rtt);
    }
  }

  private void handleSskCollisionOrStore(
      SSKInsertSender is, SSKBlock block, boolean canWriteClientCache) throws LowLevelPutException {
    boolean deep =
        node.routing()
            .shouldStoreDeep(block.getKey(), null, is == null ? new PeerNode[0] : is.getRoutedTo());

    if (is != null && is.hasCollided()) {
      SSKBlock collided = is.getBlock();
      try {
        node.storage().storeInsert(collided, deep, true, canWriteClientCache, false);
      } catch (KeyCollisionException e) {
        LOG.info("collision race? is={}", is, e);
      }
      throw new LowLevelPutException(collided);
    }
    try {
      node.storage().storeInsert(block, deep, false, canWriteClientCache, false);
    } catch (KeyCollisionException e) {
      NodeSSK key = block.getKey();
      KeyBlock collided = node.storage().fetch(key, true, canWriteClientCache, false, false, null);
      if (collided == null) {
        LOG.error("Collided but no key?!");
        try {
          node.storage().store(block, false, canWriteClientCache, false, false);
        } catch (KeyCollisionException _) {
          LOG.error("Collided but no key and still collided!");
          throw new LowLevelPutException(
              LowLevelPutException.INTERNAL_ERROR,
              "Collided, can't find block, but still collides!",
              e);
        }
      }
      throw new LowLevelPutException(collided);
    }
  }

  private void logSskInsertResult(int status, SSKInsertSender is, SSKBlock block) {
    if (status == SSKInsertSender.SUCCESS) {
      LOG.info("Succeeded inserting {}", block);
    } else {
      String msg = "Failed inserting " + block + " : " + is.getStatusString();
      if (status == CHKInsertSender.ROUTE_NOT_FOUND)
        msg +=
            " - this is normal on small networks; the data will still be propagated, but it can't"
                + " find the 20+ nodes needed for full success";
      if (is.getStatus() != SSKInsertSender.ROUTE_NOT_FOUND) LOG.error(msg);
      else LOG.info(msg);
    }
  }

  /**
   * Queues a low-priority reinsert of a key block.
   *
   * <p>The block is wrapped in a {@link SimpleSendableInsert} and scheduled on the request starters
   * at the maximum priority class for reinserts. The operation is asynchronous: it enqueues work
   * and returns immediately without waiting for completion. Use this method to refresh availability
   * for already known data without blocking the caller.
   *
   * @param block key block to reinsert and schedule for background routing.
   */
  public void queueRandomReinsert(KeyBlock block) {
    SimpleSendableInsert ssi =
        new SimpleSendableInsert(core, block, RequestStarter.MAXIMUM_PRIORITY_CLASS);
    if (LOG.isDebugEnabled()) LOG.debug("Queueing random reinsert for {} : {}", block, ssi);
    ssi.schedule();
  }

  /**
   * Generates a random UID for requests.
   *
   * <p>Note: {@code -1} is reserved internally and is never returned. If a peer uses {@code -1} it
   * is merely scheduled more slowly (round-robin with no-UID messages).
   */
  private long makeUID() {
    while (true) {
      long uid = random.nextLong();
      if (uid != -1) return uid;
    }
  }
}
