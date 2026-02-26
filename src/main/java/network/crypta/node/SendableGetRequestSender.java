package network.crypta.node;

import network.crypta.client.async.ChosenBlock;
import network.crypta.client.async.ClientContext;
import network.crypta.keys.ClientKey;
import network.crypta.keys.Key;
import network.crypta.node.subsystem.NodeRoutingSubsystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sends GET requests to the node asynchronously.
 *
 * <p>This implementation submits the request to {@link NodeClientCoreTransfers#asyncGet(Key,
 * RequestCompletionListener,
 * network.crypta.node.subsystem.NodeRoutingSubsystem.RequestSenderOptions)} and returns
 * immediately. It delivers results via the provided {@link RequestCompletionListener} callbacks
 * which, in turn, notify the originating {@link SendableRequest}.
 *
 * <p>Threading: this class does not block the caller; completion occurs on whatever thread the core
 * uses to invoke the listener. Callers should not assume callbacks run on the scheduler thread.
 */
public class SendableGetRequestSender implements SendableRequestSender {
  private static final Logger LOG = LoggerFactory.getLogger(SendableGetRequestSender.class);

  /**
   * Creates a new sender that submits GET requests asynchronously and reports completion via the
   * provided {@link RequestCompletionListener}.
   */
  public SendableGetRequestSender() {
    // Intentionally empty: this sender is stateless and requires no initialization.
    // Having an explicit no-args constructor aids DI/serialization tools and clarifies intent.
  }

  /**
   * Indicates whether {@link #send(NodeClientCore, RequestScheduler, ClientContext, ChosenBlock)}
   * blocks the calling thread.
   *
   * @return {@code false}. The request is submitted asynchronously.
   */
  @Override
  public boolean sendIsBlocking() {
    return false;
  }

  /**
   * Submits an asynchronous GET for the provided block.
   *
   * <p>Validates the request, then calls {@link NodeClientCoreTransfers#asyncGet(Key,
   * RequestCompletionListener,
   * network.crypta.node.subsystem.NodeRoutingSubsystem.RequestSenderOptions)}. Completion is
   * reported via the supplied listener which delegates to {@code req.onFetchSuccess(context)} or
   * {@code req.onFailure(e, context)}.
   *
   * <p>Return semantics: - Returns {@code false} when no request is submitted (e.g., missing key,
   * canceled request) so the scheduler can try another. - Returns {@code true} once a request is
   * submitted or when an internal error is converted to a failure callback.
   *
   * <p>Exceptions are handled internally and reported to the request as {@link
   * LowLevelGetException}; this method does not throw.
   *
   * @param core the node client core used to dispatch the GET; non-null
   * @param sched the scheduler invoking this sender; may be unused
   * @param context client context propagated to callbacks; non-null
   * @param req the chosen block to fetch; must provide a non-null {@code ckey}
   * @return {@code true} if submitted or converted to a failure; {@code false} if the scheduler
   *     should pick a different request
   */
  @Override
  @SuppressWarnings("java:S1181")
  public boolean send(
      NodeClientCore core,
      final RequestScheduler sched,
      final ClientContext context,
      final ChosenBlock req) {
    // Token is a stable identifier used for logging/debugging.
    Object keyNum = req.token;
    final ClientKey key = req.ckey;
    // Guard against malformed requests: the client key must be present.
    if (key == null) {
      LOG.error("Send aborted: key is null (token={}, request={})", keyNum, req);
      return false;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Submit GET (token={}, key={})", keyNum, key);
    if (req.isCancelled()) {
      if (LOG.isDebugEnabled()) LOG.debug("Request cancelled: {}", req);
      try {
        req.onFailure(new LowLevelGetException(LowLevelGetException.CANCELLED), context);
      } catch (RuntimeException | Error callbackEx) {
        LOG.error("Failure callback threw (CANCELLED): {}", callbackEx, callbackEx);
      }
      return false;
    }
    try {
      /*
       * Resolve the node-level key and submit the asynchronous GET.
       * Options control store usage, client cache writes, and realtime priority.
       */
      final Key k = key.getNodeKey();
      NodeRoutingSubsystem.RequestSenderOptions options =
          NodeRoutingSubsystem.RequestSenderOptions.of(
              req.localRequestOnly,
              req.ignoreStore,
              false,
              !req.ignoreStore,
              req.canWriteClientCache,
              req.realTimeFlag);
      core.getTransfers()
          .asyncGet(
              k,
              new RequestCompletionListener() {

                @Override
                public void onSucceeded() {
                  req.onFetchSuccess(context);
                }

                @Override
                public void onFailed(LowLevelGetException e) {
                  req.onFailure(e, context);
                }
              },
              options,
              req.getExternalRequestIdentifier());
    } catch (RuntimeException | Error t) {
      // Convert unexpected throwables into a failure callback to keep the scheduler healthy.
      LOG.error("Unhandled throwable in send: {}", t, t);
      try {
        req.onFailure(new LowLevelGetException(LowLevelGetException.INTERNAL_ERROR), context);
      } catch (RuntimeException | Error callbackEx) {
        LOG.error("Failure callback threw (INTERNAL_ERROR): {}", callbackEx, callbackEx);
      }
      return true;
    }
    return true;
  }
}
