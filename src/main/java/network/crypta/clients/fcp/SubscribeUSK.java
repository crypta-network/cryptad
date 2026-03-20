package network.crypta.clients.fcp;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.USKCallback;
import network.crypta.client.async.USKFoundEdition;
import network.crypta.client.async.USKProgressCallback;
import network.crypta.keys.USK;

/**
 * Bridges an FCP client subscription to the node's USK manager.
 *
 * <p>This helper wires a {@link SubscribeUSKMessage} received over FCP into the asynchronous USK
 * subscription facilities provided by the insert runtime support seam. It registers itself as the
 * {@link USKProgressCallback} so that progress, network activity, and discovered editions are fed
 * back to the originating {@link FCPConnectionHandler}. Instances are intentionally lightweight and
 * short-lived: they register with the node on construction and can be removed via {@link
 * #unsubscribe()} when the client disconnects or no longer requires updates.
 *
 * <p>Typical usage is driven by the FCP protocol flow: the handler constructs this class when a
 * client issues a subscription request, lets the node push progress callbacks, and eventually calls
 * {@link #unsubscribe()} during teardown. The object does not perform retries itself; it relies on
 * the underlying USK manager for polling cadence, sparse polling decisions, and cache ownership.
 * All callbacks are expected to be invoked on the node's internal threads, so callers should avoid
 * long-running work and keep message emission cheap. Thread-safety is limited to delegating into
 * the handler and USK manager; the class itself is effectively single-use per subscription.
 *
 * <ul>
 *   <li>Relays edition discoveries, including whether data was newly accepted.
 *   <li>Reports network-send phases and polling round completion to the FCP client.
 *   <li>Preserves the polling priorities supplied by the client for normal and progress phases.
 * </ul>
 *
 * @see USKProgressCallback
 * @see network.crypta.client.async.USKManager#subscribe
 * @see network.crypta.client.async.USKManager#subscribeSparse
 */
public final class SubscribeUSK implements USKProgressCallback {
  final FCPConnectionHandler handler;
  final String clientIdentifier;
  final FcpInsertRuntimeSupport runtimeSupport;
  final boolean dontPoll;
  final short prio;
  final short prioProgress;
  final USK usk;
  final USKCallback toUnsub;

  /**
   * Creates and registers a subscription that reflects the caller's FCP request parameters.
   *
   * <p>The constructor immediately adds this callback to both the connection handler and the USK
   * manager. Depending on the {@code dontPoll} and {@code sparsePoll} flags in the supplied
   * message, it chooses either sparse subscription mode or the default polling behavior. No
   * additional initialization is required after construction.
   *
   * @param message parsed FCP subscribe request containing keys, flags, and priorities; never null.
   * @param runtimeSupport insert runtime support that owns the USK manager and polling logic.
   * @param handler connection handler used to emit FCP responses back to the requesting client.
   * @throws IdentifierCollisionException if the identifier already exists on this handler and
   *     cannot be reused for another subscription.
   */
  SubscribeUSK(
      SubscribeUSKMessage message,
      FcpInsertRuntimeSupport runtimeSupport,
      FCPConnectionHandler handler)
      throws IdentifierCollisionException {
    this.handler = handler;
    this.dontPoll = message.dontPoll;
    this.clientIdentifier = message.clientIdentifier;
    this.runtimeSupport = runtimeSupport;
    this.usk = message.key;
    prio = message.prio;
    prioProgress = message.prioProgress;
    handler.addUSKSubscription(clientIdentifier, this);
    if (!message.dontPoll && message.sparsePoll)
      toUnsub =
          runtimeSupport
              .uskManager()
              .subscribeSparse(
                  message.key,
                  this,
                  message.ignoreUSKDatehints,
                  handler.getRebootClient().lowLevelClient(message.realTimeFlag));
    else {
      runtimeSupport
          .uskManager()
          .subscribe(
              message.key,
              this,
              !message.dontPoll,
              message.ignoreUSKDatehints,
              handler.getRebootClient().lowLevelClient(message.realTimeFlag));
      toUnsub = this;
    }
  }

  /**
   * Receives notification that a specific USK edition was located and processed.
   *
   * <p>The callback is triggered by the USK manager whenever it fetches an edition for this
   * subscription. It forwards a {@link SubscribedUSKUpdate} over FCP unless the handler has been
   * closed, in which case it unsubscribes to conserve resources. Data bytes are not sent here; only
   * edition and freshness metadata travel across the connection.
   *
   * @param foundEdition The payload describing the discovered edition and its metadata.
   */
  @Override
  public void onFoundEdition(USKFoundEdition foundEdition) {
    USK key = foundEdition.key();
    if (handler.isClosed()) {
      runtimeSupport.uskManager().unsubscribe(key, toUnsub);
      return;
    }
    FCPMessage msg =
        new SubscribedUSKUpdate(
            clientIdentifier,
            foundEdition.edition(),
            key,
            foundEdition.newKnownGood(),
            foundEdition.newSlotToo());
    handler.send(msg);
  }

  /**
   * Returns the client-requested priority for regular polling cycles.
   *
   * <p>The value originates from the FCP subscribe message and is passed through unchanged, so the
   * USK manager can schedule this subscription relative to others. Lower values typically denote
   * higher priority depending on the underlying scheduler configuration.
   *
   * @return priority hint for normal polling, as supplied by the subscribing client.
   */
  @Override
  public short getPollingPriorityNormal() {
    return prio;
  }

  /**
   * Returns the client-requested priority used while progress feedback is being emitted.
   *
   * <p>This priority can differ from the normal polling priority to bias subscriptions that are
   * mid-transfer or issuing updates to clients. It is not modified by this class; the USK manager
   * is free to interpret the value according to its scheduling rules.
   *
   * @return priority hint for progress phases, mirroring the value in the original request.
   */
  @Override
  public short getPollingPriorityProgress() {
    return prioProgress;
  }

  /**
   * Cancels the active subscription with the USK manager.
   *
   * <p>Callers should invoke this when the FCP connection closes or when the client issues an
   * unsubscribed request. The method forwards the removal to the node's USK manager using the key
   * captured at construction. It is safe to call multiple times; the manager ignores redundant
   * calls.
   */
  public void unsubscribe() {
    runtimeSupport.uskManager().unsubscribe(usk, toUnsub);
  }

  /**
   * Signals that a polling cycle is actively sending a request to the network.
   *
   * <p>The callback relays a {@link SubscribedUSKSendingToNetworkMessage} to the FCP client so it
   * can display activity state. It does not include payload details; its purpose is purely
   * observational, allowing clients to track when network traffic begins for a given subscription.
   *
   * @param context client context for the poll; may be shared with other progress callbacks.
   */
  @Override
  public void onSendingToNetwork(ClientContext context) {
    handler.send(new SubscribedUSKSendingToNetworkMessage(clientIdentifier));
  }

  /**
   * Notifies listeners that a polling round completed for this subscription.
   *
   * <p>When invoked, the method emits a {@link SubscribedUSKRoundFinishedMessage} to the FCP client
   * to mark the end of the current poll cycle. No guarantees are made about the presence of new
   * editions; the signal merely brackets a batch of network activity.
   *
   * @param context client context associated with the concluded round; may be reused by the caller.
   */
  @Override
  public void onRoundFinished(ClientContext context) {
    handler.send(new SubscribedUSKRoundFinishedMessage(clientIdentifier));
  }
}
