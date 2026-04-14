package network.crypta.clients.fcp;

import network.crypta.keys.USK;

/**
 * Bridges an FCP client subscription to the adapter-owned USK subscription seam.
 *
 * <p>This helper keeps the FCP-side subscription state and message emission in {@code :adapter-fcp}
 * while delegating all live USK manager interaction to {@link FcpInsertRuntimeSupport}. The bridge
 * implementation owns the concrete runtime subscription and calls back through {@link
 * SubscribeUSKCallbacks} whenever editions are found or polling progress changes.
 */
public final class SubscribeUSK implements SubscribeUSKCallbacks {
  final FCPConnectionHandler handler;
  final String clientIdentifier;
  final short prio;
  final short prioProgress;
  private final UskSubscriptionHandle subscriptionHandle;

  /**
   * Creates and registers a subscription that reflects the caller's FCP request parameters.
   *
   * <p>The constructor first registers the identifier with the connection handler, so collisions
   * are reported using the existing FCP behavior. It then asks {@link FcpInsertRuntimeSupport} to
   * create the live runtime subscription behind an opaque handle owned by the adapter.
   *
   * @param message parsed FCP subscribe request containing keys, flags, and priorities
   * @param runtimeSupport insert runtime support that owns the concrete runtime subscription wiring
   * @param handler connection handler used to emit FCP responses back to the requesting client
   * @throws IdentifierCollisionException if the identifier already exists on this handler
   */
  SubscribeUSK(
      SubscribeUSKMessage message,
      FcpInsertRuntimeSupport runtimeSupport,
      FCPConnectionHandler handler)
      throws IdentifierCollisionException {
    this.handler = handler;
    this.clientIdentifier = message.clientIdentifier;
    this.prio = message.prio;
    this.prioProgress = message.prioProgress;
    handler.addUSKSubscription(clientIdentifier, this);
    this.subscriptionHandle = runtimeSupport.subscribeUSK(message, this, handler);
  }

  /**
   * Returns the client-requested priority for regular polling cycles.
   *
   * @return priority hint for normal polling, as supplied by the subscribing client
   */
  public short getPollingPriorityNormal() {
    return prio;
  }

  /**
   * Returns the client-requested priority used while progress feedback is being emitted.
   *
   * @return priority hint for progress phases, mirroring the value in the original request
   */
  public short getPollingPriorityProgress() {
    return prioProgress;
  }

  /**
   * Cancels the active subscription through the opaque runtime handle.
   *
   * <p>Callers invoke this when the FCP connection closes or the client explicitly unsubscribes.
   */
  public void unsubscribe() {
    subscriptionHandle.unsubscribe();
  }

  @Override
  public boolean isClosed() {
    return handler.isClosed();
  }

  @Override
  public String clientIdentifier() {
    return clientIdentifier;
  }

  @Override
  public short pollingPriorityNormal() {
    return prio;
  }

  @Override
  public short pollingPriorityProgress() {
    return prioProgress;
  }

  @Override
  public void onFoundEdition(long edition, USK key, boolean newKnownGood, boolean newSlotToo) {
    handler.send(new SubscribedUSKUpdate(clientIdentifier, edition, key, newKnownGood, newSlotToo));
  }

  @Override
  public void onSendingToNetwork() {
    handler.send(new SubscribedUSKSendingToNetworkMessage(clientIdentifier));
  }

  @Override
  public void onRoundFinished() {
    handler.send(new SubscribedUSKRoundFinishedMessage(clientIdentifier));
  }
}
