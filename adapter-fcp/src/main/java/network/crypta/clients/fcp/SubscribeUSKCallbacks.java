package network.crypta.clients.fcp;

import network.crypta.keys.USK;

/**
 * Adapter-owned callback surface used by the bridge USK subscription helper.
 *
 * <p>The bridge runtime owns the concrete USK manager subscription and invokes this interface to
 * report discovered editions and polling progress back into {@code :adapter-fcp}. Implementations
 * typically live on top of {@link SubscribeUSK} and translate the callback events into FCP wire
 * messages without importing the runtime-owned USK callback types directly.
 */
public interface SubscribeUSKCallbacks {

  /**
   * Returns whether the owning FCP connection has already closed.
   *
   * <p>The bridge uses this as a guard before emitting more USK updates, so it can tear down the
   * runtime subscription promptly when the client is no longer available.
   *
   * @return {@code true} when the owning connection should no longer receive callback events
   */
  boolean isClosed();

  /**
   * Returns the client-visible identifier used when sending FCP messages.
   *
   * <p>The returned identifier is echoed in protocol messages generated from callback events so the
   * subscribing client can correlate updates with the original {@code SubscribeUSK} request.
   *
   * @return client-visible identifier associated with the active USK subscription
   */
  String clientIdentifier();

  /**
   * Returns the steady-state polling priority.
   *
   * <p>The bridge forwards this value into the runtime subscription, so normal background polling
   * competes with other work at the same priority level the FCP client requested.
   *
   * @return steady-state polling priority for the USK subscription
   */
  short pollingPriorityNormal();

  /**
   * Returns the startup or progress polling priority.
   *
   * <p>This secondary priority allows the runtime subscription to bias startup or progress-related
   * polling differently from steady-state operation when the underlying USK machinery supports it.
   *
   * @return priority to use for startup or progress-oriented polling work
   */
  short pollingPriorityProgress();

  /**
   * Handles a discovered USK edition.
   *
   * <p>The bridge invokes this when the runtime subscription finds an edition or advances its known
   * slot state. Implementations typically convert the callback into a {@code SubscribedUSKUpdate}
   * FCP message.
   *
   * @param edition discovered edition number
   * @param key resolved USK key associated with the discovered edition
   * @param newKnownGood whether the discovered edition became a new known-good edition
   * @param newSlotToo whether the discovered edition also advanced the newest known slot
   */
  void onFoundEdition(long edition, USK key, boolean newKnownGood, boolean newSlotToo);

  /**
   * Handles a polling round entering network I/O.
   *
   * <p>Implementations typically turn this into a lightweight protocol notification so clients can
   * observe that the USK subscription is actively talking to the network.
   */
  void onSendingToNetwork();

  /**
   * Handles the end of a polling round.
   *
   * <p>This callback marks the completion of one polling cycle, regardless of whether a new edition
   * was found during that round.
   */
  void onRoundFinished();
}
