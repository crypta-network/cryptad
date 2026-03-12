package network.crypta.io.comm;

/**
 * Callback interface for asynchronous message filter events.
 *
 * <p>Implementations receive notifications when a message matches a filter, when a filter is
 * expired, and when a peer connection is disconnected or restarted. Callbacks may be invoked from
 * transport or maintenance threads; implementations should avoid long-running or blocking work and
 * should offload heavy processing where appropriate.
 *
 * <p>Unless otherwise stated, callbacks are invoked after the corresponding filter has been removed
 * and without holding filter-list locks. See individual method documentation for threading/locking
 * constraints.
 *
 * @author toad
 */
public interface AsyncMessageFilterCallback {

  /**
   * Notifies that a message matched the filter.
   *
   * <p>The filter is removed before this callback is invoked, and no filter-list locks are held by
   * the caller. Implementations should return promptly and perform only lightweight work in this
   * method.
   *
   * @param m the {@link Message} that matched the filter; never modified by the caller.
   */
  void onMatched(Message m);

  /**
   * Indicates whether the filter should be timed out immediately.
   *
   * <p>This method may be called while USM locks are held by the caller. The implementation must
   * not perform actions that acquire USM-related locks or that could trigger sending messages. Keep
   * the check side effect free and fast.
   *
   * @return {@code true} to request immediate timeout/removal; {@code false} to keep the filter
   *     active.
   */
  boolean shouldTimeout();

  /**
   * Notifies that the filter has timed out and was removed from matching.
   *
   * <p>Use this to release resources associated with the filter or to update any related state.
   */
  void onTimeout();

  /**
   * Notifies that the filter was dropped due to a peer connection being disconnected.
   *
   * @param ctx the {@link PeerContext} for the disconnected peer.
   */
  void onDisconnect(PeerContext ctx);

  /**
   * Notifies that the filter was dropped due to a peer connection restart.
   *
   * @param ctx the {@link PeerContext} for the restarted peer.
   */
  void onRestarted(PeerContext ctx);
}
