package network.crypta.runtime.alerts.feed;

/**
 * Runtime-owned sink for user-alert feed events.
 *
 * <p>{@link network.crypta.runtime.alerts.UserAlertManager} uses this interface to publish alerts
 * without knowing which endpoint or protocol is listening. Implementations are typically
 * lightweight adapters around a concrete delivery mechanism such as FCP, but the runtime itself
 * only depends on the act of sending an immutable {@link UserAlertFeedEvent}.
 *
 * <p>Implementations should define clear equality and lifecycle semantics when callers use them as
 * watch or unwatch keys.
 */
public interface UserAlertFeedSubscriber {
  /**
   * Delivers one runtime-owned feed event to the subscriber.
   *
   * <p>The caller supplies an immutable event snapshot and expects the implementation to encode or
   * forward it using its own transport-specific rules. Implementations may reject unsupported or
   * malformed events by throwing a runtime exception, but they should not mutate the supplied
   * object.
   *
   * @param event immutable runtime-owned event snapshot to deliver to the subscriber
   * @throws NullPointerException if the implementation requires a non-null event and {@code event}
   *     is {@code null}
   */
  void send(UserAlertFeedEvent event);
}
