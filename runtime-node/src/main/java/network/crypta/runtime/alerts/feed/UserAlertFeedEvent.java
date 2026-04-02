package network.crypta.runtime.alerts.feed;

/**
 * Marker interface for immutable runtime-owned user-alert feed events.
 *
 * <p>This interface defines the transport-neutral alert feed seam owned by {@code
 * network.crypta.runtime.alerts}. Concrete event records capture the data that alert producers want
 * to publish without depending on FCP message classes or connection handlers. The runtime can
 * therefore notify subscribers in a stable, testable format while endpoint packages remain
 * responsible for any protocol-specific encoding.
 *
 * <p>Implementations are expected to behave as plain data carriers. They should not perform I/O,
 * hold mutable state, or encode transport-specific behavior.
 *
 * @see BasicUserAlertFeedEvent
 * @see BookmarkUserAlertFeedEvent
 * @see UriUserAlertFeedEvent
 * @see TextUserAlertFeedEvent
 */
public interface UserAlertFeedEvent {}
