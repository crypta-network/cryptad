package network.crypta.clients.fcp.bridge;

import java.util.Objects;
import network.crypta.clients.fcp.FCPConnectionHandler;
import network.crypta.runtime.alerts.feed.UserAlertFeedEvent;
import network.crypta.runtime.alerts.feed.UserAlertFeedSubscriber;

/**
 * FCP-side subscriber adapter for runtime-owned user-alert feed events.
 *
 * <p>This record wraps an {@link FCPConnectionHandler} and implements the runtime-owned {@link
 * UserAlertFeedSubscriber} interface so {@code UserAlertManager} can publish feed events without
 * depending on FCP types directly. When it receives a runtime event, it delegates encoding to
 * {@link FcpUserAlertFeedMessageFactory} and then sends the resulting protocol message on the
 * wrapped connection.
 *
 * <p>Because this type is a record, equality and hashing are tied to the wrapped handler instance.
 * That makes it suitable as a stable watch or unwatch key when FCP runtime wiring recreates the
 * adapter around the same connection handler.
 *
 * @param handler active FCP connection handler that receives encoded feed messages
 */
public record FcpUserAlertFeedSubscriber(FCPConnectionHandler handler)
    implements UserAlertFeedSubscriber {

  /**
   * Creates a subscriber adapter bound to one FCP connection.
   *
   * <p>The adapter does not own the lifecycle of the wrapped handler. Callers remain responsible
   * for registering, unregistering, and closing the connection itself. The constructor validates
   * only that a handler reference is present, so the later feed delivery does not fail with an
   * ambiguous null dereference.
   *
   * @param handler active FCP connection handler that receives encoded feed messages
   * @throws NullPointerException if {@code handler} is {@code null}
   */
  public FcpUserAlertFeedSubscriber {
    Objects.requireNonNull(handler, "handler");
  }

  /**
   * Sends one runtime-owned feed event through the wrapped FCP connection.
   *
   * <p>This method first converts the event into the matching FCP message type and then passes the
   * encoded message to {@link FCPConnectionHandler#send(network.crypta.clients.fcp.FCPMessage)}.
   * The call is synchronous with respect to the wrapped handler invocation and preserves the same
   * event-to-message mapping as the legacy direct alert code path.
   *
   * @param event immutable runtime-owned feed event snapshot to encode and deliver
   * @throws NullPointerException if {@code event} is {@code null}
   * @throws IllegalArgumentException if the event type is not supported by the FCP bridge
   */
  @Override
  public void send(UserAlertFeedEvent event) {
    handler.send(FcpUserAlertFeedMessageFactory.create(event));
  }
}
