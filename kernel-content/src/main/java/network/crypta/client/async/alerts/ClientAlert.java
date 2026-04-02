package network.crypta.client.async.alerts;

/**
 * Marks an alert value that can cross the client-layer alert seam.
 *
 * <p>This interface is intentionally empty. Client code only needs a stable type that says "this
 * object is safe to hand to the alert sink" without taking a direct dependency on runtime-owned
 * alert implementations. The concrete alert model, rendering, and operator-facing registration
 * remain on the runtime side of the boundary.
 *
 * <p>Typical call flow is straightforward: client-layer code creates or receives an implementation,
 * passes it to {@link ClientAlertSink#post(ClientAlert)}, and relies on the owning runtime adapter
 * to validate and route it. Implementations should generally behave like immutable notification
 * values because they may be queued briefly during startup before the sink is ready.
 *
 * @see ClientAlertSink
 */
public interface ClientAlert {}
