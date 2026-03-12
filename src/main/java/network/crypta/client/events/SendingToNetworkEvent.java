package network.crypta.client.events;

/**
 * Event indicating that a client operation is currently sending data to the network.
 *
 * <p>This event is emitted by higher-level client workflows to announce the transition into the
 * “sending” phase, for example when a request begins transmitting payload bytes or negotiates the
 * initial network exchange. It provides a short, human-readable description suitable for logs or a
 * status panel, together with a small, stable integer code that can be used by programmatic
 * consumers to filter, route, or summarize progress. Instances are stateless and immutable; they
 * may be constructed whenever needed and safely shared across threads as read-only values.
 *
 * <p>Typical usage is to publish the event through an event producer and handle it in one or more
 * listeners that update UI, write to logs, or aggregate metrics. The integer code is intended to be
 * stable within the component that emits it so dashboards and policies remain consistent across
 * releases. Because the class carries no mutable state and performs no I/O, it imposes negligible
 * overhead and is safe to create on demand.
 *
 * <ul>
 *   <li>Responsibility: identify that transmission to the network has started.
 *   <li>Notable behavior: immutable, thread-safe, and suitable for reuse.
 *   <li>Programmatic use: rely on {@link #getCode()} for filtering and correlation.
 * </ul>
 */
public class SendingToNetworkEvent implements ClientEvent {

  static final int CODE = 0x0A;

  /**
   * Creates a new event instance representing the start of transmission to the network.
   *
   * <p>The type is stateless and immutable; constructing a new instance allocates no external
   * resources and performs no I/O. Instances may be created on demand or reused safely across
   * threads as read-only values.
   */
  public SendingToNetworkEvent() {
    // Intentionally empty: this value object has no mutable state or initialization work.
    // An explicit constructor exists for clarity and to attach Javadoc for doclint compliance.
  }

  /**
   * Returns the stable integer identifier for this event kind.
   *
   * <p>The value is constant for this type and can be used in switches, counters, or filters where
   * a compact, programmatic signal is preferable to the human-readable description. The value is
   * stable within the producing component across releases so downstream consumers can maintain
   * durable mappings.
   *
   * @return a stable, non-negative integer uniquely identifying the “sending to network” event
   *     within the emitting component; callers may compare or persist it as needed.
   */
  @Override
  public int getCode() {
    return CODE;
  }

  /**
   * Returns a concise, human-readable summary of the event.
   *
   * <p>The description is suitable for operator logs, progress indicators, or status views. It is
   * informational and not intended for programmatic parsing; prefer {@link #getCode()} when
   * implementing routing or policy decisions. The returned text is immutable and may be reused by
   * the implementation.
   *
   * @return a non-null, plain-English summary indicating that transmission to the network is in
   *     progress; callers do not assume ownership of the returned string instance.
   */
  @Override
  public String getDescription() {
    return "Sending to network";
  }
}
