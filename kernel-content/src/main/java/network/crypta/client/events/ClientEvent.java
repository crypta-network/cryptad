package network.crypta.client.events;

/**
 * Describes a client-facing event emitted by higher-level operations.
 *
 * <p>This interface models a lightweight, immutable signal that conveys what happened during a
 * client request or background activity. Implementations typically wrap a concise, human-readable
 * description together with a stable integer code that can be used for programmatic routing,
 * filtering, or correlation in logs. Events are produced by components that implement
 * ClientEventProducer implementations produce these events and ClientEventListener implementations
 * consume them; listeners may log, persist, aggregate, or display them to users.
 *
 * <p>Use this type when you need to surface progress, state changes, or non-fatal conditions to the
 * client layer without throwing exceptions. A common pattern is to define small value objects for
 * concrete event kinds (for example, progress updates or expected content metadata) that implement
 * this interface and are dispatched to interested listeners. Implementations are generally
 * thread-safe by virtue of being immutable; consumers should treat instances as read-only. The
 * integer code is intended to remain stable across versions of a component, while the textual
 * description is optimized for operators and end users.
 *
 * <ul>
 *   <li>Responsibilities: identify the event, summarize it for humans, and allow filtering.
 *   <li>Scope: communicates information; it is not an error/exception transport mechanism.
 *   <li>Usage: emit from producers, subscribe via listeners, and log or render as needed.
 * </ul>
 *
 * @author oskar
 */
public interface ClientEvent {

  /**
   * Returns a human-readable description of the event.
   *
   * <p>The description should be concise, suitable for logs or status panels, and should avoid
   * embedding sensitive information. Implementations are encouraged to keep the text stable enough
   * for operators to recognize recurring conditions, while remaining clear to end users. The string
   * is informational only and must not be parsed programmatically; use {@link #getCode()} for
   * machine handling.
   *
   * <pre>{@code
   * // Example: log the description at INFO level
   * listener.receive(event, context); // typical dispatch path
   * String summary = event.getDescription();
   * }</pre>
   *
   * @return a non-null, human-oriented summary; callers do not take ownership and must not modify
   *     the returned string instance if it happens to be shared.
   */
  String getDescription();

  /**
   * Returns a stable integer that identifies the event kind.
   *
   * <p>The code is suitable for programmatic routing, de-duplication, or metric labeling. Its
   * uniqueness scope is defined by the producing component; consumers should not assume global
   * uniqueness across the entire application unless documented by a specific producer. The value is
   * intended to be stable across releases of the emitting component to support filtering policies
   * and dashboards.
   *
   * @return an integer identifier for the event type; stable within the producing component and
   *     suitable for comparisons, switches, or counters.
   */
  int getCode();
}
