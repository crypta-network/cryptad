package network.crypta.client.events;

import network.crypta.client.async.ClientContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * Logs client-layer events to SLF4J at a configured severity.
 *
 * <p>This lightweight listener adapts {@link ClientEvent} notifications into structured log lines
 * using the application logger. It is intended for cases where event propagation should not affect
 * control flow and a concise, human‑readable summary is sufficient. The instance is constructed
 * with a desired {@link org.slf4j.event.Level} and, upon {@link #receive(ClientEvent,
 * ClientContext) receipt}, emits the event description at that level. For {@code DEBUG} and {@code
 * TRACE}, the logger's enablement is consulted to avoid unnecessary formatting and noise; when
 * {@code TRACE} is requested but disabled, the message falls back to {@code DEBUG} or {@code INFO}
 * depending on what is enabled.
 *
 * <p>The class is stateless aside from its configuration and therefore safe to reuse across
 * threads. It performs no I/O beyond logging, retains no references to delivered events, and does
 * not throw. Consumers can register a single instance with multiple producers when identical
 * routing is desired.
 *
 * <ul>
 *   <li>Responsibility: convert {@code ClientEvent.getDescription()} to a log entry.
 *   <li>Thread-safety: immutable configuration; the listener itself is thread-safe.
 *   <li>Notable behavior: conditional emission for {@code DEBUG}/{@code TRACE} levels.
 * </ul>
 *
 * @author oskar
 * @see ClientEvent
 * @see ClientEventListener
 */
public class EventLogger implements ClientEventListener {
  private static final Logger LOG = LoggerFactory.getLogger(EventLogger.class);

  final Level slf4jLevel;
  final boolean removeWithProducer;

  /**
   * Creates a logger-backed event listener with the given severity.
   *
   * <p>The supplied {@code level} determines how {@link #receive(ClientEvent, ClientContext)} emits
   * messages: {@code ERROR}, {@code WARN}, and {@code INFO} always log at the requested level;
   * {@code DEBUG} logs only when debug is enabled; {@code TRACE} logs at trace when enabled and
   * otherwise falls back to debug or info depending on availability. A {@code null} level is
   * treated as {@link Level#INFO}.
   *
   * @param level the desired SLF4J severity used when emitting events; if {@code null}, the
   *     instance defaults to {@code INFO} for predictable behavior across environments.
   * @param removeWithProducer lifecycle hint carried with the listener; registries may use it to
   *     decide whether to unregister the listener when its producing component is removed. This
   *     class stores the flag but does not enforce any lifecycle policy itself.
   */
  public EventLogger(Level level, boolean removeWithProducer) {
    this.slf4jLevel = level == null ? Level.INFO : level;
    this.removeWithProducer = removeWithProducer;
  }

  /**
   * Receives a single event and logs its description at the configured level.
   *
   * <p>Emission rules: for {@code ERROR}, {@code WARN}, and {@code INFO} levels the description is
   * logged unconditionally at the selected level. For {@code DEBUG}, the description is logged only
   * if debug logging is enabled. For {@code TRACE}, the description is logged at trace when
   * enabled; otherwise the method falls back to debug (if enabled) or info. The method is
   * non-blocking and does not mutate the supplied event. Implementations ignore the {@code context}
   * parameter.
   *
   * <pre>{@code
   * // Example: wire a logger for INFO-level event summaries
   * ClientEventListener l = new EventLogger(Level.INFO, false);
   * l.receive(event, context);
   * }</pre>
   *
   * @param ce the event being delivered; expected to be non-null; only its {@link
   *     ClientEvent#getDescription()} is read and used for logging.
   * @param context execution context associated with the event; may be {@code null} and is not
   *     consulted by this listener; producers pass it for symmetry with other listeners.
   */
  @Override
  public void receive(ClientEvent ce, ClientContext context) {
    switch (slf4jLevel) {
      case ERROR:
        LOG.error("{}", ce.getDescription());
        break;
      case WARN:
        LOG.warn("{}", ce.getDescription());
        break;
      case INFO:
        LOG.info("{}", ce.getDescription());
        break;
      case DEBUG:
        if (LOG.isDebugEnabled()) LOG.debug("{}", ce.getDescription());
        break;
      case TRACE:
      default:
        if (LOG.isTraceEnabled()) LOG.trace("{}", ce.getDescription());
        else if (LOG.isDebugEnabled()) LOG.debug("{}", ce.getDescription());
        else LOG.info("{}", ce.getDescription());
    }
  }

  // No legacy Logger.LogLevel constructor; SLF4J Level is used directly.
}
