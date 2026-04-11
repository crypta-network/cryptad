package network.crypta.client.events;

import java.io.IOException;
import java.io.Writer;

/**
 * A {@link ClientEventListener} that writes a one-line textual description of each received event
 * to a provided {@link Writer}.
 *
 * <p>This utility is useful in diagnostics, tests, or lightweight logging pipelines where a
 * compact, append-only representation of client events is desired. For every delivered {@code
 * ClientEvent}, the listener calls {@code getDescription()} and writes the resulting line followed
 * by a newline. The supplied writer is never flushed or closed by this class; lifecycle and
 * buffering are the responsibility of the caller.
 *
 * <p>Error handling is intentionally minimal: {@link IOException} from the writer is swallowed to
 * avoid interfering with the surrounding event dispatch. As a result, failures to write do not
 * propagate to callers, and events will continue to be processed.
 *
 * <p>Thread-safety depends on the provided writer. This class performs no synchronization; if the
 * writer may be accessed concurrently, callers should coordinate access or supply a thread-safe
 * wrapper. For higher throughput, consider wrapping the writer in a {@code BufferedWriter}.
 *
 * <ul>
 *   <li>Writes exactly one line per event (description plus {@code '\n'}).
 *   <li>Never closes the writer; ownership remains with the caller.
 *   <li>Ignores I/O failures to keep event delivery non-intrusive.
 * </ul>
 *
 * @see ClientEventListener
 * @see network.crypta.client.events.ClientEvent
 */
public class EventDumper implements ClientEventListener {

  final Writer w;
  final boolean removeWithProducer;

  /**
   * Creates a new dumper that appends one descriptive line per received event to the given writer.
   *
   * <p>The writer is used as-is and is not closed or flushed by this instance; callers control its
   * lifecycle and buffering strategy. The {@code removeWithProducer} flag is recorded and may be
   * consulted by the surrounding event subsystem to decide whether this listener should be removed
   * together with the producer that owns it.
   *
   * @param writer the destination to which event descriptions are written; must not be {@code
   *     null}; caller retains ownership and is responsible for flushing and closing
   * @param removeWithProducer whether the listener should be considered removable together with its
   *     producer by frameworks that support such semantics; this class does not act on the flag
   */
  public EventDumper(Writer writer, boolean removeWithProducer) {
    this.w = writer;
    this.removeWithProducer = removeWithProducer;
  }

  /**
   * Receives an event and writes its description as a single line to the configured writer.
   *
   * <p>The implementation calls {@code ce.getDescription()}, appends a newline, and attempts to
   * write the result. Any {@link IOException} thrown by the writer is caught and ignored to avoid
   * disrupting event dispatch. No synchronization is performed; callers should ensure safe access
   * when multiple threads may deliver events concurrently.
   *
   * <p>Preconditions: {@code ce} must be non-{@code null}. The {@code context} parameter may be
   * provided by the dispatching framework but is not consulted by this implementation.
   *
   * <pre>{@code
   * // Example: direct invocation
   * var dumper = new EventDumper(writer, false);
   * dumper.receive(event, context);
   * }</pre>
   *
   * @param ce the event being delivered; must be non-{@code null}; its {@code getDescription()}
   *     text is written verbatim followed by a newline
   * @param context framework-supplied context for the event dispatch; accepted but ignored by this
   *     implementation
   */
  @Override
  public void receive(ClientEvent ce, ClientEventDispatchContext context) {
    try {
      w.write(ce.getDescription() + "\n");
    } catch (IOException _) {
      // Ignore.
    }
  }
}
