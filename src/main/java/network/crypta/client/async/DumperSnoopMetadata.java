package network.crypta.client.async;

import network.crypta.client.Metadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Snoop implementation that emits a diagnostic metadata dump for in-flight client requests.
 *
 * <p>This implementation is intended for troubleshooting and operational diagnostics. When the
 * client surfaces metadata for a pending fetch, this class renders a human‑readable dump produced
 * by {@link Metadata#dump()} and emits it at the error logging level. Environments that do not
 * provide an SLF4J backend or have the error level disabled still receive the dump on the process
 * standard error stream to preserve the historical behavior of always surfacing the diagnostic
 * output.
 *
 * <p>Typical usage attaches an instance to a request to observe headers, sizes, and other
 * descriptive attributes before any payload bytes are transferred. The class performs no policy
 * decisions; it never cancels the request and therefore has no effect on the normal control flow of
 * the client pipeline. It is thread‑safe for concurrent use because it maintains no mutable state.
 *
 * <ul>
 *   <li><strong>Purpose:</strong> Visibility into per‑request metadata for debugging and support.
 *   <li><strong>Behavior:</strong> Logs at {@code ERROR}; falls back to {@code System.err} when
 *       logging is unavailable or disabled.
 *   <li><strong>Cancellation:</strong> Always returns {@code false}; never requests early abort.
 *   <li><strong>Thread‑safety:</strong> Stateless; safe to share across requests.
 * </ul>
 *
 * @see SnoopMetadata
 * @see Metadata
 * @see ClientContext
 */
public class DumperSnoopMetadata implements SnoopMetadata {

  private static final Logger LOG = LoggerFactory.getLogger(DumperSnoopMetadata.class);

  /**
   * Constructs a new, stateless dumper.
   *
   * <p>Instances keep no per‑request state and may be shared freely across multiple concurrent
   * operations. Creating additional instances has negligible cost; however, most callers can reuse
   * a single instance wherever a {@link SnoopMetadata} is required.
   */
  public DumperSnoopMetadata() {
    // no state
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation unconditionally permits the request to continue (it never cancels) and
   * emits the metadata dump for diagnostics. If the SLF4J backend reports that the {@code ERROR}
   * level is enabled, the dump is written via the logger; otherwise, the dump is written directly
   * to {@code System.err} so visibility is preserved even without a logging binding.
   *
   * <p>The method does not mutate the provided arguments and performs no blocking I/O. It should be
   * considered idempotent with respect to its return value. The size of the dump depends on the
   * information exposed by {@link Metadata#dump()} and may be large for complex items; callers who
   * attach this snoop in production should ensure log routing and retention are configured
   * appropriately.
   *
   * <pre>{@code
   * // Attach a dumper to a request to aid debugging
   * request.setMetaSnoop(new DumperSnoopMetadata());
   * }</pre>
   *
   * @param meta descriptive information about the in‑flight request; never {@code null}. The dump
   *     string is derived from this object and written to the configured output.
   * @param context per‑request context; never {@code null}. This implementation does not read from
   *     or write to the context and ignores it entirely.
   * @return always {@code false}, indicating that the request must proceed without cancellation,
   *     regardless of the metadata contents.
   */
  @Override
  @SuppressWarnings("java:S106")
  public boolean snoopMetadata(Metadata meta, ClientContext context) {
    // Prefer logging at ERROR, but preserve stderr dump when backend is absent or ERROR disabled.
    String dump = String.valueOf(meta.dump());
    if (LOG.isErrorEnabled()) {
      LOG.error(dump);
    } else {
      System.err.print(dump);
    }
    return false;
  }
}
