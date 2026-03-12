package network.crypta.client.async;

import network.crypta.client.Metadata;

/**
 * Callback interface for observing metadata during an asynchronous fetch operation.
 *
 * <p>Implementations of this interface are invoked when the client obtains descriptive information
 * about the requested content, typically before any payload bytes are delivered to the caller. This
 * early signal allows a client to make a policy decision — for example, rejecting content that is
 * too large, of an unexpected type, or otherwise unsuitable — without incurring the cost of
 * downloading the body. Returning {@code true} from the callback requests that the in‑flight fetch
 * be cancelled immediately; returning {@code false} permits the fetch to proceed normally.
 *
 * <p>The interface is intentionally minimal so it can be implemented as a lambda or method
 * reference. Implementations should keep work bounded and avoid blocking, as the callback may be
 * executed on an internal I/O or scheduler thread used by other requests. If an instance is shared
 * across multiple concurrent fetches, treat it as effectively stateless or ensure appropriate
 * external synchronization.
 *
 * <ul>
 *   <li>Inspect metadata exposed by {@link network.crypta.client.Metadata}.
 *   <li>Optionally signal early cancellation to conserve bandwidth and resources.
 *   <li>May record telemetry or tracing using the provided {@link ClientContext}.
 * </ul>
 *
 * @see network.crypta.client.Metadata
 * @see ClientContext
 */
public interface SnoopMetadata {

  /**
   * Inspects the fetched metadata and optionally cancels the request.
   *
   * <p>The client calls this method when metadata for a pending fetch becomes available. The method
   * should be fast and side‑effect free aside from the decision to continue or abort. It may be
   * invoked on a background worker thread; implementations must avoid long‑running operations and
   * should tolerate being called in close proximity to other I/O events. Treat the callback as
   * idempotent: repeated invocations with the same arguments should lead to the same outcome.
   *
   * <pre>{@code
   * // Example: cancel when an expected type is not present
   * SnoopMetadata sn = (meta, ctx) -> !"application/octet-stream".equals(meta.contentType());
   * }</pre>
   *
   * @param meta descriptive information about the item being fetched; never {@code null}. It may
   *     include type hints, sizes, or other attributes that inform early acceptance decisions.
   * @param context per-request context and facilities for the ongoing operation; never {@code
   *     null}. May expose logging, tracing, or scheduling helpers; do not retain beyond this
   *     invocation.
   * @return {@code true} to request immediate cancellation of the fetch, suppressing payload
   *     download; {@code false} to continue the fetch according to the configured pipeline.
   */
  boolean snoopMetadata(Metadata meta, ClientContext context);
}
