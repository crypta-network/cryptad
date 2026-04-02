package network.crypta.client.async;

import network.crypta.support.api.Bucket;

/**
 * Intercepts in-flight fetch data to observe or influence the request.
 *
 * <p>{@code SnoopBucket} is a lightweight callback interface that the fetch pipeline invokes while
 * retrieving an object. Implementations can inspect the current {@link Bucket} — which may contain
 * either payload data or request metadata — and decide whether the overall request should continue
 * or be cancelled early. This is useful for monitoring, metrics, tracing, or conditional aborts
 * based on the content or headers seen so far.
 *
 * <p>The interface deliberately does not prescribe a threading model. Callers may invoke a single
 * instance from different threads depending on the fetch path and scheduling, so implementations
 * that are shared across requests should be designed to be thread-safe or otherwise confined.
 * Implementations are expected to return quickly to avoid delaying the surrounding fetch logic.
 *
 * <ul>
 *   <li>Return {@code true} to cancel the ongoing fetch; {@code false} to continue.
 *   <li>The {@code isMetadata} flag indicates whether the bucket holds metadata rather than data.
 *   <li>The provided {@link ClientContext} exposes request-related facilities if additional
 *       information is needed to make a decision.
 * </ul>
 *
 * @see Bucket
 * @see ClientContext
 */
public interface SnoopBucket {

  /**
   * Examines the supplied bucket during a fetch and optionally cancels the request.
   *
   * <p>The callback is invoked by the fetch pipeline with a {@link Bucket} that represents the
   * current material being processed. When {@code isMetadata} is {@code true}, the bucket contains
   * associated metadata for the request; otherwise it contains the content being fetched. Return
   * {@code true} to signal that the caller should cancel the fetch; return {@code false} to allow
   * the operation to proceed normally.
   *
   * <pre>{@code
   * // Example: inspect and allow the request to continue
   * boolean cancel = snoop.snoopBucket(bucket, false, context);
   * if (cancel) {
   *   // caller cancels the request
   * }
   * }</pre>
   *
   * @param data the bucket being observed during fetch; content or metadata depending on flag
   * @param isMetadata {@code true} when {@code data} holds metadata; {@code false} for payload data
   * @param context client-layer context associated with this request; may expose helpers and state
   * @return {@code true} to cancel the request immediately; {@code false} to continue processing
   */
  boolean snoopBucket(Bucket data, boolean isMetadata, ClientContext context);
}
