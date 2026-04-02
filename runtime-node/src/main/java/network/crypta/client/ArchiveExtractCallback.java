package network.crypta.client;

import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;

/**
 * Callback interface that reports the outcome of extracting a single entry from an archive.
 *
 * <p>Implementations receive one of the methods defined here once an archive extraction attempt
 * completes. Typical call patterns are:
 *
 * <ul>
 *   <li>{@link #gotBucket(Bucket, ClientContext)} when the requested entry is found and its
 *       contents are materialized into a {@link Bucket}.
 *   <li>{@link #notInArchive(ClientContext)} when the requested entry does not exist within the
 *       archive.
 *   <li>{@link #onFailed(ArchiveRestartException, ClientContext)} or {@link
 *       #onFailed(ArchiveFailureException, ClientContext)} when extraction fails.
 * </ul>
 *
 * <p>Unless otherwise documented by the component invoking this callback, methods may be invoked on
 * a worker thread. Implementations should therefore avoid long blocking operations on the callback
 * thread and delegate heavier work as needed. When off-thread extraction is requested by the
 * caller, the provided {@link Bucket} is typically persistent, allowing the recipient to read the
 * data after the method returns. Callers are responsible for obeying the {@link Bucket} lifetime
 * semantics defined elsewhere.
 *
 * <p>This interface is designed to be stateless and reusable across multiple extraction attempts;
 * implementations may capture state if desired, but should document any concurrency limitations.
 *
 * @see Bucket
 * @see ClientContext
 * @see ArchiveRestartException
 * @see ArchiveFailureException
 */
public interface ArchiveExtractCallback extends Serializable {

  /**
   * Called when the requested archive entry is found and its data are available.
   *
   * <p>The supplied {@code Bucket} contains the extracted content of the target entry. If the
   * extraction was performed off-thread (as requested by the caller), the {@code Bucket} is
   * typically persistent so its contents remain accessible beyond the scope of this call. The
   * implementation should consume or hand off the bucket according to the {@link Bucket} contract
   * and avoid performing long-running operations on the callback thread.
   *
   * <pre>{@code
   * // Example: record that the entry was obtained
   * callback.gotBucket(dataBucket, context);
   * }</pre>
   *
   * @param data the extracted entry content; usually persistent for off-thread extraction; never
   *     {@code null} when this method is invoked
   * @param context the client execution context associated with the extraction; can be used to
   *     access shared state or services; never {@code null}
   */
  void gotBucket(Bucket data, ClientContext context);

  /**
   * Called when the requested entry is not present in the archive.
   *
   * <p>Use this signal to update caller-visible state or to try alternative sources if applicable.
   * No {@link Bucket} is provided because there is no content to deliver.
   *
   * @param context the client execution context associated with the extraction attempt; useful for
   *     logging, metrics, or follow-up actions; never {@code null}
   */
  void notInArchive(ClientContext context);

  /**
   * Called when extraction fails in a way that may be resolved by restarting the operation.
   *
   * <p>This variant conveys a recoverable condition. Callers commonly respond by scheduling a
   * retry, potentially after backoff or once prerequisites are satisfied. Implementations should
   * avoid throwing from this method; surface errors through the provided context if necessary.
   *
   * @param e the failure describing why a restart is advisable; includes details for diagnostics;
   *     never {@code null}
   * @param context the client execution context associated with the extraction; may be used to log
   *     the failure, update state, or enqueue a retry; never {@code null}
   */
  void onFailed(ArchiveRestartException e, ClientContext context);

  /**
   * Called when extraction fails for a non-restartable reason.
   *
   * <p>Use this to report a terminal failure where a simple retry is not expected to succeed
   * without external intervention (for example, an unsupported format or a permanent integrity
   * error). Implementations should record relevant diagnostics and notify upstream components as
   * appropriate.
   *
   * @param e the non-restartable failure explaining why extraction could not complete; includes
   *     diagnostic details; never {@code null}
   * @param context the client execution context associated with the failed extraction; use for
   *     logging, metrics, or cleanup; never {@code null}
   */
  void onFailed(ArchiveFailureException e, ClientContext context);
}
