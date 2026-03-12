package network.crypta.support.compress;

import network.crypta.client.InsertException;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientPutState;

/**
 * Unit of work that performs a compression attempt for a client operation.
 *
 * <p>Instances are enqueued and executed by {@link RealCompressor} on background threads. A job
 * implementation is responsible for running the compression, handling success by notifying its
 * continuation (e.g., an inserter), and reporting failures via {@link #onFailure(InsertException,
 * ClientPutState, ClientContext)}.
 *
 * <p>Threading: {@code tryCompress(...)} runs on a worker thread managed by the compressor. The
 * implementation must arrange any required callbacks or scheduling on the appropriate executors in
 * {@link ClientContext}. Implementations should ensure proper resource cleanup on both success and
 * failure paths.
 */
public interface CompressJob {

  /**
   * Executes the compression step for this job.
   *
   * <p>Implementations read input, attempt compression using the configured codec set, and arrange
   * delivery of the result to the owning component. On success, this method should perform or
   * schedule any follow-up actions (for example, notifying an inserter) and release temporary
   * resources.
   *
   * <p>Threading: called on a background thread. Callers must not block indefinitely; jobs should
   * be responsive to shutdown via {@link ClientContext} facilities where applicable.
   *
   * @param context execution context providing schedulers, persistence, and configuration; non-null
   * @throws InsertException if compression cannot proceed or complete successfully; the caller
   *     catches this and invokes {@link #onFailure(InsertException, ClientPutState, ClientContext)}
   */
  void tryCompress(ClientContext context) throws InsertException;

  /**
   * Reports a failure that occurred during {@link #tryCompress(ClientContext)}.
   *
   * <p>Called by the compressor when the job throws an {@link InsertException} or when an
   * unexpected error is translated to one. Implementations should log the error, free any allocated
   * resources, and notify their owner that compression failed.
   *
   * @param e the failure reason; never {@code null}
   * @param c the request state associated with this job, if available; may be {@code null} when not
   *     known by the caller
   * @param context execution context for performing callbacks or rescheduling; non-null
   */
  void onFailure(InsertException e, ClientPutState c, ClientContext context);
}
