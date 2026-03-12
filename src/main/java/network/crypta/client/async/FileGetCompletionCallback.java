package network.crypta.client.async;

import java.io.File;
import network.crypta.client.ClientMetadata;

/**
 * Callback specialization for downloads that materialize directly to a regular {@link File}.
 *
 * <p>When a request will store the final content as a non-temporary file, and the data does not
 * require post-processing such as decompression or filtering, the client can avoid extra copying by
 * writing into a temporary file in the destination directory. On successful completion the caller
 * invokes {@link #onSuccess(File, long, ClientMetadata, ClientGetState, ClientContext)} to allow
 * the implementation to verify hashes, truncate to the exact length, and atomically move/rename the
 * file into its final location where appropriate.
 *
 * <p>This strategy reduces peak disk usage and filesystem I/O by eliminating an intermediate buffer
 * or staging copy. The calling {@link ClientGetState} must only use this interface when performing
 * the final fetch stage, since earlier phases may still require transformation or splitting logic.
 * Callers should assume callbacks may be invoked from internal worker threads and avoid blocking
 * operations inside handlers.
 *
 * <ul>
 *   <li>Optimized path for direct-to-file downloads with stable metadata.
 *   <li>Explicit lifecycle: temporary file write → success/failure signal.
 *   <li>Context-limited helpers via {@link ClientContext} for the duration of calls.
 * </ul>
 *
 * @see GetCompletionCallback
 * @see ClientGetState
 * @see ClientMetadata
 */
public interface FileGetCompletionCallback extends GetCompletionCallback {

  /**
   * Returns the final target location for the downloaded data, when applicable.
   *
   * <p>If a non-{@code null} value is returned, the caller may create a temporary file in the same
   * directory and use it to store downloaded blocks while assembling the result. On completion, the
   * caller should truncate the file to the exact length and then invoke {@link #onSuccess(File,
   * long, ClientMetadata, ClientGetState, ClientContext)} to commit the result. Returning {@code
   * null} indicates that direct-to-file optimization is not suitable for this request.
   *
   * @return the absolute path to the final destination file when direct-to-file handling is
   *     supported; otherwise {@code null} to fall back to standard streaming and staging
   */
  File getCompletionFile();

  /**
   * Finalizes a direct-to-file download where {@code tempFile} holds the assembled content.
   *
   * <p>The temporary file resides in the same directory as the target. Implementations should
   * truncate the file to {@code length} bytes if necessary, verify integrity using the known
   * hashes, and commit the file as the final result (e.g., via an atomic move/rename when
   * permissible). Any failure should be reported through the regular failure path of the
   * surrounding fetch request. Callers should not modify or delete {@code tempFile} after invoking
   * this method unless instructed by the implementation.
   *
   * <pre>{@code
   * // Typical commit from the final fetch stage
   * callback.onSuccess(tempFile, expectedLength, metadata, state, context);
   * }</pre>
   *
   * @param tempFile a file in the same directory as the completion file containing the assembled
   *     data ready for verification and commit; must be readable and writable by the process
   * @param length the exact expected length of the final content in bytes; implementations may
   *     truncate the file to this size prior to verification
   * @param metadata content metadata such as MIME type and parameters available at completion; may
   *     inform downstream handling or user presentation
   * @param state the calling {@link ClientGetState} representing the final stage of the request at
   *     completion time; useful for logging and auditing
   * @param context run-time helpers such as executors and temporary storage factories; valid only
   *     during the invocation and not intended for cross-thread retention
   */
  void onSuccess(
      File tempFile,
      long length,
      ClientMetadata metadata,
      ClientGetState state,
      ClientContext context);
}
