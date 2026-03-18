package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Runtime capability for creating new persistent queue inserts from the queue UI.
 *
 * <p>This port hides the remaining daemon-specific work needed to create persistent queue inserts.
 * Callers are expected to parse form data, validate URIs, and choose the user-facing response path
 * before invoking the port. The implementation then stages browser uploads, rebuilds the matching
 * legacy insert objects, and starts the request through the daemon's persistent queue.
 *
 * <p>The port deliberately exposes one method per queue-toadlet flow instead of a single tagged
 * union request. That keeps the boundary readable, makes caller intent explicit, and avoids leaking
 * HTTP-only concepts into the runtime SPI.
 */
public interface QueueInsertPort {
  /**
   * Registers one new persistent insert backed by browser-uploaded bytes.
   *
   * <p>The caller remains responsible for multipart parsing, insert URI validation, and redirect
   * handling. Implementations may perform temporary staging work before queue registration because
   * browser uploads do not already exist as files on disk.
   *
   * @param request detached browser-upload insert request with staged form values
   * @return legacy completion state describing how registration finished
   * @throws QueueInsertRejectedException if runtime policy rejects the uploaded source
   * @throws RequestQueueUnavailableException if the persistent request queue or FCP endpoint is
   *     unavailable while starting the insert
   * @throws IOException if I/O fails while staging, upload bytes, or rebuilding the legacy request
   */
  QueueInsertOutcome enqueueBrowserUploadInsert(QueueBrowserUploadInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException;

  /**
   * Registers one new persistent insert backed by a local file.
   *
   * <p>This method represents the queue flow where the user selected one local file from the file
   * browser. The runtime adapter is responsible for access checks, legacy request reconstruction,
   * and starting the insert on the persistent queue.
   *
   * @param request detached local-file insert request with the chosen source path
   * @return legacy completion state describing how registration finished
   * @throws QueueInsertRejectedException if runtime policy rejects the local source file
   * @throws RequestQueueUnavailableException if the persistent request queue or FCP endpoint is
   *     unavailable while starting the insert
   * @throws IOException if I/O fails while reopening the local file or rebuilding the legacy
   *     request
   */
  QueueInsertOutcome enqueueLocalFileInsert(QueueLocalFileInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException;

  /**
   * Registers one new persistent insert backed by a local directory tree.
   *
   * <p>This method covers the legacy directory-insert flow where the daemon scans a selected tree
   * and reconstructs a persistent manifest-style request. Callers still own redirect and error-page
   * mapping after the outcome or exception is returned.
   *
   * @param request detached local-directory insert request with the selected root directory
   * @return legacy completion state describing how registration finished
   * @throws QueueInsertRejectedException if runtime policy rejects the directory, or it exceeds the
   *     supported per-insert file limit
   * @throws RequestQueueUnavailableException if the persistent request queue or FCP endpoint is
   *     unavailable while starting the insert
   * @throws IOException if I/O fails while rebuilding the legacy directory insert request
   */
  QueueInsertOutcome enqueueLocalDirectoryInsert(QueueLocalDirectoryInsertRequest request)
      throws QueueInsertRejectedException, RequestQueueUnavailableException, IOException;
}
