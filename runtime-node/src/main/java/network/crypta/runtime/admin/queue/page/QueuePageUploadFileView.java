package network.crypta.runtime.admin.queue.page;

import java.io.File;

/**
 * Adds the file-upload-specific fields still needed by the legacy queue page.
 *
 * <p>Single-file inserts expose a few presentation details that directory inserts do not share: the
 * detected MIME type, the original filename, and the user-visible compression phase used by the
 * progress cell. This subtype keeps those values narrow and read-only so the queue page can
 * preserve its existing output without depending directly on FCP upload status classes.
 */
public interface QueuePageUploadFileView extends QueuePageUploadView {
  /**
   * Returns the MIME type currently associated with the file upload.
   *
   * @return MIME type text for the queue page's type column, or {@code null} when unavailable
   */
  String getMimeType();

  /**
   * Returns the original file selected for the upload when that path is known.
   *
   * @return original upload file path for display, or {@code null} when unavailable
   */
  File getOrigFilename();

  /**
   * Returns the presentation-oriented compression state for the upload row.
   *
   * @return runtime-owned compression state used to choose progress-cell messaging
   */
  QueueCompressionState getCompressionState();
}
