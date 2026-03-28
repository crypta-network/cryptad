package network.crypta.runtime.admin.queue.page;

/**
 * Adds the directory-upload-specific fields still needed by the legacy queue page.
 *
 * <p>Directory inserts share the generic upload state exposed by {@link QueuePageUploadView}, but
 * the queue page also renders aggregate size and file-count columns for them. This subtype exposes
 * only those extra read-only values, so the seam stays aligned with the current HTML rather than
 * turning into a broad directory-insert API.
 */
public interface QueuePageUploadDirView extends QueuePageUploadView {
  /**
   * Returns the aggregate size of the directory upload payload.
   *
   * @return total upload payload size in bytes across all files included in the directory insert
   */
  long getTotalDataSize();

  /**
   * Returns the number of files included in the directory upload.
   *
   * @return file count rendered in the queue page's directory-specific columns
   */
  int getNumberOfFiles();
}
