package network.crypta.runtime.admin.queue.page;

import java.io.File;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext;

/**
 * Adds the download-specific fields still rendered by the legacy queue page.
 *
 * <p>The legacy queue page needs a little more than the generic request counters when it renders
 * download rows. It still shows destination details, MIME metadata, compatibility information, and
 * failure categorization. This subtype exposes only those read-only values, so the runtime-owned
 * seam can support the existing page without importing the full FCP download status API.
 */
public interface QueuePageDownloadView extends QueuePageRequestView {
  /**
   * Indicates whether the completed or in-progress download targets temporary storage.
   *
   * @return {@code true} when the queue row represents a temp-space download destination
   */
  boolean toTempSpace();

  /**
   * Returns the structured failure code associated with the current download state.
   *
   * @return failure classification used for MIME and error grouping on the queue page
   */
  FetchExceptionMode getFailureCode();

  /**
   * Returns the MIME type currently associated with the download, if one is known.
   *
   * @return MIME type text used for the queue type column, or {@code null} when unavailable
   */
  String getMimeType();

  /**
   * Returns the destination file selected for this download when it writes to disk.
   *
   * @return destination file path for queue-page display, or {@code null} when not applicable
   */
  File getDestFilename();

  /**
   * Returns the compatibility-mode hints attached to the underlying fetch request.
   *
   * @return compatibility modes shown in advanced queue-page output, possibly empty or {@code null}
   */
  InsertContext.CompatibilityMode[] getCompatibilityMode();

  /**
   * Returns any override splitfile crypto key associated with the request.
   *
   * @return override key bytes for advanced diagnostics, or {@code null} when no override exists
   */
  byte[] getOverriddenSplitfileCryptoKey();

  /**
   * Indicates whether the download detected content that should avoid compression.
   *
   * @return {@code true} when the request observed a do-not-compress condition
   */
  boolean detectedDontCompress();
}
