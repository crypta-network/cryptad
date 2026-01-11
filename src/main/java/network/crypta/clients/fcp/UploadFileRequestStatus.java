package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;

/**
 * Captures the evolving status of a single file upload handled through the FCP client API.
 *
 * <p>This specialization of {@link UploadRequestStatus} preserves metadata that only exists for
 * file-based inserts, including byte size estimates, MIME typing hints, and the originating
 * filename if one was provided by the submitting client. Instances are created by the request cache
 * to mirror the lifecycle of {@code ClientPut} operations and remain mutable while the upload runs.
 * Consumer code typically reads these objects via the status cache to drive web UIs, command-line
 * monitors, or plugin notifications without keeping strong references to the live request.
 *
 * <p>The class is intentionally lightweight and thread-safe for concurrent readers: the mutable
 * compression state is guarded by {@link #updateCompressionStatus(ClientPut.COMPRESS_STATE)}, while
 * other fields are immutable snapshots taken when the cache entry was constructed. Callers should
 * therefore re-query periodically rather than holding on to references that may become stale after
 * a restart or when a worker thread commits the final URI.
 *
 * <ul>
 *   <li>Tracks MIME type and human-friendly filename hints so download dialogs can present sane
 *       defaults.
 *   <li>Spans the entire compression pipeline by reflecting whether the request waits, compresses,
 *       or already streams encrypted blocks.
 *   <li>Offers deterministic {@link #copy()} snapshots, allowing callers to hand status objects to
 *       other components without additional synchronization.
 * </ul>
 */
public class UploadFileRequestStatus extends UploadRequestStatus {

  private final long dataSize;
  private final String mimeType;

  /** Null = from temp space */
  private final File origFilename;

  private COMPRESS_STATE compressing;

  /**
   * Creates a file upload status entry from bundled snapshots.
   *
   * @param statusSnapshot base request counters and timestamps.
   * @param details upload-specific URI and failure metadata.
   * @param dataSize size of the payload in bytes.
   * @param mimeType MIME type hint for the upload.
   * @param origFilename original filename, if known.
   * @param compressing current compression state.
   */
  UploadFileRequestStatus(
      RequestStatusSnapshot statusSnapshot,
      UploadRequestStatusDetails details,
      long dataSize,
      String mimeType,
      File origFilename,
      COMPRESS_STATE compressing) {
    super(statusSnapshot, details);
    this.dataSize = dataSize;
    this.mimeType = mimeType;
    this.origFilename = origFilename;
    this.compressing = compressing;
  }

  private UploadFileRequestStatus(UploadFileRequestStatus source) {
    super(source);
    this.dataSize = source.dataSize;
    this.mimeType = source.mimeType;
    this.origFilename = source.origFilename;
    this.compressing = source.compressing;
  }

  /**
   * Reports the number of bytes queued for insertion as captured when the status was created.
   *
   * <p>The size originates from the {@code ClientPut} metadata and therefore reflects the entire
   * payload, including any directories that were flattened prior to compression. The value does not
   * change after construction because the upload scheduler treats the request as immutable once
   * block enumeration finishes. Callers should treat the number as advisory for progress bars and
   * be aware that certain streaming uploads may not know their final size upfront.
   *
   * @return positive byte count representing the payload, or {@code 0} when no estimate was
   *     available at scheduling time.
   */
  @Override
  public long getDataSize() {
    return dataSize;
  }

  /**
   * Exposes the MIME type hint that accompanied the upload request.
   *
   * <p>The MIME value helps downstream components choose appropriate content handlers and inform
   * GUI clients whether a file likely contains text, images, or opaque binary data. The type is not
   * revalidated; it simply mirrors the user-supplied value (or the detector result) captured in the
   * {@code ClientPut}. Implementations retain the raw string so callers may apply their own parsing
   * or subtype matching logic.
   *
   * @return textual MIME identifier such as {@code "text/plain"}, or {@code null} when the client
   *     submitted no type information.
   */
  public String getMIMEType() {
    return mimeType;
  }

  /**
   * Returns the on-disk filename that originated the upload when such a file existed.
   *
   * <p>The value is particularly helpful when the preferred filename cannot be inferred from URIs;
   * in that case callers fall back to {@link File#getName()} to pre-populate save dialogs. When the
   * upload came from a temporary bucket rather than user storage this method returns {@code null},
   * signaling that no stable human-friendly name is available.
   *
   * @return {@link File} pointing at the source path, or {@code null} when the data originates from
   *     an anonymous or transient bucket.
   */
  public File getOrigFilename() {
    return origFilename;
  }

  /**
   * Reveals the current compression stage as observed by the request cache.
   *
   * <p>The compression state helps UIs distinguish whether the request waits for CPU resources,
   * actively compresses, or already streams encrypted blocks into the network. The value is updated
   * by {@link ClientPut} whenever significant transitions occur and therefore reflects a
   * best-effort view that may lag behind the most recent worker thread change. Consumers should use
   * the enumeration primarily for user feedback instead of implementing scheduling logic.
   *
   * @return {@link COMPRESS_STATE} describing waiting, compressing, or working behavior; never
   *     {@code null} after the status was initialized.
   */
  public COMPRESS_STATE isCompressing() {
    return compressing;
  }

  /**
   * Updates the cached compression state in a thread-safe manner.
   *
   * <p>This method is invoked exclusively by {@code RequestStatusCache} wiring or worker threads to
   * publish stage transitions. It intentionally performs no validation because the caller already
   * determines the canonical state.
   *
   * @param status the most recent {@link COMPRESS_STATE} reported by the upload pipeline.
   */
  synchronized void updateCompressionStatus(COMPRESS_STATE status) {
    compressing = status;
  }

  /**
   * Suggests the most appropriate filename for user interfaces that expose downloads or logs.
   *
   * <p>The method first delegates to {@link UploadRequestStatus#getPreferredFilename()} so URI
   * metadata (document names or meta strings) wins whenever the insert explicitly advertised a
   * label. If no URI-derived hint exists, the method falls back to {@link #getOrigFilename()} and
   * returns the basename of the originating file. This guarantees deterministic filenames even when
   * the upload stemmed from a directory flattening stage with limited metadata.
   *
   * @return sanitized filename assembled from URIs or, if unavailable, the original local file
   *     name; {@code null} when neither source exposes a usable value.
   */
  @Override
  public String getPreferredFilename() {
    String s = super.getPreferredFilename();
    if (s == null && origFilename != null) return origFilename.getName();
    return s;
  }

  /**
   * Creates an immutable snapshot of this status suitable for hand-off to external callers.
   *
   * <p>The returned instance duplicates every scalar and reference visible to clients, including
   * compression state, so it remains stable even if the originating request continues to mutate
   * while the snapshot is in use. This is the preferred way to expose status data over APIs because
   * it upholds the copy-on-read contract assumed by {@link RequestStatusCache}.
   *
   * @return a new {@link UploadFileRequestStatus} containing the same values observed at the moment
   *     {@code copy()} was invoked.
   */
  @Override
  public UploadFileRequestStatus copy() {
    return new UploadFileRequestStatus(this);
  }
}
