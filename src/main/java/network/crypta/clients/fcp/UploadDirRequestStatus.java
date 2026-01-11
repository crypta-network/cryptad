package network.crypta.clients.fcp;

/**
 * Captures the evolving status of a site or directory upload handled through the FCP layer.
 *
 * <p>This status object tracks both the aggregate byte count and the number of files remaining so
 * operators can surface long-running progress bars and quota indicators for large manifests.
 * Callers typically obtain instances from {@link RequestStatusCache} or the various {@code
 * ClientPutDir} flows, inspect the counters, and optionally snapshot the instance via {@link
 * #copy()} before handing it to background reporters. All mutable state is inherited from {@link
 * UploadRequestStatus}; this subclass simply adds directory-centric metadata such as the overall
 * file tally. The instance relies on the superclass synchronization, so external callers should
 * treat it as a snapshot or invoke {@link #copy()} when sharing across threads.
 *
 * <p>Typical lifecycle:
 *
 * <ul>
 *   <li>Constructed when a directory insert is scheduled or restored from persistence.
 *   <li>Polled repeatedly by monitoring endpoints to retrieve byte counts and failure reasons.
 *   <li>Copied and published once the upload finishes or when UI code needs an immutable view.
 * </ul>
 *
 * <p>The {@link #getTotalDataSize()} and {@link #getNumberOfFiles()} metrics represent best-known
 * estimates for the pending upload. They may change as manifests expand, but once {@link
 * RequestStatus#isTotalFinalized()} is true the values stabilize and can be archived alongside
 * audit logs. Use {@link #getDataSize()} when the caller does not care whether the data originated
 * from a directory or a single file.
 */
public class UploadDirRequestStatus extends UploadRequestStatus {

  /**
   * Creates a new mutable directory upload status populated with the supplied counters and
   * metadata.
   *
   * <p>Callers should pass the latest known values when resuming persisted work or creating a fresh
   * request so user interfaces immediately display accurate estimates. All timestamps are
   * defensively copied by the superclass. The {@code size} and {@code files} arguments represent
   * the aggregate payload of the directory tree and may be zero for empty manifests.
   *
   * <pre>{@code
   * UploadDirRequestStatus status = new UploadDirRequestStatus(...);
   * cache.put(status.getIdentifier(), status);
   * }</pre>
   *
   * @param statusSnapshot base request counters and timestamps.
   * @param details upload-specific URI and failure metadata.
   * @param size aggregate payload size of the directory in bytes; callers may pass zero to indicate
   *     an empty manifest or unknown size.
   * @param files total number of files scheduled for insertion at this time; may be zero for
   *     metadata-only structures.
   */
  public UploadDirRequestStatus(
      RequestStatusSnapshot statusSnapshot,
      UploadRequestStatusDetails details,
      long size,
      int files) {
    super(statusSnapshot, details);
    this.totalDataSize = size;
    this.totalFiles = files;
  }

  private UploadDirRequestStatus(UploadDirRequestStatus source) {
    super(source);
    this.totalDataSize = source.totalDataSize;
    this.totalFiles = source.totalFiles;
  }

  private final long totalDataSize;
  private final int totalFiles;

  /**
   * Reports the best-known aggregate byte size for the directory upload.
   *
   * <p>The value mirrors {@link #getDataSize()} but remains available under a dedicated accessor so
   * UI code can distinguish directory uploads from single-file inserts. It is not recomputed on the
   * fly; callers should treat it as a cached estimate and refresh from a newer status when
   * manifests change.
   *
   * @return number of bytes that the directory is expected to consume, or zero for empty uploads.
   */
  public long getTotalDataSize() {
    return getDataSize();
  }

  /**
   * Returns how many files are currently expected to be inserted within this directory request.
   *
   * <p>The count includes every file discovered by the manifest so far, including nested paths.
   * Zero indicates either an empty directory or an as-yet unknown file list. The value is a
   * snapshot that may change when the underlying client discovers more files.
   *
   * @return total number of files scheduled for upload, or zero when unknown/empty.
   */
  public int getNumberOfFiles() {
    return totalFiles;
  }

  /** {@inheritDoc} */
  @Override
  public long getDataSize() {
    return totalDataSize;
  }

  /**
   * Produces a detached snapshot of this status, including directory-specific metadata.
   *
   * <p>Use this when publishing state to other threads or remote clients to avoid exposing the
   * mutable instance managed by worker code. The resulting copy never shares mutable references, so
   * future calls to mutators on the original do not affect the snapshot.
   *
   * @return new status instance mirroring the current values while remaining immutable thereafter.
   */
  @Override
  public UploadDirRequestStatus copy() {
    return new UploadDirRequestStatus(this);
  }
}
