package network.crypta.clients.http;

import network.crypta.client.FetchException;
import network.crypta.support.api.Bucket;

/**
 * Snapshot describing the state or outcome of a single FProxy fetch operation.
 *
 * <p>Instances are immutable snapshots created by {@code FProxyFetchInProgress} to communicate the
 * latest known progress or the completed payload. A snapshot may lag reality slightly: if it says
 * the fetch is still running, the operation may already have completed by the time the caller acts.
 * Callers are expected to treat the object as read-only, aside from updating the fetch-count for
 * bookkeeping, and to close it once the data has been consumed so the underlying bucket can be
 * released promptly.
 *
 * <p>Typical usage is to poll or block for successive {@code FProxyFetchResult} instances until
 * {@link #isFinished()} returns {@code true}, then read {@link #getData()} when available. The
 * class does not provide synchronization; callers should coordinate access if they share instances
 * across threads. Time and size values are captured at creation time and are not refreshed.
 *
 * <ul>
 *   <li>Represents either in-progress metrics or final content.
 *   <li>Intended to be used as a short-lived snapshot, not a live view.
 *   <li>Resource release is explicit via {@link #close()}.
 * </ul>
 *
 * @author Matthew Toseland &lt;toad@amphibian.dyndns.org&gt; (0xE43DA450)
 */
public final class FProxyFetchResult {

  /**
   * MIME type reported for the fetched content when this snapshot was created; may be absent if the
   * type has not been detected or declared yet.
   */
  public final String mimeType;

  /**
   * Size of the requested entity in bytes, if known at snapshot time; zero or negative values may
   * indicate that the length is unknown because the transfer is still underway.
   */
  public final long size;

  /** If we have fetched the data */
  final Bucket data;

  /**
   * Epoch millisecond timestamp representing when FProxy began this fetch, allowing clients to
   * compute elapsed time or display start information without consulting the parent tracker.
   */
  public final long timeStarted;

  /**
   * Indicates whether the request has already been handed off to the network layer rather than
   * being served immediately from a local cache.
   */
  public final boolean goneToNetwork;

  /**
   * The total number of data blocks expected for the fetch according to the manifest at the time
   * this snapshot was produced; useful for progress percentages when combined with block counters.
   */
  public final int totalBlocks;

  /**
   * Number of blocks that must be successfully retrieved to reconstruct the content, typically a
   * threshold less than or equal to {@link #totalBlocks} when erasure coding is used.
   */
  public final int requiredBlocks;

  /**
   * Count of blocks that have been fetched successfully so far; values only increase across
   * successive snapshots and enable callers to report progress.
   */
  public final int fetchedBlocks;

  /**
   * Number of blocks whose retrieval attempts failed but might be retried depending on upstream
   * logic; consult {@link #fatallyFailedBlocks} for unrecoverable failures.
   */
  public final int failedBlocks;

  /**
   * Count of blocks deemed irrecoverable for this fetch, implying retries will not succeed unless
   * the request is restarted or additional sources appear.
   */
  public final int fatallyFailedBlocks;

  /**
   * Flag indicating whether the block status set has been finalized, meaning no additional block
   * descriptors are expected to be discovered for this request.
   */
  public final boolean finalizedBlocks;

  /** Number of times this has been used */
  private int fetchedCount;

  /**
   * Fetch failure cause when the request ended unsuccessfully; {@code null} when the fetch is still
   * running or succeeded, allowing callers to surface detailed diagnostics.
   */
  public final FetchException failed;

  final FProxyFetchInProgress progress;
  final boolean hasWaited;

  /**
   * Estimated remaining time in milliseconds at snapshot creation; callers can use negative or zero
   * values to signal that no reliable estimate is currently available.
   */
  public final long eta;

  /** At the time of creating the snapshot, has it finished? */
  private final boolean finished;

  /** Constructor when we are returning the data */
  FProxyFetchResult(FProxyFetchInProgress parent, Bucket data, FProxyFetchSnapshotInfo info) {
    assert (data != null);
    this.data = data;
    this.mimeType = info.mimeType();
    this.size = data.size();
    this.timeStarted = info.timeStarted();
    this.goneToNetwork = info.goneToNetwork();
    totalBlocks = requiredBlocks = fetchedBlocks = failedBlocks = fatallyFailedBlocks = 0;
    finalizedBlocks = true;
    failed = null;
    this.progress = parent;
    this.eta = info.eta();
    this.hasWaited = info.hasWaited();
    finished = true;
  }

  /** Constructor when we are not returning the data, because it is still running, or it failed */
  FProxyFetchResult(
      FProxyFetchInProgress parent,
      FProxyFetchSnapshotInfo info,
      long size,
      FProxyFetchProgressCounts counts,
      FetchException failed) {
    this.data = null;
    this.mimeType = info.mimeType();
    this.size = size;
    this.timeStarted = info.timeStarted();
    this.goneToNetwork = info.goneToNetwork();
    this.totalBlocks = counts.totalBlocks();
    this.requiredBlocks = counts.requiredBlocks();
    this.fetchedBlocks = counts.fetchedBlocks();
    this.failedBlocks = counts.failedBlocks();
    this.fatallyFailedBlocks = counts.fatallyFailedBlocks();
    this.finalizedBlocks = counts.finalizedBlocks();
    this.failed = failed;
    this.progress = parent;
    this.eta = info.eta();
    this.hasWaited = info.hasWaited();
    finished = (failed != null);
  }

  /**
   * Releases any resources associated with this snapshot once the caller is finished processing it.
   *
   * <p>This method delegates to {@link FProxyFetchInProgress#close(FProxyFetchResult)} so upstream
   * bookkeeping can reclaim buffers or decrement reference counts. It is safe to call even when the
   * fetch failed or yielded no data; callers should invoke it exactly once per snapshot to avoid
   * resource leaks. The method performs no synchronization, so external coordination is needed if
   * multiple threads could close the same result.
   */
  public void close() {
    progress.close(this);
  }

  /**
   * Indicates whether this snapshot contains the fetched payload bucket rather than only progress
   * information.
   *
   * <p>Call this before {@link #getData()} to determine whether content is available. The presence
   * of data implies {@link #isFinished()} is {@code true}, but the converse is not guaranteed when
   * a fetch fails. The result reflects the state at snapshot creation and will not update if the
   * underlying fetch later completes.
   *
   * @return {@code true} when a data bucket is attached to this snapshot.
   */
  public boolean hasData() {
    return data != null;
  }

  /**
   * Returns the fetched payload bucket if it was available when the snapshot was produced.
   *
   * <p>The returned {@link Bucket} is owned by the caller, which should consume or copy it before
   * invoking {@link #close()}. If no data is present, this method returns {@code null}; callers
   * should check {@link #hasData()} to avoid unexpected {@code null} handling. The bucket size is
   * captured in {@link #size} for convenience.
   *
   * @return the fetched bucket when available, or {@code null} when only progress was captured.
   */
  public Bucket getData() {
    return data;
  }

  /**
   * Reports whether the server forced the client to wait before delivering a response for this
   * fetch request.
   *
   * <p>The flag is recorded when the snapshot is created and is primarily intended for user-facing
   * status displays that differentiate between immediate responses and those delivered after a
   * deliberate delay. It does not imply completion or failure of the fetch itself.
   *
   * @return {@code true} if the caller had to wait before receiving this snapshot.
   */
  public boolean hasWaited() {
    return hasWaited;
  }

  /**
   * Determines whether the fetch was finished—successfully or unsuccessfully—when this snapshot was
   * generated.
   *
   * <p>A finished snapshot may contain data, an exception, or neither if the operation concluded
   * without a payload. Use {@link #hasData()} to check for successful completion and {@link
   * #failed} to inspect failures. Because the value is captured at creation time, callers polling
   * for progress should request a new snapshot to observe later state changes.
   *
   * @return {@code true} if the fetch was marked finished at snapshot time; otherwise {@code
   *     false}.
   */
  public boolean isFinished() {
    return finished;
  }

  /**
   * Records how many times this snapshot has been delivered to or processed by the caller.
   *
   * <p>The fetch count is maintained externally for monitoring or throttling purposes and is not
   * used internally by this class. Callers should supply a non-negative value representing the
   * current delivery count. The method performs no validation and simply stores the provided value.
   *
   * @param fetched non-negative number describing how many times the snapshot was fetched.
   */
  public void setFetchCount(int fetched) {
    this.fetchedCount = fetched;
  }

  /**
   * Returns the number of times the caller has marked this snapshot as fetched or processed.
   *
   * <p>This accessor is typically used in reporting or to avoid double-counting when snapshots are
   * reused across polling cycles. The value defaults to zero until explicitly set via {@link
   * #setFetchCount(int)}.
   *
   * @return the current fetch-count marker associated with this snapshot instance.
   */
  public int getFetchCount() {
    return fetchedCount;
  }
}
