package network.crypta.client;

import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;

/**
 * Placeholder store item representing an entry that failed to extract from an archive.
 *
 * <p>This type is used when metadata for an archived file is known, but the actual content cannot
 * be provided to callers. Typical reasons include policy or size limits, or failures that make the
 * extracted content unavailable. Code that iterates over archive items can still surface the entry
 * in listings and present a clear error at the point where data would otherwise be read.
 *
 * <p>Instances are created by the archive handling code and are immutable after construction. The
 * data accessors deliberately fail fast: {@code getDataOrThrow()} always throws, and {@code
 * getReaderBucket()} either throws or returns {@code null} if the item was flagged as too large to
 * stream. This design keeps the failure localized to the data path while allowing callers to
 * inspect names, sizes, or other attributes provided by the surrounding context.
 *
 * <ul>
 *   <li>Represents an archived entry that cannot be served.
 *   <li>Defers the precise error message until access time.
 *   <li>Optionally marks entries as “too big” for reader creation.
 * </ul>
 *
 * <p>Thread-safety: instances do not mutate after construction and are safe for concurrent reads.
 */
class ErrorArchiveStoreItem extends ArchiveStoreItem {

  /** Error message. Usually something about the file being too big. */
  String error;

  /**
   * Whether the archived entry exceeded configured size thresholds.
   *
   * <p>When {@code true}, callers should expect {@code getReaderBucket()} to return {@code null} to
   * indicate that no streaming reader is available due to size constraints, while other data access
   * methods will throw with the recorded error message. The flag is read-only and reflects the
   * condition at creation time.
   */
  boolean tooBig;

  /**
   * Create a placeholder item for a file which could not be extracted from the archive.
   *
   * <p>The created instance records the reason for failure and, when applicable, that the entry was
   * considered too large to provide a streaming reader. Listing code may still surface the item by
   * name, while data access will deterministically fail with the recorded error.
   *
   * @param ctx Context that tracks items produced for the enclosing key; never {@code null} and
   *     reused by the caller across related archive entries for consistent state.
   * @param key2 The archive key from which this entry originates, used for grouping and for
   *     diagnostics when reporting failures to the caller or logs.
   * @param name The archive-relative file name that failed to extract; should be a normalized,
   *     displayable name suitable for presenting in user interfaces.
   * @param error Human-readable explanation describing why the content is unavailable; included in
   *     exceptions thrown from data accessors and intended for end-user display.
   * @param tooBig {@code true} when the entry exceeded configured size limits; signals that a
   *     streaming reader cannot be created even if other errors are ignored.
   */
  public ErrorArchiveStoreItem(
      ArchiveStoreContext ctx, FreenetURI key2, String name, String error, boolean tooBig) {
    super(new ArchiveKey(key2, name), ctx);
    this.error = error;
    this.tooBig = tooBig;
  }

  /**
   * Throws an exception with the given error message, because this file could not be extracted from
   * the archive.
   *
   * @return This method never returns normally; the return type is present for API symmetry.
   * @throws ArchiveFailureException always thrown to report the recorded error condition to callers
   *     attempting to access data.
   */
  @Override
  Bucket getDataOrThrow() throws ArchiveFailureException {
    throw new ArchiveFailureException(error);
  }

  /**
   * Reports the on-disk space used by this store item.
   *
   * <p>Placeholder items that represent failed extractions do not allocate persistent storage and
   * therefore consume no space. The value is constant over the lifetime of the instance and is
   * useful when accounting across a mixed collection of successful and failed entries.
   *
   * @return Always {@code 0} because failed or filtered entries do not store any data blocks.
   */
  @Override
  public long spaceUsed() {
    return 0;
  }

  @Override
  Bucket getReaderBucket() throws ArchiveFailureException {
    if (tooBig) return null;
    throw new ArchiveFailureException(error);
  }

  /**
   * Indicates whether the archived entry exceeded size limits that prevent reader creation.
   *
   * <p>When this method returns {@code true}, callers should avoid attempting to stream the entry
   * via {@code getReaderBucket()} and instead handle the condition explicitly in user interfaces or
   * logs. When {@code false}, a reader may still be unavailable if another failure was recorded.
   *
   * @return {@code true} if the entry was flagged as too large to stream; otherwise {@code false}.
   */
  public boolean tooBig() {
    return tooBig;
  }
}
