package network.crypta.client.async;

import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.node.BaseSendableGet;

/**
 * Callback contract used by {@link SplitFileFetcherStorage} and its collaborators during a split
 * file fetch.
 *
 * <p>This interface decouples the low-level storage/decoding layer from higher-level orchestration
 * such as {@link SplitFileFetcher}. Implementations receive lifecycle notifications (success,
 * failure, and closure), progress signals for fetched or failed blocks, and various hints needed by
 * the storage engine (e.g., priority class, compatibility mode, and healing requests). Typical call
 * patterns are:
 *
 * <ul>
 *   <li>Construction: {@link #setSplitfileBlocks(int, int)} and {@link
 *       #onSplitfileCompatibilityMode(CompatibilityMode, CompatibilityMode, byte[], boolean,
 *       boolean, boolean)} provide initial metadata.
 *   <li>Active fetch: repeated {@link #onFetchedBlock()} / {@link #onFailedBlock()} updates,
 *       optional {@link #queueHeal(byte[], byte[], byte)} requests, and a final {@link
 *       #onSuccess()} when decoding completes.
 *   <li>Shutdown: {@link #onClosed()} is called after both the higher-level code has finished and
 *       the storage has been freed.
 * </ul>
 *
 * <p>Implementations should be thread-safe where noted, because some callbacks are invoked on a
 * decode thread. State is typically owned by the fetcher; callbacks should avoid long blocking
 * operations and heavy locking. The interface itself is intentionally narrow to streamline unit
 * testing and to allow storage strategies to evolve independently.
 *
 * <p>FIXME reconsider.
 *
 * @author toad
 * @see SplitFileFetcher
 * @see SplitFileFetcherStorage
 * @see SplitFileFetcherKeyListener
 */
public interface SplitFileFetcherStorageCallback {

  /**
   * Signal that the splitfile has been fully downloaded and decoded by the storage layer.
   *
   * <p>After this callback returns, consumers can treat the decoded content as available for read
   * operations (for example, stream generators in higher levels). The underlying storage might
   * still retain access to the data to finalize internal steps such as generating healing blocks.
   * Final resource release happens only after the higher layer has indicated completion and the
   * storage has finished its own post-processing, at which point {@link #onClosed()} will be
   * invoked.
   */
  void onSuccess();

  /**
   * Return the priority class associated with this fetch request.
   *
   * <p>The value is used by the storage/fetch pipeline to choose scheduling policies (for example,
   * forward error correction work queues). Implementations should return a stable value for the
   * lifetime of a single fetch operation. Higher numeric values usually indicate lower priority
   * classes in the surrounding system, unless documented otherwise by the caller.
   *
   * @return a priority class identifier for scheduling decisions; callers treat the value as
   *     read-only and do not modify it after retrieval.
   */
  short getPriorityClass();

  /**
   * Report an unrecoverable disk I/O error encountered by the storage layer.
   *
   * <p>Implementations should propagate the failure to upstream components, log sufficiently for
   * diagnosis, and ensure that no further work proceeds on the failed request. This callback may be
   * invoked from a worker or decode thread.
   *
   * @param e the I/O exception that triggered the failure; non-null and represents the immediate
   *     cause as observed by the storage layer.
   */
  void failOnDiskError(IOException e);

  /**
   * Report unrecoverable data corruption detected by the storage layer.
   *
   * <p>Unlike I/O failures, corruption indicates that on-disk data failed integrity verification
   * (e.g., checksum mismatch). Implementations should abort the request and surface a clear error
   * to clients. This callback may be invoked on a decode thread.
   *
   * @param e the checksum failure that explains the corruption; non-null and specific to the
   *     detected condition.
   */
  void failOnDiskError(ChecksumFailedException e);

  /**
   * Provide the expected splitfile block counts to cooperating layers during initialization.
   *
   * <p>The pair distinguishes between blocks that are strictly required to complete decoding and
   * additional blocks that may be fetched to improve redundancy or to enable forward error
   * correction. Values are non-negative and typically remain constant for the duration of the
   * request.
   *
   * @param requiredBlocks the number of blocks that must be fetched for a successful decode; zero
   *     is valid for empty content but unusual in practice.
   * @param remainingBlocks the number of non-required blocks (total minus required); used for
   *     progress reporting and scheduling decisions across segments.
   */
  void setSplitfileBlocks(int requiredBlocks, int remainingBlocks);

  /**
   * Called during construction, when we know the settings for the splitfile.
   *
   * @param min The lowest CompatibilityMode that appears to be valid based on what we've fetched so
   *     far.
   * @param max The highest CompatibilityMode that appears to be valid based on what we've fetched
   *     so far.
   * @param customSplitfileKey The fixed byte[] encryption key used on insert. On anything recent,
   *     we generate a single key, randomly for an SSK, or based on the content for a CHK, and use
   *     it for everything. This saves metadata space and improves security for SSKs.
   * @param compressed Whether the content is compressed. If false, the dontCompress option was
   *     used.
   * @param bottomLayer Whether this report originates at the bottom layer of the splitfile pyramid.
   *     I.e. the actual file, not the file containing the metadata to fetch the file (this can
   *     recurse for several levels!)
   * @param definitiveAnyway Whether this report is definitive even though it's not from the bottom
   *     layer. This is true of recent splitfiles, where we store all the data in the top key.
   */
  void onSplitfileCompatibilityMode(
      CompatibilityMode min,
      CompatibilityMode max,
      byte[] customSplitfileKey,
      boolean compressed,
      boolean bottomLayer,
      boolean definitiveAnyway);

  /**
   * Queue a block for healing by the storage layer.
   *
   * <p>Healing requests are typically issued when decoding reveals an otherwise fixable defect or
   * when parity information needs to be regenerated. The method is called from a decode thread, so
   * implementations must avoid heavy locking and long-running operations.
   *
   * @param data the raw block payload bytes to be considered for healing; must not be modified
   *     after the call returns by the implementation.
   * @param cryptoKey the symmetric key or key material associated with the block; the exact format
   *     depends on the crypto algorithm in use.
   * @param cryptoAlgorithm an identifier for the crypto algorithm used for the block; callers pass
   *     a protocol-defined code and expect the implementation to interpret it.
   */
  void queueHeal(byte[] data, byte[] cryptoKey, byte cryptoAlgorithm);

  /**
   * Notify that the request has fully completed and all resources have been released.
   *
   * <p>This is invoked after the higher-level components have indicated that they are done and the
   * storage has freed backing resources. Implementations should perform final cleanup and update
   * any persistent state or user-visible status.
   */
  void onClosed();

  /**
   * Indicate that a block has been fetched and processed successfully.
   *
   * <p>Callers invoke this for every successful block retrieval/verification. Implementations may
   * update progress indicators, adjust scheduling, or trigger downstream notifications. The call is
   * side effect only and does not carry block content.
   */
  void onFetchedBlock();

  /**
   * Called when the splitfile fetcher gives up on a block. (Assumed to be a non-fatal error, run
   * out of retries)
   */
  void onFailedBlock();

  /**
   * Resume notification providing a summary of previous progress and known metadata.
   *
   * <p>Invoked when an interrupted fetch resumes, allowing implementations to reconstruct progress
   * indicators and status. The method does not imply that any thread or queue is already active; it
   * merely communicates the last known state according to persisted storage.
   *
   * @param succeededBlocks the number of blocks previously fetched and verified as correct; must be
   *     non-negative and not exceed the total for the splitfile.
   * @param failedBlocks the number of blocks previously attempted and ultimately abandoned; used
   *     for diagnostics and backoff behavior.
   * @param mimeType the best-known content type metadata if available, or {@code null} when the
   *     type is not yet determined; callers do not retain ownership.
   * @param finalSize the expected final size of the decoded content in bytes, or a negative value
   *     when unknown; implementations should tolerate large values.
   */
  void onResume(int succeededBlocks, int failedBlocks, ClientMetadata mimeType, long finalSize);

  /**
   * Called when the fetch failed, for example after exhausting retry attempts.
   *
   * @param fetchException a structured description of the failure condition; contains user-facing
   *     details and internal causes that can be logged or surfaced to clients.
   */
  void fail(FetchException fetchException);

  /**
   * Called whenever we successfully download, decode or encode a block, and it matches the expected
   * key. LOCKING: Called on the decode thread so should avoid taking any dangerous locks.
   *
   * @param decodedBlock the verified block that matched its expected key; implementations must not
   *     mutate the instance and should treat it as read-only input for aggregation logic.
   */
  void maybeAddToBinaryBlob(ClientCHKBlock decodedBlock);

  /**
   * Indicate whether {@link #maybeAddToBinaryBlob(ClientCHKBlock)} should be invoked for blocks.
   *
   * <p>Implementations return {@code true} to request that eligible blocks be passed to {@code
   * maybeAddToBinaryBlob}. The method must be fast and lock-free. The decision typically depends on
   * caller needs, such as building an out-of-band aggregate or deduplication index.
   *
   * @return {@code true} when the storage layer should receive decoded blocks via {@link
   *     #maybeAddToBinaryBlob(ClientCHKBlock)}; {@code false} to skip such callbacks.
   */
  boolean wantBinaryBlob();

  /**
   * Return the associated {@link BaseSendableGet} if one exists.
   *
   * <p>The value is optional and may be {@code null}. It is primarily used by components that need
   * insight into the lower-level request object (for example, for key listeners or diagnostics).
   * Callers must not mutate the returned object.
   *
   * @return the related sendable-get instance, or {@code null} when not applicable or unavailable.
   */
  BaseSendableGet getSendableGet();

  /**
   * Called when we recover from disk corruption, and have to re-download some blocks that we had
   * already downloaded but which were corrupted on disk. E.g. when a segment attempts to decode but
   * discovers that a block doesn't match the key given.
   */
  void restartedAfterDataCorruption();

  /** Called when the fetcher may have exited cooldown early. */
  void clearCooldown();

  /**
   * Indicate that the cooldown wake-up time was reduced but the request remains non-fetchable.
   *
   * <p>Implementations may update internal timers or user-visible schedules. This is a hint rather
   * than a guarantee and does not by itself make the request immediately eligible for fetch.
   *
   * @param wakeupTime the next suggested wake-up time in milliseconds since the epoch; callers do
   *     not assume strict adherence and may send subsequent updates.
   */
  void reduceCooldown(long wakeupTime);

  /**
   * Return an object exposing key-listener registration, when available.
   *
   * <p>The return value is optional and may be {@code null}. It enables the listener wiring needed
   * by components such as {@link SplitFileFetcherKeyListener}. Implementations should not perform
   * heavy work when this method is called.
   *
   * @return an accessor for key-listener integration, or {@code null} if not supported.
   */
  HasKeyListener getHasKeyListener();

  /**
   * Return the {@link KeySalter} used to derive or adjust keys for this fetch, if any.
   *
   * <p>Salting affects how keys are formed or compared during block processing. The value is
   * immutable for the lifetime of the fetch. The method may return {@code null} when salting is not
   * used in the current context.
   *
   * @return the key salter associated with this request, or {@code null} when salting is disabled
   *     or not required.
   */
  KeySalter getSalter();
}
