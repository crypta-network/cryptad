package network.crypta.client.async;

import network.crypta.client.InsertBlock;
import network.crypta.client.InsertContext;
import network.crypta.crypt.HashResult;

/**
 * Mutable parameter bundle for constructing {@link SingleFileInserter} instances.
 *
 * <p>This type centralizes the inputs that would otherwise be passed as a long constructor argument
 * list, keeping call sites readable while preserving the original semantics. Callers typically
 * allocate a new instance, configure it fluently with the {@code with*} methods, and pass it
 * directly to {@link SingleFileInserter}. The bundle performs no validation, normalization, or
 * defensive copying; it exists purely as a structured carrier of values that the inserter will
 * interpret later.
 *
 * <p>Because the fields are mutable and package-visible, instances are not thread-safe and should
 * be treated as short-lived setup objects. After construction, callers should avoid reusing or
 * mutating the same instance across threads or across unrelated insert operations. Any mutable
 * references (such as {@code origHashes}) are stored by reference, so callers retain ownership of
 * their contents and must keep them stable until the inserter no longer needs them.
 *
 * <ul>
 *   <li>Encapsulates inserter inputs without adding validation or behavior.
 *   <li>Supports a fluent setup style via package-local {@code with*} methods.
 *   <li>Intended for one-shot configuration, not long-term storage.
 * </ul>
 *
 * @see SingleFileInserter
 */
public final class SingleFileInserterParams {
  /**
   * Parent putter that owns the insert lifecycle and receives state transitions.
   *
   * <p>Set this before construction to ensure callbacks and counters are wired correctly. This
   * reference is stored as-is and may be {@code null} only in test or specialized flows that
   * tolerate a missing parent.
   */
  BaseClientPutter parent;

  /**
   * Callback invoked for state changes, completion, and failure notifications.
   *
   * <p>The callback must remain valid for the duration of the insert. It may be {@code null} only
   * when the caller intentionally suppresses notifications, such as in tightly scoped tests.
   */
  PutCompletionCallback callback;

  /**
   * Input block containing data, optional client metadata, and the desired URI.
   *
   * <p>The inserter reads from this block and may null out its data after scheduling when the
   * request is persistent. The block reference is stored without copying.
   */
  InsertBlock block;

  /**
   * Flag indicating whether this inserter is processing metadata rather than primary content.
   *
   * <p>This influences hashing behavior and redirect/manifest handling. The value is stored
   * verbatim and interpreted by {@link SingleFileInserter} during preprocessing.
   */
  boolean metadata;

  /**
   * Insert context that supplies compatibility settings, retry policies, and factories.
   *
   * <p>The context is read at scheduling time and is expected to remain stable for the lifetime of
   * the insert. It is stored by reference without validation.
   */
  InsertContext ctx;

  /**
   * Execution options controlling compression, crypto settings, and scheduling hints.
   *
   * <p>These options are reused across inserter types and are stored as provided. Callers should
   * not mutate shared instances once passed to the inserter.
   */
  InsertExecutionOptions executionOptions;

  /**
   * Application-supplied correlation token forwarded to callbacks.
   *
   * <p>This token may be {@code null}. It is stored by reference and typically used for logging or
   * request correlation by higher layers.
   */
  Object token;

  /**
   * Whether the underlying data bucket should be freed as soon as possible.
   *
   * <p>This flag allows memory- or disk-backed buckets to be released early once the inserter no
   * longer needs the payload. It does not affect the logical success or failure of the insert.
   */
  boolean freeData;

  /**
   * Optional filename to use when emitting a redirect/manifest wrapper.
   *
   * <p>When non-{@code null}, the inserter wraps generated metadata under this name. The string is
   * stored as provided and is not validated here.
   */
  String targetFilename;

  /**
   * Indicates whether this insert is above a splitfile layer.
   *
   * <p>This flag affects extra-insert policies for block scheduling. It is stored verbatim and
   * evaluated by the inserter when constructing downstream components.
   */
  boolean forSplitfile;

  /**
   * Whether the insert should survive process restarts and resume later.
   *
   * <p>Persistent inserts use different bucket factories and may serialize state. The flag is
   * passed through to downstream inserters without validation.
   */
  boolean persistent;

  /**
   * Original uncompressed length of the payload in bytes, or {@code 0} when unknown.
   *
   * <p>This value is used for metadata reporting and progress displays. It is not validated for
   * consistency with the data bucket size.
   */
  long origDataLength;

  /**
   * Original compressed length of the payload in bytes, or {@code 0} when unknown.
   *
   * <p>This is used for reporting and metadata emission when available. The value is stored as
   * provided without range checks.
   */
  long origCompressedDataLength;

  /**
   * Optional precomputed hashes for the original data.
   *
   * <p>The array is stored by reference and may be {@code null}. Callers must keep the contents
   * stable until the inserter finishes consuming them.
   */
  HashResult[] origHashes;

  /**
   * Threshold in bytes for returning inline metadata instead of a URI, or non-positive to disable.
   *
   * <p>The inserter compares this to the serialized metadata size to decide whether to return raw
   * metadata bytes. The value is stored as provided.
   */
  long metadataThreshold;

  /**
   * Creates an empty parameter bundle with all fields left at their default values.
   *
   * <p>This constructor performs no initialization beyond the Java defaults. Callers are expected
   * to populate every required field using the fluent {@code with*} methods before handing the
   * instance to {@link SingleFileInserter}. Leaving fields unset will defer validation to the
   * inserter and may result in failures during scheduling or preprocessing. This constructor is
   * intentionally lightweight and side-effect free.
   */
  public SingleFileInserterParams() {
    // Intentionally empty: callers configure fields via the fluent setters.
  }

  /**
   * Sets the parent putter that coordinates this insert.
   *
   * <p>This should be a non-null instance that can accept progress notifications. The value is
   * stored by reference with no validation. Returns {@code this} to allow fluent setup.
   *
   * @param parent parent putter responsible for lifecycle coordination; may be {@code null} in
   *     controlled test scenarios
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withParent(BaseClientPutter parent) {
    this.parent = parent;
    return this;
  }

  /**
   * Sets the completion callback to receive state transitions and terminal events.
   *
   * <p>The callback should remain valid for the duration of the insert. The reference is stored
   * verbatim, and {@code null} is only appropriate when callers intentionally suppress callbacks.
   *
   * @param callback callback to receive insert lifecycle notifications; may be {@code null} when
   *     callers do not require notifications
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withCallback(PutCompletionCallback callback) {
    this.callback = callback;
    return this;
  }

  /**
   * Sets the input {@link InsertBlock} containing data and target URI information.
   *
   * <p>The block is stored by reference and may be mutated by the inserter during scheduling for
   * persistence reasons. Callers should not reuse the block after passing it along.
   *
   * @param block insert block with data, optional metadata, and desired URI; may be {@code null}
   *     only when tests intentionally bypass scheduling
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withBlock(InsertBlock block) {
    this.block = block;
    return this;
  }

  /**
   * Sets whether this inserter is treating the payload as metadata.
   *
   * <p>Metadata inserts can alter hashing and redirect behavior. This flag is stored as given and
   * interpreted by {@link SingleFileInserter} later.
   *
   * @param metadata {@code true} to treat the payload as metadata; {@code false} for primary data
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withMetadata(boolean metadata) {
    this.metadata = metadata;
    return this;
  }

  /**
   * Sets the {@link InsertContext} that provides compatibility and operational settings.
   *
   * <p>The context reference is stored without validation or copying. It should remain usable for
   * the duration of the insert.
   *
   * @param ctx insert context supplying policies and factories; may be {@code null} only in tests
   *     that never schedule the inserter
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withCtx(InsertContext ctx) {
    this.ctx = ctx;
    return this;
  }

  /**
   * Sets the execution options that control compression, crypto, and scheduling hints.
   *
   * <p>The options object is stored by reference and should not be mutated after being set. This
   * method performs no validation.
   *
   * @param executionOptions options describing compression, crypto, and scheduling behavior; may be
   *     {@code null} only if the inserter tolerates missing options
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withExecutionOptions(InsertExecutionOptions executionOptions) {
    this.executionOptions = executionOptions;
    return this;
  }

  /**
   * Sets the application correlation token forwarded to callbacks.
   *
   * <p>The token is stored by reference and may be {@code null}. Callers typically use it for
   * request tracking or logging.
   *
   * @param token opaque application token to echo on callbacks; may be {@code null}
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withToken(Object token) {
    this.token = token;
    return this;
  }

  /**
   * Sets whether the inserter should free the data bucket as early as possible.
   *
   * <p>This flag influences resource release timing but does not affect insert correctness.
   *
   * @param freeData {@code true} to free data as soon as possible; {@code false} to retain longer
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withFreeData(boolean freeData) {
    this.freeData = freeData;
    return this;
  }

  /**
   * Sets an optional filename to use when wrapping metadata in a redirect manifest.
   *
   * <p>When non-{@code null}, the inserter emits a redirect manifest keyed by this name. No
   * validation is performed here.
   *
   * @param targetFilename optional filename for metadata wrapping; may be {@code null}
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withTargetFilename(String targetFilename) {
    this.targetFilename = targetFilename;
    return this;
  }

  /**
   * Sets whether the insertion is above a splitfile layer.
   *
   * <p>This affects extra-insert policies in downstream inserters. The value is stored verbatim.
   *
   * @param forSplitfile {@code true} when the insert is above a splitfile; {@code false} otherwise
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withForSplitfile(boolean forSplitfile) {
    this.forSplitfile = forSplitfile;
    return this;
  }

  /**
   * Sets whether the insert should be durable across restarts.
   *
   * <p>Persistent inserts use durable buckets and may be serialized for resume. No validation is
   * performed by this method.
   *
   * @param persistent {@code true} for durable inserts; {@code false} for transient inserts
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withPersistent(boolean persistent) {
    this.persistent = persistent;
    return this;
  }

  /**
   * Sets the original uncompressed data length for reporting and metadata emission.
   *
   * <p>Use {@code 0} when the length is unknown. The value is stored as provided without checks.
   *
   * @param origDataLength original uncompressed length in bytes; {@code 0} when unknown
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withOrigDataLength(long origDataLength) {
    this.origDataLength = origDataLength;
    return this;
  }

  /**
   * Sets the original compressed data length for reporting and metadata emission.
   *
   * <p>Use {@code 0} when unknown. The value is stored as provided and may be inconsistent with the
   * actual compressed size, which is not validated here.
   *
   * @param origCompressedDataLength original compressed length in bytes; {@code 0} when unknown
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withOrigCompressedDataLength(long origCompressedDataLength) {
    this.origCompressedDataLength = origCompressedDataLength;
    return this;
  }

  /**
   * Sets the precomputed hash array for the original data.
   *
   * <p>The array is stored by reference and may be {@code null}. Callers should not mutate its
   * contents after passing it in if they rely on stable hashing output.
   *
   * @param origHashes optional precomputed hashes for the original data; may be {@code null}
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withOrigHashes(HashResult[] origHashes) {
    this.origHashes = origHashes;
    return this;
  }

  /**
   * Sets the metadata size threshold for returning inline bytes.
   *
   * <p>Values greater than zero cause the inserter to return raw metadata bytes when the serialized
   * metadata fits under this threshold. Non-positive values disable the optimization.
   *
   * @param metadataThreshold byte threshold for inline metadata; non-positive disables inlining
   * @return this bundle instance for chained configuration
   */
  SingleFileInserterParams withMetadataThreshold(long metadataThreshold) {
    this.metadataThreshold = metadataThreshold;
    return this;
  }
}
