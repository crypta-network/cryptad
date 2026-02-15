package network.crypta.client.async;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.Metadata;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.FreenetURI;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.Ticker;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.FileRandomAccessBufferFactory;

/**
 * Holds the inputs required to initialize a splitfile fetch storage session.
 *
 * <p>This type is a simple data carrier that mirrors the parameters needed to start a new {@link
 * SplitFileFetcherStorage} instance for a splitfile fetch. It captures parsed {@link Metadata}, the
 * decompression pipeline, client metadata, and the various execution helpers (job runners, tickers,
 * randomness, and checksum policy) that are supplied at runtime. Instances are typically produced
 * via {@link Builder} and then passed directly to {@link
 * SplitFileFetcherStorage#SplitFileFetcherStorage(SplitFileFetcherStorageInitParams)} without
 * further transformation or validation.
 *
 * <p>Most fields are stored as references, while mutable array/list inputs such as client details
 * and decompressor lists are defensively copied. Callers should still treat the built instance as
 * immutable and avoid mutating supplied objects after {@link Builder#build()}. The container
 * performs no I/O and is not thread-safe; publish it to a single thread or apply external
 * synchronization if multiple threads may read it concurrently.
 *
 * <ul>
 *   <li>Captures metadata, keys, and compression settings for the fetch plan.
 *   <li>Bundles execution-time helpers such as schedulers, RNG, and checksum policy.
 *   <li>Provides a stable snapshot to hand to storage construction.
 * </ul>
 *
 * @see SplitFileFetcherStorage
 * @see SplitFileFetcherStorageInitParams.Builder
 */
public final class SplitFileFetcherStorageInitParams {
  Metadata metadata;
  SplitFileFetcherStorageCallback fetcher;
  List<COMPRESSOR_TYPE> decompressors;
  ClientMetadata clientMetadata;
  boolean topDontCompress;
  short topCompatibilityMode;
  FetchContext origFetchContext;
  boolean realTime;
  KeySalter salt;
  FreenetURI thisKey;
  FreenetURI origKey;
  boolean isFinalFetch;
  byte[] clientDetails;
  RandomSource random;
  BucketFactory tempBucketFactory;
  LockableRandomAccessBufferFactory rafFactory;
  PersistentJobRunner exec;
  Ticker ticker;
  MemoryLimitedJobRunner memoryLimitedJobRunner;
  ChecksumChecker checker;
  boolean persistent;
  File storageFile;
  FileRandomAccessBufferFactory diskSpaceCheckingRAFFactory;
  KeysFetchingLocally keysFetching;

  /**
   * Builds {@link SplitFileFetcherStorageInitParams} instances through fluent, mutable setters.
   *
   * <p>This builder is a lightweight accumulator: each setter stores the provided reference and
   * returns {@code this} for chaining. It performs no I/O and no validation. Selected mutable
   * inputs (byte arrays and decompressor lists) are defensively copied. The final {@link #build()}
   * call creates a new parameter snapshot containing the current references; subsequent setter
   * calls do not affect already-built instances. Because the builder is mutable and unsynchronized,
   * it should be confined to one thread or externally synchronized if shared.
   *
   * <ul>
   *   <li>Set metadata, keys, and compression choices in a single place.
   *   <li>Provide runtime helpers such as tickers, RNGs, and job runners.
   *   <li>Create repeatable snapshots by reusing the same builder.
   * </ul>
   */
  public static class Builder {
    private Metadata metadata;
    private SplitFileFetcherStorageCallback fetcher;
    private List<COMPRESSOR_TYPE> decompressors;
    private ClientMetadata clientMetadata;
    private boolean topDontCompress;
    private short topCompatibilityMode;
    private FetchContext origFetchContext;
    private boolean realTime;
    private KeySalter salt;
    private FreenetURI thisKey;
    private FreenetURI origKey;
    private boolean isFinalFetch;
    private byte[] clientDetails;
    private RandomSource random;
    private BucketFactory tempBucketFactory;
    private LockableRandomAccessBufferFactory rafFactory;
    private PersistentJobRunner exec;
    private Ticker ticker;
    private MemoryLimitedJobRunner memoryLimitedJobRunner;
    private ChecksumChecker checker;
    private boolean persistent;
    private File storageFile;
    private FileRandomAccessBufferFactory diskSpaceCheckingRAFFactory;
    private KeysFetchingLocally keysFetching;

    /**
     * Sets the parsed splitfile {@link Metadata} used to plan the fetch.
     *
     * <p>This setter records the provided reference on the builder and performs no validation or
     * copying. If invoked multiple times, the most recent value replaces any earlier one. Passing
     * {@code null} clears the stored value, which may cause construction to fail later if storage
     * logic requires metadata. Treat the supplied object as effectively immutable once {@link
     * #build()} is called.
     *
     * @param v metadata describing segments and blocks; stored without defensive copy.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder metadata(Metadata v) {
      this.metadata = v;
      return this;
    }

    /**
     * Sets the fetcher callback that receives progress and completion events.
     *
     * <p>This setter stores the callback reference without validation, copying, or lifecycle
     * management. If the method is called more than once, the latest callback replaces the prior
     * one. A {@code null} value clears the field and may defer failure until the storage
     * constructor attempts to publish events. The stored reference is used as-is by downstream
     * logic.
     *
     * @param v callback for progress and completion events; stored as provided.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder fetcher(SplitFileFetcherStorageCallback v) {
      this.fetcher = v;
      return this;
    }

    /**
     * Configures the decompressor pipeline to apply after block decode.
     *
     * <p>The list is defensively copied to avoid aliasing with caller-owned mutable lists. Order
     * matters: callers are responsible for supplying the correct sequence for the metadata they
     * expect to decode. A {@code null} or empty list indicates no additional decompression steps
     * beyond the mandatory decoding performed elsewhere. The last value provided wins when this
     * setter is called repeatedly.
     *
     * @param v ordered compressor list to apply after decode; may be null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder decompressors(List<COMPRESSOR_TYPE> v) {
      this.decompressors = copyListNullable(v);
      return this;
    }

    /**
     * Supplies optional client metadata to attach to the completed object.
     *
     * <p>This setter records the provided metadata reference without validation or copying. It may
     * be {@code null} to indicate the absence of client-side metadata, in which case downstream
     * consumers decide on defaults. If you call this method multiple times, the most recent value
     * replaces any previous one. Avoid mutating the supplied metadata after {@link #build()}.
     *
     * @param v optional client metadata for the final object; may be null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder clientMetadata(ClientMetadata v) {
      this.clientMetadata = v;
      return this;
    }

    /**
     * Sets whether the top-level container should avoid compression.
     *
     * <p>This setter stores the flag value directly and does not enforce any compatibility checks.
     * The flag influences how downstream code chooses compression behavior, but the builder itself
     * does not interpret it. Repeated calls simply overwrite the previous value. When left at the
     * default {@code false}, downstream components may still decide to skip compression based on
     * their own rules.
     *
     * @param v flag indicating whether top-level compression is skipped.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder topDontCompress(boolean v) {
      this.topDontCompress = v;
      return this;
    }

    /**
     * Specifies the minimum compatibility mode expected by the consumer.
     *
     * <p>The provided short value is stored without validation or normalization. The builder does
     * not interpret the meaning of the mode; it simply passes it through to storage construction.
     * Callers are responsible for selecting a value compatible with the metadata and protocol
     * expectations in use. The last value set wins if this method is called more than once.
     *
     * @param v compatibility mode identifier stored as provided; not validated.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder topCompatibilityMode(short v) {
      this.topCompatibilityMode = v;
      return this;
    }

    /**
     * Provides the fetch context carrying retry and cooldown policy.
     *
     * <p>This setter stores the supplied context reference as-is and does not attempt to validate
     * timeouts, limits, or priorities. If called multiple times, the most recent value overwrites
     * any earlier one. Supplying {@code null} clears the context and may lead to failures later if
     * the storage logic requires a valid context. Callers should avoid mutating the context after
     * {@link #build()}.
     *
     * @param v fetch context carrying retry and priority policy; stored as provided.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder fetchContext(FetchContext v) {
      this.origFetchContext = v;
      return this;
    }

    /**
     * Indicates whether the fetch should prefer reduced buffering (real-time).
     *
     * <p>This setter records the boolean flag without additional validation or side effects. The
     * meaning of real-time mode is interpreted by downstream scheduling and buffering logic rather
     * than by the builder itself. Repeated calls simply overwrite the previously stored value. When
     * left {@code false}, default buffering behavior is preserved unless other components override
     * it.
     *
     * @param v flag selecting real-time scheduling preference for the fetch.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder realTime(boolean v) {
      this.realTime = v;
      return this;
    }

    /**
     * Sets the key salter used when deriving salted keys for requests.
     *
     * <p>This setter stores the salter reference directly and does not validate its behavior. A
     * {@code null} value indicates that salting should be skipped or handled elsewhere. If invoked
     * multiple times, the most recent salter replaces any earlier one. Callers should ensure the
     * provided instance has the desired lifetime and thread-safety properties for their context.
     *
     * @param v optional key-salter strategy; null disables salting.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder salt(KeySalter v) {
      this.salt = v;
      return this;
    }

    /**
     * Sets the primary request URI associated with this fetch.
     *
     * <p>The provided URI reference is stored without validation or copying. Downstream components
     * may use the value for logging, provenance, or request key derivation. If this method is
     * called multiple times, the latest value replaces the previous one. Passing {@code null}
     * clears the field, which may cause storage initialization to fail if a key is required.
     *
     * @param v primary URI associated with this fetch; stored as provided.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder thisKey(FreenetURI v) {
      this.thisKey = v;
      return this;
    }

    /**
     * Optionally records the original user-facing URI if different from {@link #thisKey}.
     *
     * <p>This setter stores the reference as provided and does not compare it with {@code thisKey}
     * or perform normalization. A {@code null} value indicates there is no distinct original key.
     * If called multiple times, the last value wins. Downstream components may use this value to
     * preserve provenance or to display canonical forms to users.
     *
     * @param v original or canonical URI for provenance; may be null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder origKey(FreenetURI v) {
      this.origKey = v;
      return this;
    }

    /**
     * Indicates whether this fetch corresponds to the final content rather than metadata.
     *
     * <p>The flag value is stored directly and is not interpreted by the builder itself. Downstream
     * logic may treat {@code true} as a signal that the request targets final payload data, while
     * {@code false} may indicate intermediate or metadata-only stages. If called multiple times,
     * the latest value replaces the earlier one with no additional side effects.
     *
     * @param v flag marking whether this fetch targets final data.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder isFinalFetch(boolean v) {
      this.isFinalFetch = v;
      return this;
    }

    /**
     * Attaches opaque client details preserved for callbacks and auditing.
     *
     * <p>The byte array is defensively copied on set to avoid aliasing mutable caller-owned
     * buffers. A {@code null} value indicates that no client details are supplied. If this setter
     * is invoked multiple times, the most recent array value replaces any prior one.
     *
     * @param v opaque client detail bytes; copied when non-null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder clientDetails(byte[] v) {
      this.clientDetails = copyBytesNullable(v);
      return this;
    }

    /**
     * Provides the source of randomness used for key scheduling and shuffling.
     *
     * <p>This setter stores the randomness provider reference without validation or wrapping. If
     * called multiple times, the most recent provider replaces any earlier one. Supplying {@code
     * null} clears the reference; downstream components may reject {@code null} depending on the
     * execution mode. The builder does not assume ownership and will not close or otherwise manage
     * the provider.
     *
     * @param v randomness source for scheduling or shuffling; may be null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder random(RandomSource v) {
      this.random = v;
      return this;
    }

    /**
     * Sets the temporary bucket factory used to stage metadata before persistence.
     *
     * <p>This setter records the factory reference with no validation or defensive copying. The
     * builder does not create buckets or verify compatibility; it merely stores the supplier for
     * later use. If invoked multiple times, the latest factory replaces the earlier one. When
     * persistence is enabled, downstream logic may require a non-null factory to buffer metadata.
     *
     * @param v factory for temporary buckets used during persistence; may be null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder tempBucketFactory(BucketFactory v) {
      this.tempBucketFactory = v;
      return this;
    }

    /**
     * Configures the random-access buffer factory that creates the backing store.
     *
     * <p>The provided factory reference is stored as-is and is not validated or wrapped. The
     * builder does not attempt to open files or allocate buffers; it only captures the factory for
     * later use by storage construction. If set more than once, the most recent factory replaces
     * the previous one. Callers should ensure the factory is compatible with any chosen storage
     * file and persistence mode.
     *
     * @param v factory for persistent random-access buffers; stored without validation.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder rafFactory(LockableRandomAccessBufferFactory v) {
      this.rafFactory = v;
      return this;
    }

    /**
     * Provides the job runner used for off-thread work and callbacks.
     *
     * <p>This setter stores the job runner reference without validation or lifecycle management. If
     * called multiple times, the most recent runner replaces any earlier one. Supplying {@code
     * null} clears the reference and may lead to failures later if asynchronous execution is
     * required. The builder does not manage threads or scheduling; it merely captures the runner.
     *
     * @param v persistent job runner for async tasks; stored as provided.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder exec(PersistentJobRunner v) {
      this.exec = v;
      return this;
    }

    /**
     * Sets the time source/scheduler used for delayed tasks and de-duplication.
     *
     * <p>The provided ticker reference is stored directly with no validation or wrapping. The
     * builder does not schedule tasks or query time; it only retains the reference for later use.
     * If set repeatedly, the newest value replaces the previous one. A {@code null} value clears
     * the field and may cause failures if scheduling or de-duplication requires a ticker.
     *
     * @param v time source used for scheduling and de-duplication; stored.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder ticker(Ticker v) {
      this.ticker = v;
      return this;
    }

    /**
     * Provides the memory-limited job runner used for heavy decode/encode work.
     *
     * <p>This setter stores the provided runner reference without validation or configuration. The
     * builder does not execute jobs or enforce memory limits itself; it merely captures the runner
     * for later use by storage and decoding logic. If called more than once, the last runner
     * replaces the earlier one. Supplying {@code null} may defer failure until heavy work is
     * scheduled.
     *
     * @param v memory-aware job runner for heavy work; stored as provided.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder memoryLimitedJobRunner(MemoryLimitedJobRunner v) {
      this.memoryLimitedJobRunner = v;
      return this;
    }

    /**
     * Chooses the checksum implementation and length used in persisted sections.
     *
     * <p>The checker reference is stored without validation or defensive copying. The builder does
     * not compute checksums or verify consistency; it only records the implementation to be used by
     * storage and persistence code. If called multiple times, the latest checker replaces the
     * previous one. A {@code null} value clears the field and may cause later failures if checksum
     * verification is required.
     *
     * @param v checksum policy implementation including length; stored as provided.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder checker(ChecksumChecker v) {
      this.checker = v;
      return this;
    }

    /**
     * Enables or disables persistence of metadata and progress across restarts.
     *
     * <p>This setter records the persistence flag without validation or side effects. The builder
     * does not allocate storage or check disk space; it simply captures the intent to persist. When
     * {@code true}, downstream logic may require additional factories and storage configuration to
     * be present. If called repeatedly, the most recent value replaces the previous one.
     *
     * @param v flag enabling persistence of metadata and progress.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder persistent(boolean v) {
      this.persistent = v;
      return this;
    }

    /**
     * Provides an explicit file for the backing store when truncation is desired.
     *
     * <p>This setter stores the file reference without creating or validating the file. Downstream
     * storage code may use the file to place or truncate persistent data, but the builder does not
     * touch the filesystem. A {@code null} value indicates that the storage layer should select its
     * own file location. If called more than once, the latest file replaces the earlier one.
     *
     * @param v target file used for backing storage; may be null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder storageFile(File v) {
      this.storageFile = v;
      return this;
    }

    /**
     * Configures a disk-space checking RAF factory for safer persistent allocations.
     *
     * <p>The provided factory reference is stored as-is and is not validated or wrapped. The
     * builder does not check disk space itself; it merely captures the factory for later use by
     * persistence logic. Passing {@code null} disables this additional safety check. If called
     * multiple times, the last value replaces any earlier one.
     *
     * @param v factory that validates disk space for RAF allocations; optional.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder diskSpaceCheckingRAFFactory(FileRandomAccessBufferFactory v) {
      this.diskSpaceCheckingRAFFactory = v;
      return this;
    }

    /**
     * Sets the key-tracking helper that marks keys as fetching locally.
     *
     * <p>This setter stores the helper reference without validation or copying. The builder does
     * not register or unregister keys; it only supplies the helper to downstream components. A
     * {@code null} value indicates that no local key tracking should be performed. If called
     * multiple times, the most recent helper replaces any earlier one.
     *
     * @param v helper tracking keys fetched locally; may be null.
     * @return this builder instance so further parameters can be chained.
     */
    public Builder keysFetching(KeysFetchingLocally v) {
      this.keysFetching = v;
      return this;
    }

    /**
     * Builds a new snapshot of the current builder state.
     *
     * <p>This method allocates a fresh {@link SplitFileFetcherStorageInitParams} instance and
     * copies the current builder references into it. No validation, normalization, or defensive
     * copying is performed, so the returned snapshot directly reflects the values last provided to
     * the setters. The builder remains mutable and may be reused to create additional snapshots;
     * subsequent changes do not affect previously built instances but may share referenced objects.
     *
     * @return a new parameter snapshot holding the current builder references.
     */
    public SplitFileFetcherStorageInitParams build() {
      SplitFileFetcherStorageInitParams p = new SplitFileFetcherStorageInitParams();
      p.metadata = metadata;
      p.fetcher = fetcher;
      p.decompressors = copyListNullable(decompressors);
      p.clientMetadata = clientMetadata;
      p.topDontCompress = topDontCompress;
      p.topCompatibilityMode = topCompatibilityMode;
      p.origFetchContext = origFetchContext;
      p.realTime = realTime;
      p.salt = salt;
      p.thisKey = thisKey;
      p.origKey = origKey;
      p.isFinalFetch = isFinalFetch;
      p.clientDetails = copyBytesNullable(clientDetails);
      p.random = random;
      p.tempBucketFactory = tempBucketFactory;
      p.rafFactory = rafFactory;
      p.exec = exec;
      p.ticker = ticker;
      p.memoryLimitedJobRunner = memoryLimitedJobRunner;
      p.checker = checker;
      p.persistent = persistent;
      p.storageFile = storageFile;
      p.diskSpaceCheckingRAFFactory = diskSpaceCheckingRAFFactory;
      p.keysFetching = keysFetching;
      return p;
    }
  }

  private static byte[] copyBytesNullable(byte[] input) {
    return input == null ? null : input.clone();
  }

  private static List<COMPRESSOR_TYPE> copyListNullable(List<COMPRESSOR_TYPE> input) {
    return input == null ? null : new ArrayList<>(input);
  }
}
