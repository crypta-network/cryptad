package network.crypta.client.async;

import java.io.File;
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
 * Builder-style constructor arguments for a fresh fetch session.
 *
 * <p>This holder captures all inputs required to initialise a brand-new storage instance when a
 * splitfile fetch begins. It mirrors the metadata-driven structure of the file (segment keys,
 * compression chain, client metadata) and also includes execution-time components such as
 * schedulers, randomness and checksum policies. Instances are typically created via the nested
 * {@link Builder} and passed to the {@link
 * SplitFileFetcherStorage#SplitFileFetcherStorage(SplitFileFetcherStorageInitParams)} constructor.
 *
 * <p>Thread-safety: {@code SplitFileFetcherStorageInitParams} is a simple data container; callers
 * should publish it to a single thread and avoid mutation once built.
 *
 * @hidden
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
   * Fluent builder for {@link SplitFileFetcherStorageInitParams}.
   *
   * <p>The builder performs no I/O and minimal validation. Typical usage sets the metadata,
   * callback, decompression pipeline, factories, and execution helpers, then calls {@link #build()}
   * to obtain an immutable {@link SplitFileFetcherStorageInitParams} snapshot.
   *
   * <p>Unless otherwise stated, all values are required. Optional values follow sensible defaults
   * inside the storage constructor when omitted.
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
     * Set the parsed splitfile {@link Metadata} required to plan the fetch.
     *
     * @param v metadata describing segments, blocks, and algorithms; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder metadata(Metadata v) {
      this.metadata = v;
      return this;
    }

    /**
     * Set the fetcher callback that receives progress and completion events.
     *
     * @param v callback implementation used for notifications; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder fetcher(SplitFileFetcherStorageCallback v) {
      this.fetcher = v;
      return this;
    }

    /**
     * Configure the decompressor pipeline to apply after block decode.
     *
     * @param v ordered list of compressor types; empty or singleton in most deployments.
     * @return this builder for fluent chaining.
     */
    public Builder decompressors(List<COMPRESSOR_TYPE> v) {
      this.decompressors = v;
      return this;
    }

    /**
     * Supply optional client metadata to attach to the completed object.
     *
     * @param v metadata such as MIME type and filename; may be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder clientMetadata(ClientMetadata v) {
      this.clientMetadata = v;
      return this;
    }

    /**
     * Set whether the top-level container should avoid compression.
     *
     * @param v when {@code true}, skip attempting compression at the top level.
     * @return this builder for fluent chaining.
     */
    public Builder topDontCompress(boolean v) {
      this.topDontCompress = v;
      return this;
    }

    /**
     * Specify the minimum compatibility mode expected by the consumer.
     *
     * @param v numeric mode constant; affects padding and related behaviours.
     * @return this builder for fluent chaining.
     */
    public Builder topCompatibilityMode(short v) {
      this.topCompatibilityMode = v;
      return this;
    }

    /**
     * Provide the fetch context carrying retry and cooldown policy.
     *
     * @param v context with limits, timeouts, and priorities; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder fetchContext(FetchContext v) {
      this.origFetchContext = v;
      return this;
    }

    /**
     * Indicate whether the fetch should prefer reduced buffering (real-time).
     *
     * @param v when {@code true}, configure for lower latency over throughput.
     * @return this builder for fluent chaining.
     */
    public Builder realTime(boolean v) {
      this.realTime = v;
      return this;
    }

    /**
     * Set the key salter used when deriving salted keys for requests.
     *
     * @param v optional salter strategy; may be {@code null} to disable salting.
     * @return this builder for fluent chaining.
     */
    public Builder salt(KeySalter v) {
      this.salt = v;
      return this;
    }

    /**
     * Set the primary request URI associated with this fetch.
     *
     * @param v the URI for the current object; used for logging and provenance.
     * @return this builder for fluent chaining.
     */
    public Builder thisKey(FreenetURI v) {
      this.thisKey = v;
      return this;
    }

    /**
     * Optionally record the original user-facing URI if different from {@link #thisKey}.
     *
     * @param v the original or canonical URI; may be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder origKey(FreenetURI v) {
      this.origKey = v;
      return this;
    }

    /**
     * Indicate whether this fetch corresponds to the final content rather than metadata.
     *
     * @param v set {@code true} when fetching the actual payload, not intermediate data.
     * @return this builder for fluent chaining.
     */
    public Builder isFinalFetch(boolean v) {
      this.isFinalFetch = v;
      return this;
    }

    /**
     * Attach opaque client details preserved for callbacks and auditing.
     *
     * @param v optional byte array copied/stored as provided; may be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder clientDetails(byte[] v) {
      this.clientDetails = v;
      return this;
    }

    /**
     * Provide the source of randomness used for key scheduling and shuffling.
     *
     * @param v randomness provider; must not be {@code null} in production use.
     * @return this builder for fluent chaining.
     */
    public Builder random(RandomSource v) {
      this.random = v;
      return this;
    }

    /**
     * Set the temporary bucket factory used to stage metadata before persistence.
     *
     * @param v factory for transient buffers; required when {@code persistent} is enabled.
     * @return this builder for fluent chaining.
     */
    public Builder tempBucketFactory(BucketFactory v) {
      this.tempBucketFactory = v;
      return this;
    }

    /**
     * Configure the random-access buffer factory that creates the backing store.
     *
     * @param v factory responsible for persistent RAF creation; must be compatible with the chosen
     *     storage file.
     * @return this builder for fluent chaining.
     */
    public Builder rafFactory(LockableRandomAccessBufferFactory v) {
      this.rafFactory = v;
      return this;
    }

    /**
     * Provide the job runner used for off-thread work and callbacks.
     *
     * @param v persistent job runner implementation; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder exec(PersistentJobRunner v) {
      this.exec = v;
      return this;
    }

    /**
     * Set the time source/scheduler used for delayed tasks and de-duplication.
     *
     * @param v ticker implementation; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder ticker(Ticker v) {
      this.ticker = v;
      return this;
    }

    /**
     * Provide the memory-limited job runner used for heavy decode/encode work.
     *
     * @param v job runner aware of memory caps; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder memoryLimitedJobRunner(MemoryLimitedJobRunner v) {
      this.memoryLimitedJobRunner = v;
      return this;
    }

    /**
     * Choose the checksum implementation and length used in persisted sections.
     *
     * @param v checker implementation which also provides the checksum length.
     * @return this builder for fluent chaining.
     */
    public Builder checker(ChecksumChecker v) {
      this.checker = v;
      return this;
    }

    /**
     * Enable or disable persistence of metadata and progress across restarts.
     *
     * @param v set {@code true} to persist enough state for resumption after a restart.
     * @return this builder for fluent chaining.
     */
    public Builder persistent(boolean v) {
      this.persistent = v;
      return this;
    }

    /**
     * Provide an explicit file for the backing store when truncation is desired.
     *
     * @param v target file path; when set, completion may use truncation optimisation.
     * @return this builder for fluent chaining.
     */
    public Builder storageFile(File v) {
      this.storageFile = v;
      return this;
    }

    /**
     * Configure a disk-space checking RAF factory for safer persistent allocations.
     *
     * @param v RAF factory that validates available space; optional but recommended.
     * @return this builder for fluent chaining.
     */
    public Builder diskSpaceCheckingRAFFactory(FileRandomAccessBufferFactory v) {
      this.diskSpaceCheckingRAFFactory = v;
      return this;
    }

    /**
     * Set the key-tracking helper that marks keys as fetching locally.
     *
     * @param v helper for cross-component key accounting; may be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder keysFetching(KeysFetchingLocally v) {
      this.keysFetching = v;
      return this;
    }

    /**
     * Build an immutable snapshot of the current builder state.
     *
     * @return a fully-populated {@link SplitFileFetcherStorageInitParams} ready for storage
     *     construction.
     */
    public SplitFileFetcherStorageInitParams build() {
      SplitFileFetcherStorageInitParams p = new SplitFileFetcherStorageInitParams();
      p.metadata = metadata;
      p.fetcher = fetcher;
      p.decompressors = decompressors;
      p.clientMetadata = clientMetadata;
      p.topDontCompress = topDontCompress;
      p.topCompatibilityMode = topCompatibilityMode;
      p.origFetchContext = origFetchContext;
      p.realTime = realTime;
      p.salt = salt;
      p.thisKey = thisKey;
      p.origKey = origKey;
      p.isFinalFetch = isFinalFetch;
      p.clientDetails = clientDetails;
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
}
