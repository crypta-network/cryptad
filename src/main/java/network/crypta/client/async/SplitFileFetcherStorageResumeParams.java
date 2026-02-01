package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.RandomSource;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBuffer;

/**
 * Holds runtime services and flags needed to resume a persisted splitfile fetch.
 *
 * <p>This parameter holder is populated during restart when persistent storage must reconstruct
 * in-memory state from a backing random-access buffer and checksummed sections. It captures the
 * runtime environment required by the resume constructor, such as scheduling helpers, randomness,
 * and checksum validation logic, along with flags that influence resume behavior. Unlike {@link
 * SplitFileFetcherStorageInitParams}, these values originate from the on-disk format and the
 * persisted session state rather than the original request metadata.
 *
 * <p>The instance is intentionally lightweight: it stores references as-is, performs no validation,
 * and is intended for single-threaded construction followed by immediate handoff to {@link
 * SplitFileFetcherStorage#SplitFileFetcherStorage(SplitFileFetcherStorageResumeParams)}. Callers
 * are responsible for providing compatible services and honoring nullability contracts expected by
 * the resume path.
 *
 * <ul>
 *   <li>Holds the storage buffer and checksum checker for persisted sections.
 *   <li>Provides schedulers, randomness, and accounting helpers used during resume.
 *   <li>Captures resume flags such as real-time mode, salting, and truncation completion.
 * </ul>
 *
 * @see SplitFileFetcherStorageResumeParams.Builder
 * @see SplitFileFetcherStorageInitParams
 * @see SplitFileFetcherStorage
 */
public final class SplitFileFetcherStorageResumeParams {
  LockableRandomAccessBuffer raf;
  boolean realTime;
  SplitFileFetcherStorageCallback callback;
  FetchContext origContext;
  RandomSource random;
  PersistentJobRunner exec;
  KeysFetchingLocally keysFetching;
  Ticker ticker;
  MemoryLimitedJobRunner memoryLimitedJobRunner;
  ChecksumChecker checker;
  boolean newSalt;
  KeySalter salt;
  boolean resumed;
  boolean completeViaTruncation;

  /**
   * Fluent builder for {@link SplitFileFetcherStorageResumeParams} used when reconstructing state
   * from disk.
   *
   * <p>The builder records the runtime dependencies and flags that the resume constructor expects.
   * Each setter overwrites the previous value and returns the same builder for fluent chaining.
   * Values are captured without validation or defensive copying; the {@link #build()} method
   * transfers references into a new parameters instance. After construction, subsequent changes to
   * the builder do not affect already-built objects.
   *
   * <p>Typical usage is to configure the buffer, schedulers, and checksum implementation based on
   * the persisted state, then pass the resulting snapshot directly to {@link
   * SplitFileFetcherStorage#SplitFileFetcherStorage(SplitFileFetcherStorageResumeParams)}. The
   * builder is mutable and not thread-safe, so configure it on a single thread.
   *
   * <pre>{@code
   * SplitFileFetcherStorageResumeParams params =
   *     new SplitFileFetcherStorageResumeParams.Builder()
   *         .raf(buffer)
   *         .callback(callback)
   *         .ticker(ticker)
   *         .build();
   * }</pre>
   */
  public static class Builder {
    private LockableRandomAccessBuffer raf;
    private boolean realTime;
    private SplitFileFetcherStorageCallback callback;
    private FetchContext origContext;
    private RandomSource random;
    private PersistentJobRunner exec;
    private KeysFetchingLocally keysFetching;
    private Ticker ticker;
    private MemoryLimitedJobRunner memoryLimitedJobRunner;
    private ChecksumChecker checker;
    private boolean newSalt;
    private KeySalter salt;
    private boolean resumed;
    private boolean completeViaTruncation;

    /**
     * Sets the random-access buffer to resume from.
     *
     * <p>This buffer is the backing store that contains the persisted splitfile metadata and
     * checksummed sections. The builder records the reference exactly as provided; it does not
     * validate position, size, or lock state. The last value set wins if invoked multiple times.
     *
     * @param v buffer positioned at the persisted storage file; may be {@code null}.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder raf(LockableRandomAccessBuffer v) {
      this.raf = v;
      return this;
    }

    /**
     * Configures whether resume should prefer real-time behavior.
     *
     * <p>This flag is a hint consumed by the resume logic to prefer lower latency to throughput
     * where applicable. It is stored as-is without validation. Repeated calls replace the previous
     * value; setting the same value again is idempotent.
     *
     * @param v {@code true} to favor latency; {@code false} to favor throughput.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder realTime(boolean v) {
      this.realTime = v;
      return this;
    }

    /**
     * Sets the callback used for notifications during the resumed session.
     *
     * <p>The callback is passed through to the resumed storage so it can emit progress or error
     * notifications. The builder does not enforce non-nullity; the resume constructor may rely on
     * callers to supply a valid implementation. Multiple invocations replace the previous callback.
     *
     * @param v callback implementation; may be {@code null} if the caller tolerates it.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder callback(SplitFileFetcherStorageCallback v) {
      this.callback = v;
      return this;
    }

    /**
     * Provides the original fetch context to reapply scheduling policy.
     *
     * <p>The resume path may consult the original context to restore retry, cooldown, and queueing
     * policies. This builder stores the reference directly and does not clone or sanitize it. The
     * most recently supplied context wins if the method is called multiple times.
     *
     * @param v original fetch context reference; may be {@code null} if unavailable.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder context(FetchContext v) {
      this.origContext = v;
      return this;
    }

    /**
     * Provides the randomness source used by resumed operations.
     *
     * <p>The resume path may rely on this source for randomized scheduling or salting decisions.
     * The builder keeps the reference unchanged and does not enforce non-nullity. Calling this
     * method repeatedly replaces the previous reference.
     *
     * @param v randomness provider reference; may be {@code null} if not available.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder random(RandomSource v) {
      this.random = v;
      return this;
    }

    /**
     * Sets the job runner handling off-thread activity.
     *
     * <p>The resume logic may schedule work through this runner; this builder only stores the
     * provided reference and does not validate its configuration. If invoked more than once, the
     * last supplied runner is retained.
     *
     * @param v job runner for background tasks; may be {@code null} if not used.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder exec(PersistentJobRunner v) {
      this.exec = v;
      return this;
    }

    /**
     * Provides the helper used to mark keys as fetching locally.
     *
     * <p>This helper is optional and may be {@code null} when local key accounting is not desired
     * or when the resume flow does not need to track local fetches. The builder records whatever
     * reference is supplied, with later calls overwriting earlier ones.
     *
     * @param v helper for local fetch accounting; {@code null} disables the helper.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder keysFetching(KeysFetchingLocally v) {
      this.keysFetching = v;
      return this;
    }

    /**
     * Sets the ticker used for timed operations and coalescing.
     *
     * <p>The ticker provides a scheduling and timing facility that the resume path can use for
     * delays or periodic activity. The builder stores the reference as-is and performs no
     * validation or wrapping. As with other setters, the most recent call wins.
     *
     * @param v ticker or scheduler implementation; may be {@code null} if unused.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder ticker(Ticker v) {
      this.ticker = v;
      return this;
    }

    /**
     * Provides the memory-limited job runner for heavy tasks.
     *
     * <p>This runner is used when resume operations should respect memory caps. The builder keeps
     * the supplied reference without validation, and later calls overwrite earlier values. The
     * resume constructor is responsible for handling a {@code null} reference if provided.
     *
     * @param v job runner that enforces memory caps; may be {@code null} if unused.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder memoryLimitedJobRunner(MemoryLimitedJobRunner v) {
      this.memoryLimitedJobRunner = v;
      return this;
    }

    /**
     * Sets the checksum implementation used to validate persisted sections.
     *
     * <p>The resume logic consults this checker when reading checksummed data from the backing
     * buffer. This builder stores the reference exactly as provided and does not validate the
     * checker’s configuration. Multiple calls replace the previous checker reference.
     *
     * @param v checksum checker implementation; may be {@code null} if not required.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder checker(ChecksumChecker v) {
      this.checker = v;
      return this;
    }

    /**
     * Specifies whether to inject a new salt when resuming, if supported.
     *
     * <p>This flag signals a preference for re-salting during resume. It does not itself generate
     * or validate salts, and it has no effect until consumed by the resume constructor. Repeated
     * calls overwrite the previous value, and setting the same value again is idempotent.
     *
     * @param v {@code true} to request re-salting; {@code false} to keep existing salt.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder newSalt(boolean v) {
      this.newSalt = v;
      return this;
    }

    /**
     * Provides the salter to use if {@link #newSalt(boolean)} is {@code true}.
     *
     * <p>The salter reference is recorded without validation. It may be {@code null}, in which case
     * the resume logic can decide to skip salting even if {@code newSalt} is requested. The most
     * recently supplied salter replaces any prior value.
     *
     * @param v salter implementation reference; {@code null} disables salting support.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder salt(KeySalter v) {
      this.salt = v;
      return this;
    }

    /**
     * Marks that this session represents a true resume rather than a fresh start.
     *
     * <p>This flag allows the resume constructor to distinguish between reconstructed state and a
     * newly initialized fetch. The builder records the value directly; repeated calls overwrite the
     * prior value, and setting the same value again is idempotent.
     *
     * @param v {@code true} when resuming persisted state; {@code false} otherwise.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder resumed(boolean v) {
      this.resumed = v;
      return this;
    }

    /**
     * Enables completion via truncation when possible.
     *
     * <p>This flag indicates a preference for truncation-based completion optimizations at the end
     * of the resumed fetch. The builder stores the preference as provided and does not validate
     * compatibility. Later calls overwrite earlier ones.
     *
     * @param v {@code true} to prefer truncation completion; {@code false} to disable it.
     * @return this builder instance for fluent chaining and continued configuration.
     */
    public Builder completeViaTruncation(boolean v) {
      this.completeViaTruncation = v;
      return this;
    }

    /**
     * Builds a {@link SplitFileFetcherStorageResumeParams} snapshot for resuming from disk.
     *
     * <p>The returned instance is a shallow snapshot of the current builder state. References are
     * copied as-is, so mutations to referenced objects are visible to the resume flow. The builder
     * itself remains mutable and can be reused to build additional snapshots with different values.
     * This method performs no validation; callers should ensure required fields are set before
     * invoking the resume constructor.
     *
     * @return a new parameters object reflecting the builder’s current values and flags.
     */
    public SplitFileFetcherStorageResumeParams build() {
      SplitFileFetcherStorageResumeParams p = new SplitFileFetcherStorageResumeParams();
      p.raf = raf;
      p.realTime = realTime;
      p.callback = callback;
      p.origContext = origContext;
      p.random = random;
      p.exec = exec;
      p.keysFetching = keysFetching;
      p.ticker = ticker;
      p.memoryLimitedJobRunner = memoryLimitedJobRunner;
      p.checker = checker;
      p.newSalt = newSalt;
      p.salt = salt;
      p.resumed = resumed;
      p.completeViaTruncation = completeViaTruncation;
      return p;
    }
  }
}
