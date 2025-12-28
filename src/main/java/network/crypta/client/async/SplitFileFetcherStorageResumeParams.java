package network.crypta.client.async;

import network.crypta.client.FetchContext;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.RandomSource;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.Ticker;
import network.crypta.support.api.LockableRandomAccessBuffer;

/**
 * Parameters needed to resume a previously persisted fetch session.
 *
 * <p>When storage was created in persistent mode, a restart rebuilds its in-memory state by reading
 * and validating checksummed sections from the backing random access buffer. This holder conveys
 * the environment required to do so, including the buffer itself, scheduling helpers and checksum
 * implementation.
 *
 * <p>Unlike {@link SplitFileFetcherStorageInitParams}, these values are derived from the on-disk
 * format rather than the metadata that initiated the fetch. Use the nested {@link Builder} to
 * construct an instance suitable for {@link
 * SplitFileFetcherStorage#SplitFileFetcherStorage(SplitFileFetcherStorageResumeParams)}.
 *
 * @hidden
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
   * <p>Callers provide the buffer to read from, runtime services (job/ticker), and flags indicating
   * whether a new salt should be injected. The resulting {@link
   * SplitFileFetcherStorageResumeParams} is consumed by the resuming constructor.
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
     * Set the random-access buffer to resume from.
     *
     * @param v buffer positioned at the previously persisted storage file.
     * @return this builder for fluent chaining.
     */
    public Builder raf(LockableRandomAccessBuffer v) {
      this.raf = v;
      return this;
    }

    /**
     * Configure whether resume should prefer real-time behavior.
     *
     * @param v when {@code true}, optimizes for latency over throughput.
     * @return this builder for fluent chaining.
     */
    public Builder realTime(boolean v) {
      this.realTime = v;
      return this;
    }

    /**
     * Set the callback used for notifications during the resumed session.
     *
     * @param v callback implementation; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder callback(SplitFileFetcherStorageCallback v) {
      this.callback = v;
      return this;
    }

    /**
     * Provide the original fetch context to reapply scheduling policy.
     *
     * @param v fetch context used to derive retries and cooldown; non-null.
     * @return this builder for fluent chaining.
     */
    public Builder context(FetchContext v) {
      this.origContext = v;
      return this;
    }

    /**
     * Provide the randomness source used by resumed operations.
     *
     * @param v randomness provider; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder random(RandomSource v) {
      this.random = v;
      return this;
    }

    /**
     * Set the job runner handling off-thread activity.
     *
     * @param v job runner for background tasks; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder exec(PersistentJobRunner v) {
      this.exec = v;
      return this;
    }

    /**
     * Provide the helper used to mark keys as fetching locally.
     *
     * @param v optional accounting helper.
     * @return this builder for fluent chaining.
     */
    public Builder keysFetching(KeysFetchingLocally v) {
      this.keysFetching = v;
      return this;
    }

    /**
     * Set the ticker used for timed operations and coalescing.
     *
     * @param v ticker/scheduler implementation; non-null.
     * @return this builder for fluent chaining.
     */
    public Builder ticker(Ticker v) {
      this.ticker = v;
      return this;
    }

    /**
     * Provide the memory-limited job runner for heavy tasks.
     *
     * @param v job runner respecting memory caps; must not be {@code null}.
     * @return this builder for fluent chaining.
     */
    public Builder memoryLimitedJobRunner(MemoryLimitedJobRunner v) {
      this.memoryLimitedJobRunner = v;
      return this;
    }

    /**
     * Set the checksum implementation and length for persisted sections.
     *
     * @param v checker implementation; non-null.
     * @return this builder for fluent chaining.
     */
    public Builder checker(ChecksumChecker v) {
      this.checker = v;
      return this;
    }

    /**
     * Whether to inject a new salt when resuming, if supported.
     *
     * @param v set {@code true} to prefer re-salting.
     * @return this builder for fluent chaining.
     */
    public Builder newSalt(boolean v) {
      this.newSalt = v;
      return this;
    }

    /**
     * Provide the salter to use if {@link #newSalt(boolean)} is {@code true}.
     *
     * @param v salter implementation; may be {@code null} to disable.
     * @return this builder for fluent chaining.
     */
    public Builder salt(KeySalter v) {
      this.salt = v;
      return this;
    }

    /**
     * Mark that this session represents a true resume rather than a fresh start.
     *
     * @param v set {@code true} when resuming from persisted state.
     * @return this builder for fluent chaining.
     */
    public Builder resumed(boolean v) {
      this.resumed = v;
      return this;
    }

    /**
     * Enable completion via truncation when possible.
     *
     * @param v when {@code true}, prefer truncation optimization at completion.
     * @return this builder for fluent chaining.
     */
    public Builder completeViaTruncation(boolean v) {
      this.completeViaTruncation = v;
      return this;
    }

    /**
     * Build a {@link SplitFileFetcherStorageResumeParams} snapshot for resuming from disk.
     *
     * @return the constructed parameters object consumed by the resuming constructor.
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
