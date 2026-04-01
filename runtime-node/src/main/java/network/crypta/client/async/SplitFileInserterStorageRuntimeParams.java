package network.crypta.client.async;

import java.util.Random;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.Ticker;

/**
 * Bundles runtime collaborators required by splitfile insert storage.
 *
 * <p>This parameter holder captures the callback and runtime helpers used by {@link
 * SplitFileInserterStorage} during initialization or resume. Values are stored as provided with no
 * validation or defensive copying.
 *
 * @see SplitFileInserterStorageInitParams
 * @see SplitFileInserterStorageResumeParams
 */
public final class SplitFileInserterStorageRuntimeParams {
  SplitFileInserterStorageCallback callback;
  Random random;
  MemoryLimitedJobRunner memoryLimitedJobRunner;
  PersistentJobRunner jobRunner;
  Ticker ticker;
  KeysFetchingLocally keysFetching;

  private SplitFileInserterStorageRuntimeParams() {}

  /**
   * Fluent builder for {@link SplitFileInserterStorageRuntimeParams}.
   *
   * <p>The builder stores references as-is and performs no validation.
   */
  public static final class Builder {
    private SplitFileInserterStorageCallback callback;
    private Random random;
    private MemoryLimitedJobRunner memoryLimitedJobRunner;
    private PersistentJobRunner jobRunner;
    private Ticker ticker;
    private KeysFetchingLocally keysFetching;

    /**
     * Sets the callback receiving progress and completion events.
     *
     * @param v callback instance; may be {@code null} if the caller tolerates it
     * @return this builder for chaining
     */
    public Builder callback(SplitFileInserterStorageCallback v) {
      this.callback = v;
      return this;
    }

    /**
     * Sets the random source used for allocation and retry decisions.
     *
     * @param v random source reference
     * @return this builder for chaining
     */
    public Builder random(Random v) {
      this.random = v;
      return this;
    }

    /**
     * Sets the memory-limited job runner used for encoding work.
     *
     * @param v memory-limited job runner
     * @return this builder for chaining
     */
    public Builder memoryLimitedJobRunner(MemoryLimitedJobRunner v) {
      this.memoryLimitedJobRunner = v;
      return this;
    }

    /**
     * Sets the persistent job runner for background tasks.
     *
     * @param v job runner for persistence-aware work
     * @return this builder for chaining
     */
    public Builder jobRunner(PersistentJobRunner v) {
      this.jobRunner = v;
      return this;
    }

    /**
     * Sets the ticker used for timed callbacks.
     *
     * @param v ticker instance
     * @return this builder for chaining
     */
    public Builder ticker(Ticker v) {
      this.ticker = v;
      return this;
    }

    /**
     * Sets the helper used to query local key fetch state.
     *
     * @param v local key fetch tracker
     * @return this builder for chaining
     */
    public Builder keysFetching(KeysFetchingLocally v) {
      this.keysFetching = v;
      return this;
    }

    /**
     * Builds a {@link SplitFileInserterStorageRuntimeParams} snapshot.
     *
     * @return new parameter snapshot
     */
    public SplitFileInserterStorageRuntimeParams build() {
      SplitFileInserterStorageRuntimeParams p = new SplitFileInserterStorageRuntimeParams();
      p.callback = callback;
      p.random = random;
      p.memoryLimitedJobRunner = memoryLimitedJobRunner;
      p.jobRunner = jobRunner;
      p.ticker = ticker;
      p.keysFetching = keysFetching;
      return p;
    }
  }
}
