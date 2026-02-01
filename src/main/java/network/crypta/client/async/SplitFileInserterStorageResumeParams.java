package network.crypta.client.async;

import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;

/**
 * Holds inputs needed to resume a persistent splitfile insert storage session.
 *
 * <p>This parameter holder captures the persistent buffers, runtime helpers, and key material
 * required to restore state from disk. Values are stored as provided with no validation or
 * defensive copying.
 *
 * @see SplitFileInserterStorage
 * @see SplitFileInserterStorageRuntimeParams
 */
public final class SplitFileInserterStorageResumeParams {
  LockableRandomAccessBuffer raf;
  LockableRandomAccessBuffer originalData;
  SplitFileInserterStorageRuntimeParams runtime;
  FilenameGenerator persistentFG;
  PersistentFileTracker persistentFileTracker;
  MasterSecret masterKey;

  private SplitFileInserterStorageResumeParams() {}

  /**
   * Fluent builder for {@link SplitFileInserterStorageResumeParams}.
   *
   * <p>The builder stores references as-is and performs no validation.
   */
  public static final class Builder {
    private LockableRandomAccessBuffer raf;
    private LockableRandomAccessBuffer originalData;
    private SplitFileInserterStorageRuntimeParams runtime;
    private FilenameGenerator persistentFG;
    private PersistentFileTracker persistentFileTracker;
    private MasterSecret masterKey;

    /**
     * Sets the random-access buffer holding persisted storage.
     *
     * @param v RAF instance
     * @return this builder for chaining
     */
    public Builder raf(LockableRandomAccessBuffer v) {
      this.raf = v;
      return this;
    }

    /**
     * Sets the original data buffer associated with the insert.
     *
     * @param v original data buffer
     * @return this builder for chaining
     */
    public Builder originalData(LockableRandomAccessBuffer v) {
      this.originalData = v;
      return this;
    }

    /**
     * Sets runtime collaborators for storage resume.
     *
     * @param v runtime parameter group
     * @return this builder for chaining
     */
    public Builder runtime(SplitFileInserterStorageRuntimeParams v) {
      this.runtime = v;
      return this;
    }

    /**
     * Sets the filename generator used to restore temporary files.
     *
     * @param v filename generator
     * @return this builder for chaining
     */
    public Builder persistentFG(FilenameGenerator v) {
      this.persistentFG = v;
      return this;
    }

    /**
     * Sets the persistent file tracker used during restore.
     *
     * @param v persistent file tracker
     * @return this builder for chaining
     */
    public Builder persistentFileTracker(PersistentFileTracker v) {
      this.persistentFileTracker = v;
      return this;
    }

    /**
     * Sets the master secret used to decrypt stored sections.
     *
     * @param v master secret
     * @return this builder for chaining
     */
    public Builder masterKey(MasterSecret v) {
      this.masterKey = v;
      return this;
    }

    /**
     * Builds a {@link SplitFileInserterStorageResumeParams} snapshot.
     *
     * @return new parameter snapshot
     */
    public SplitFileInserterStorageResumeParams build() {
      SplitFileInserterStorageResumeParams p = new SplitFileInserterStorageResumeParams();
      p.raf = raf;
      p.originalData = originalData;
      p.runtime = runtime;
      p.persistentFG = persistentFG;
      p.persistentFileTracker = persistentFileTracker;
      p.masterKey = masterKey;
      return p;
    }
  }
}
