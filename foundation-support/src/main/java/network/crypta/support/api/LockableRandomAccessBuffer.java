package network.crypta.support.api;

import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.support.io.ResumeFailedException;

/**
 * Random-access buffer with a lightweight "keep-open" lock and persistence support.
 *
 * <p>This API extends {@link RandomAccessBuffer} with the ability to temporarily mark the
 * underlying resource (typically a pooled file descriptor) as in-use so that pooling layers do not
 * close it while callers are actively working with it. The lock is cooperative and does not provide
 * mutual exclusion: other readers/writers may still access the buffer concurrently. It is the
 * responsibility of the implementation to behave correctly under concurrency, either by serializing
 * access (e.g., via a mutex) or by providing a truly concurrent backing store.
 *
 * <p>Implementations may also persist enough information to later reconstruct an equivalent buffer
 * via {@link #storeTo(DataOutputStream)} and restore it using {@code
 * BucketTools.restoreRAFFrom(...)}.
 *
 * <p><strong>Concurrency and blocking:</strong> acquiring a lock with {@link #lockOpen()} may block
 * until a slot becomes available. Misuse (for example, locking multiple buffers in different orders
 * across threads) can cause deadlocks; callers should keep lock lifetimes short and release them
 * promptly.
 *
 * @author toad
 */
public interface LockableRandomAccessBuffer extends RandomAccessBuffer {

  /**
   * Acquire a cooperative lock to keep the underlying resource open while in use.
   *
   * <p>The lock does not provide mutual exclusion. Other callers may read or write concurrently,
   * depending on the implementation. The call may block if no lock slots are currently available.
   * Holding multiple locks in different orders can deadlock.
   *
   * @return a token that must be released exactly once via {@link RAFLock#unlock()} when work is
   *     finished; callers should use a {@code try/finally} pattern to guarantee release
   * @throws IOException if the lock cannot be obtained due to I/O or resource limits
   */
  RAFLock lockOpen() throws IOException;

  abstract class RAFLock {

    private boolean locked;

    /**
     * Creates a new lock token in the locked state.
     *
     * <p>Subclasses are constructed by the {@link LockableRandomAccessBuffer} implementation when a
     * lock is acquired. The initial state is locked; the framework guarantees that {@link
     * #innerUnlock()} is invoked at most once per instance.
     */
    protected RAFLock() {
      locked = true;
    }

    /**
     * Releases the lock.
     *
     * <p>After this method returns, the associated buffer may be closed by pooling layers if
     * otherwise eligible. Calling this method more than once throws {@link IllegalStateException}.
     */
    public final void unlock() {
      synchronized (this) {
        if (!locked) throw new IllegalStateException("Already unlocked");
        locked = false;
      }
      innerUnlock();
    }

    /**
     * Implementation hook invoked exactly once when the lock transitions from locked to unlocked.
     *
     * <p>Subclasses should perform any resource-release or accounting needed by the owning buffer.
     * The base class ensures this method is not called again after an unlock.
     */
    protected abstract void innerUnlock();
  }

  /**
   * Callback invoked after the buffer is restored from persistent state.
   *
   * <p>Typical implementations use this to (re)register temporary files or renew memberships in
   * process-local registries.
   *
   * @param context runtime context available during resume
   * @throws ResumeFailedException if the buffer cannot be made ready for use after restoration
   */
  void onResume(ResumeContext context) throws ResumeFailedException;

  /**
   * Writes enough information to reconstruct an equivalent buffer later.
   *
   * <p>The record should be self-identifying and versioned if necessary. Implementations commonly
   * write a fixed, unique integer "magic" followed by any parameters required for reconstruction,
   * and add a corresponding clause to {@code BucketTools.restoreRAFFrom(...)}.
   *
   * @param dos destination stream
   * @throws IOException on write errors
   * @throws UnsupportedOperationException if this buffer type cannot persist itself
   */
  void storeTo(DataOutputStream dos) throws IOException;

  /**
   * Compares this buffer to another for logical equality.
   *
   * <p>Implementations should define equality to reflect whether two instances refer to the same
   * stored content or resource identity, as appropriate for the type. This is used, for example,
   * when resuming a splitfile insert to detect identical underlying storage.
   *
   * @param o the object to compare with
   * @return {@code true} if the objects are equal according to the implementation's definition
   */
  @Override
  boolean equals(Object o);

  /**
   * Returns a hash code consistent with the definition of {@link #equals(Object)}.
   *
   * @return a hash code value
   */
  @Override
  int hashCode();
}
