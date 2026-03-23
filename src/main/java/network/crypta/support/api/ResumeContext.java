package network.crypta.support.api;

import java.util.Random;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.PersistentFilenameGenerator;

/**
 * Narrow runtime view used to reconnect persisted bucket and buffer state after restart.
 *
 * <p>This interface exists for persistence-oriented components such as buckets, random-access
 * buffers, and other non-crypto persistence helpers that must rebuild the transient runtime state
 * after deserialization or checkpoint restore. Callers use it from {@code onResume(...)} paths to
 * reacquire only the collaborators that remain meaningful across restarts. That keeps these
 * storage-layer types from depending directly on the larger client runtime surface.
 *
 * <p>The contract is intentionally small. Implementations should expose stable persistence helpers
 * only and avoid widening this type into a general execution context. Consumers should treat the
 * returned objects as process-local resume aids, not as permission to reach into unrelated client
 * behavior. Crypto-specific resume state belongs on a narrower extension, so this support-layer API
 * stays free of direct crypto coupling.
 */
public interface ResumeContext {

  /**
   * Returns a fast, weak pseudo-random generator for non-cryptographic resume bookkeeping.
   *
   * <p>This generator is intended for tasks such as regenerating padding bytes or other
   * non-security-critical resume state that must be rebuilt after deserialization. Implementations
   * may share a process-local instance across multiple resumed objects, so callers must not assume
   * exclusive ownership or cryptographic strength.
   *
   * @return a process-local weak PRNG suitable for deterministic-looking resume bookkeeping
   */
  Random fastWeakRandom();

  /**
   * Returns the persistent filename contract for persistent artifacts.
   *
   * <p>Resumed file-backed components use this contract to recover or allocate the stable file
   * paths associated with persistent temporary storage. The implementation should reflect the
   * persistent storage namespace for the current process, not any transient scratch area.
   *
   * @return the persistent filename resolver used for resumed state
   */
  PersistentFilenameGenerator getPersistentFilenameGenerator();

  /**
   * Returns the tracker responsible for persistent temporary files.
   *
   * <p>The tracker coordinates ownership, delayed frees, and other lifecycle work for persistent
   * files that survive across restarts. Resumed objects use it to reconnect cleanup and accounting
   * behavior without knowing about the rest of the client runtime.
   *
   * @return the persistent file tracker used for resumed file lifecycle management
   */
  PersistentFileTracker getPersistentFileTracker();
}
