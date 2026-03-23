package network.crypta.crypt;

import java.io.File;

/**
 * Persists and restores PRNG seed material across process lifecycles.
 *
 * <p>Implementations of this interface extend {@link RandomSource} with two complementary
 * capabilities:
 *
 * <ul>
 *   <li>{@link #writeSeed(boolean)} — Persist internal state to a configured seed file so future
 *       instances can bootstrap with additional entropy. Implementations may rate-limit writes when
 *       {@code force} is {@code false}.
 *   <li>{@link #readSeed(File)} — Read previously persisted seed data from the specified file and
 *       mix it into the generator state.
 * </ul>
 *
 * <p>Persisting seed material helps retain entropy across node restarts, which is useful on systems
 * with limited environmental entropy (for example, when {@code /dev/random} is slow to initialize).
 *
 * <p>Thread-safety is implementation-defined. Callers should assume no additional guarantees beyond
 * those documented by the concrete implementation.
 */
public interface PersistentRandomSource {

  /**
   * Persists seed material for later reuse by future process instances.
   *
   * <p>When {@code force} is {@code false}, implementations may skip the operation based on their
   * own heuristics (for example, to avoid writing too frequently). When {@code force} is {@code
   * true}, implementations should perform the write regardless of recent activity.
   *
   * <p>The destination (for example, a configured seed file) is implementation-defined.
   *
   * @param force request that the write bypass any rate-limiting or freshness checks.
   */
  void writeSeed(boolean force);

  /**
   * Reads previously persisted seed data and mixes it into the generator state.
   *
   * <p>Implementations should treat missing or unreadable files as non-fatal and return normally.
   * Logging the condition is acceptable.
   *
   * @param file seed file to read; must not be {@code null}.
   */
  void readSeed(File file);
}
