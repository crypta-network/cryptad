package network.crypta.crypt;

import java.io.Serial;

/**
 * A simple, non-cryptographic pseudo-random source intended for tests and simulations.
 *
 * <p>This implementation extends {@link RandomSource} but deliberately ignores all external entropy
 * inputs. Methods that accept entropy return {@code 0} to indicate that no entropy was
 * incorporated. Randomness derives only from the internal deterministic state (seeded via the
 * constructor or {@link #setSeed(long)} inherited from {@link RandomSource}).
 *
 * <p><strong>Security note:</strong> This class is not suitable for cryptographic purposes such as
 * key generation, nonce creation, or any operation requiring unpredictability. Use a proper
 * cryptographic RNG for security-sensitive tasks.
 *
 * <p>Thread-safety and other behavioral guarantees follow the contract of {@link RandomSource}.
 *
 * @author amphibian
 */
public class DummyRandomSource extends RandomSource {
  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an unseeded instance. The actual initial state follows the semantics of the inherited
   * random source.
   */
  public DummyRandomSource() {}

  /**
   * Creates an instance seeded with the given value.
   *
   * @param seed initial seed used to set the internal deterministic state.
   */
  public DummyRandomSource(long seed) {
    setSeed(seed);
  }

  /**
   * Accepts caller-provided entropy but discards it.
   *
   * <p>This dummy implementation does not mix in any external data and always reports that no
   * entropy was used.
   *
   * @param source logical source of the entropy data.
   * @param data entropy payload supplied by the caller.
   * @param entropyGuess caller's estimate of the entropy carried by {@code data}.
   * @return always {@code 0} to indicate that no entropy was incorporated.
   */
  @Override
  public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
    return 0;
  }

  /**
   * Accepts timer-derived entropy but discards it.
   *
   * @param timer logical timer source.
   * @return always {@code 0} to indicate that no entropy was incorporated.
   */
  @Override
  public int acceptTimerEntropy(EntropySource timer) {
    return 0;
  }

  /**
   * Accepts timer-derived entropy with a bias hint but discards it.
   *
   * <p>The {@code bias} parameter may be used by real implementations as a relative weighting hint.
   * This dummy implementation ignores it.
   *
   * @param fnpTimingSource logical timer source.
   * @param bias optional weighting hint for the provided timing data.
   * @return always {@code 0} to indicate that no entropy was incorporated.
   */
  @Override
  public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
    return 0;
  }

  /**
   * Accepts byte-based entropy but discards it.
   *
   * <p>The buffer region is defined by {@code offset} and {@code length}. A real implementation
   * might read from {@code buf[offset..offset+length-1]}. This dummy implementation does not read
   * or retain any data from the buffer and reports that no entropy was used.
   *
   * @param myPacketDataSource logical source of the byte data.
   * @param buf input buffer that would contain entropy data.
   * @param offset start position within {@code buf}.
   * @param length number of bytes available from {@code buf} starting at {@code offset}.
   * @param bias optional weighting hint for the provided data.
   * @return always {@code 0} to indicate that no entropy was incorporated.
   */
  @Override
  public int acceptEntropyBytes(
      EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
    return 0;
  }

  /**
   * Closes this source.
   *
   * <p>This method is a no-op because the implementation holds only in-memory state and does not
   * acquire external resources.
   */
  @Override
  public void close() {
    // No resources to release.
  }
}
