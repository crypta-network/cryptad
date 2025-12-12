package org.spaceroots.mantissa.random;

import java.io.Serial;
import java.util.Random;

/**
 * Pseudo-random number generator using the four-tap GFSR scheme defined by Robert M. Ziff.
 *
 * <p>The generator keeps a circular buffer of 16,384 32-bit values and combines four widely spaced
 * taps with XOR to produce the next state. The configuration corresponds to generator {@code R(471,
 * 1586, 6988, 9689)} in Ziff's 1997 paper <a href="http://arxiv.org/abs/cond-mat/9710104">Four-tap
 * shift-register-sequence random-number generators</a>. Extending {@link Random} makes it a drop-in
 * replacement for code that already expects the JDK API while providing higher-quality sequences
 * for Monte-Carlo style workloads.
 *
 * <p>Typical usage mirrors {@link Random}: build an instance, optionally provide a fixed seed for
 * reproducibility, then call generation methods such as {@link #nextInt()}, {@link #nextDouble()}
 * or {@link #nextLong()}. The buffer is repopulated during construction or {@link #setSeed(long)}
 * and advances on every call to {@link #next(int)}, which all public generation methods delegate
 * to.
 *
 * <p>The class is mutable and not inherently thread-safe, matching {@link Random}. External
 * synchronization is required when sharing an instance across threads; {@link #setSeed(long)} is
 * synchronized to mirror {@link Random#setSeed(long)} and avoid races during reinitialization.
 *
 * <ul>
 *   <li>State size: 16,384 integers forming a ring buffer of previous outputs.
 *   <li>Determinism: identical seeds yield identical sequences across JVMs that preserve {@link
 *       Random} bit semantics.
 *   <li>Compatibility: fully honors the {@link Random} contract for all public generation methods.
 * </ul>
 *
 * @author Bill Maier (java.util.Random specialization by Luc Maisonobe)
 * @version $Id: FourTapRandom.java 1666 2005-12-15 16:37:55Z luc $
 * @see Random
 */
public class FourTapRandom extends Random {

  /**
   * Builds a generator seeded from the current system clock to provide a fresh, unpredictable
   * sequence.
   *
   * <p>The constructor allocates the internal ring buffer immediately and forwards to {@link
   * #setSeed(long)} to populate it with 32-bit values derived from the seed. Because the seed comes
   * from {@link System#currentTimeMillis()}, two instances created in rapid succession may still
   * diverge if the clock ticks; use {@link #FourTapRandom(long)} for reproducible runs. The
   * resulting instance follows all {@link Random} semantics and can be used with any API that
   * expects a standard random generator.
   */
  public FourTapRandom() {
    setSeed(System.currentTimeMillis());
  }

  /**
   * Builds a generator with a user-supplied seed for reproducible sequences.
   *
   * <p>Supplying the seed allows callers to generate deterministic series across JVM executions,
   * which is often desirable in simulations and tests. Construction eagerly fills the internal
   * buffer so the instance is ready for immediate use. The seed value is passed verbatim to {@link
   * #setSeed(long)}, which mirrors {@link Random#setSeed(long)} semantics and resets any prior
   * state. As with {@link Random}, callers should externally synchronize when sharing the same
   * generator instance between threads.
   *
   * @param seed initial 64-bit value used to derive the internal 32-bit buffer contents; identical
   *     seeds always reproduce identical sequences.
   */
  public FourTapRandom(long seed) {
    setSeed(seed);
  }

  /**
   * Reinitializes the generator as if newly constructed with the specified seed.
   *
   * <p>This synchronized method matches the thread-safety contract of {@link Random#setSeed(long)}
   * and completely resets the internal ring buffer and index. It first seeds the superclass, then
   * fills all 16,384 buffer slots by delegating to {@link Random#next(int)} to preserve consistency
   * with {@link Random} bit production. After completion, the next generated value will be
   * identical to that of a freshly created {@link FourTapRandom} with the same seed, ensuring
   * reproducible replay of sequences even after previous usage.
   *
   * @param seed 64-bit value used to regenerate the buffer; any {@code long} is accepted and equal
   *     seeds guarantee identical subsequent outputs.
   */
  @Override
  public synchronized void setSeed(long seed) {
    super.setSeed(seed);
    fourTapBuffer = new int[TAP4M + 1];
    for (int j = 0; j <= TAP4M; j++) {
      fourTapBuffer[j] = super.next(32);
    }
    n4TapJ = 0;
  }

  /**
   * Produces the requested number of pseudo-random high-order bits from the current generator
   * state.
   *
   * <p>This is the core algorithm used by all {@link Random} convenience methods. Each call
   * advances the circular buffer index, computes a new 32-bit value by XOR-ing four distant taps,
   * stores it back into the buffer, and returns the upper {@code bits} of that value. Calling this
   * method with the same prior state and bit count always yields identical results, making it
   * suitable as a deterministic foundation for higher-level generators. The expected {@code bits}
   * range is between 1 and 32 inclusive; larger values would shift the value into zero.
   *
   * @param bits number of leading bits to return; typically 1–32, where larger values provide more
   *     entropy but still derive from the same 32-bit buffer entry.
   * @return non-negative integer containing exactly the requested number of high-order bits of the
   *     freshly generated 32-bit word; lower bits are zeroed by the unsigned shift.
   */
  @Override
  protected int next(int bits) {
    ++n4TapJ;
    fourTapBuffer[n4TapJ & TAP4M] =
        fourTapBuffer[(n4TapJ - TAP4A) & TAP4M]
            ^ fourTapBuffer[(n4TapJ - TAP4B) & TAP4M]
            ^ fourTapBuffer[(n4TapJ - TAP4C) & TAP4M]
            ^ fourTapBuffer[(n4TapJ - TAP4D) & TAP4M];
    return fourTapBuffer[n4TapJ & TAP4M] >>> (32 - bits);
  }

  private static final int TAP4A = 471;
  private static final int TAP4B = 1586;
  private static final int TAP4C = 6988;
  private static final int TAP4D = 9689;
  private static final int TAP4M = 16383;

  /** Ring buffer that stores the last 16,384 generated 32-bit values for tap-based recurrence. */
  private int[] fourTapBuffer;

  /** Current write index into {@link #fourTapBuffer}, incremented once per {@link #next(int)}. */
  private int n4TapJ;

  /**
   * Serialization identifier to preserve compatibility with previously persisted generator states.
   */
  @Serial private static final long serialVersionUID = -4095251494398895580L;
}
