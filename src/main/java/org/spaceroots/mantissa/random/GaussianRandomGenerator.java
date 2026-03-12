package org.spaceroots.mantissa.random;

import java.io.Serial;

/**
 * Generates scalar values distributed as a standard (mean&nbsp;0, variance&nbsp;1) Gaussian.
 *
 * <p>This class is a lightweight adapter that exposes the {@link NormalizedRandomGenerator}
 * interface on top of a {@link MersenneTwister} pseudo‑random number generator. Each call to {@link
 * #nextDouble()} returns the next value from {@link java.util.Random#nextGaussian()}, computed by
 * the underlying Mersenne Twister instance. The resulting sequence is fully deterministic for a
 * given seed, and two instances created with the same seed will produce identical sequences.
 *
 * <p>The generator is stateful and advances its internal state on every call. It is not designed
 * for concurrent use without external synchronization; sharing a single instance across threads may
 * lead to interleaved sequences. If you need independent streams, create separate instances with
 * distinct seeds.
 *
 * <p>Typical usage is to construct a seeded generator during test setup or simulation
 * initialization and then call {@link #nextDouble()} whenever a standard normal deviate is
 * required.
 *
 * <ul>
 *   <li><strong>Distribution:</strong> Standard normal, as defined by {@code
 *       Random.nextGaussian()}.
 *   <li><strong>Determinism:</strong> Fully determined by the supplied seed.
 *   <li><strong>State:</strong> Advances on each generated value.
 * </ul>
 *
 * <pre>{@code
 * GaussianRandomGenerator gen = new GaussianRandomGenerator(1234);
 * double noise = gen.nextDouble();
 * }</pre>
 *
 * @see MersenneTwister
 * @version $Id: GaussianRandomGenerator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class GaussianRandomGenerator implements NormalizedRandomGenerator {

  /**
   * Create a new generator seeded from the current time.
   *
   * <p>This constructor creates a fresh {@link MersenneTwister} instance using its default seeding
   * strategy, which is typically based on the system clock. The produced sequence is therefore
   * different across JVM runs unless the environment or underlying implementation fixes the seed.
   *
   * <p>Use one of the explicit seed constructors when reproducibility is required (for example, in
   * unit tests or deterministic simulations).
   */
  public GaussianRandomGenerator() {
    generator = new MersenneTwister();
  }

  /**
   * Creates a new random number generator using a single int seed.
   *
   * <p>The generated Gaussian sequence is completely determined by {@code seed}. Two generators
   * created with the same integer seed will produce identical values in the same order.
   *
   * @param seed initial 32‑bit seed value controlling the deterministic output sequence
   */
  public GaussianRandomGenerator(int seed) {
    generator = new MersenneTwister(seed);
  }

  /**
   * Creates a new random number generator using an int array seed.
   *
   * <p>The seed array allows finer control over the initial state than a single integer. Providing
   * equal arrays (element‑wise) results in identical output sequences. If {@code seed} is {@code
   * null}, the underlying generator falls back to time‑based seeding.
   *
   * @param seed initial 32‑bit integer array seed; {@code null} uses a time‑derived seed instead
   */
  public GaussianRandomGenerator(int[] seed) {
    generator = new MersenneTwister(seed);
  }

  /**
   * Create a new generator initialized with a single long seed.
   *
   * <p>Long seeds provide a larger initialization space than integer seeds while keeping
   * determinism. Two instances created with the same long seed will return the same sequence of
   * Gaussian values.
   *
   * @param seed initial 64‑bit seed value controlling the deterministic output sequence
   */
  public GaussianRandomGenerator(long seed) {
    generator = new MersenneTwister(seed);
  }

  /**
   * Generate a random scalar with null mean and unit standard deviation.
   *
   * <p>This method delegates directly to the underlying {@link MersenneTwister}'s {@link
   * java.util.Random#nextGaussian()} implementation. Each invocation advances the internal state
   * and returns the next value in the standard normal sequence.
   *
   * <p>The return value is typically unbounded in range (as with any Gaussian distribution). The
   * sequence is deterministic with respect to the constructor seed and the number of prior calls.
   *
   * @return next pseudo‑random value from a standard normal distribution (mean&nbsp;0, standard
   *     deviation&nbsp;1)
   */
  @Override
  public double nextDouble() {
    return generator.nextGaussian();
  }

  /**
   * Underlying pseudo‑random generator used to produce Gaussian deviates.
   *
   * <p>This field is package‑private to allow collaboration with other Mantissa random utilities.
   * It is stateful and mutated on each call to {@link #nextDouble()}.
   */
  MersenneTwister generator;

  @Serial private static final long serialVersionUID = 5504568059866195697L;
}
