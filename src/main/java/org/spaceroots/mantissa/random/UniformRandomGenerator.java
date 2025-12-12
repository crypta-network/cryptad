package org.spaceroots.mantissa.random;

import java.io.Serial;

/**
 * Generates standardized scalar samples from a uniform distribution.
 *
 * <p>This generator adapts a uniform {@code [0, 1)} source into a distribution with zero mean and
 * unit standard deviation, suitable for algorithms that expect normalized noise. Each call to
 * {@link #nextDouble()} draws one underlying uniform variate and linearly rescales it to the
 * symmetric interval {@code [-sqrt(3), sqrt(3)]}. With that interval, the resulting distribution
 * has mean {@code 0} and variance {@code 1} by construction.
 *
 * <p>The underlying source of randomness is a {@link MersenneTwister}. Two instances created with
 * the same seed (via any of the seeded constructors) will produce identical sequences. The default
 * constructor seeds from the current time and is therefore not deterministic.
 *
 * <p>Instances are mutable and not synchronized. Like {@link MersenneTwister} (and {@link
 * java.util.Random}), this class is not safe for concurrent use without external synchronization.
 *
 * <ul>
 *   <li><strong>Normalization:</strong> output is standardized to mean 0 and standard deviation 1.
 *   <li><strong>Shape:</strong> output is uniform on a finite symmetric interval.
 *   <li><strong>Determinism:</strong> controlled entirely by the provided seed.
 * </ul>
 *
 * @see NormalizedRandomGenerator
 * @see MersenneTwister
 * @version $Id: UniformRandomGenerator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class UniformRandomGenerator implements NormalizedRandomGenerator {

  /**
   * Creates a new generator seeded from the current time.
   *
   * <p>This constructor is a convenience for callers that do not require repeatability. The seed is
   * derived from wall-clock time inside {@link MersenneTwister}, so two instances created close
   * together may start from the same state and yield identical sequences. If deterministic output
   * is required, use one of the explicit seeding constructors instead.
   */
  public UniformRandomGenerator() {
    generator = new MersenneTwister();
  }

  /**
   * Creates a new generator using a single 32-bit seed.
   *
   * <p>The provided seed fully determines the internal state of the underlying {@link
   * MersenneTwister}. Two generators built with the same {@code seed} will therefore produce the
   * same sequence of values from {@link #nextDouble()}. This is the simplest way to obtain a
   * reproducible uniform-normalized stream.
   *
   * @param seed initial 32-bit seed defining the deterministic output sequence
   */
  public UniformRandomGenerator(int seed) {
    generator = new MersenneTwister(seed);
  }

  /**
   * Creates a new generator using an array of 32-bit seed values.
   *
   * <p>The seed array is forwarded to {@link MersenneTwister#MersenneTwister(int[])} and mixed into
   * the internal state. Arrays with the same contents produce identical sequences. If {@code seed}
   * is {@code null}, the generator falls back to time-based seeding and is not deterministic.
   *
   * @param seed initial 32-bit seed array; may be {@code null} for time-based seeding
   */
  public UniformRandomGenerator(int[] seed) {
    generator = new MersenneTwister(seed);
  }

  /**
   * Creates a new generator initialized with a single 64-bit seed.
   *
   * <p>This constructor provides a larger seed space than {@link #UniformRandomGenerator(int)} and
   * is useful when deriving independent streams from long-lived identifiers. The seed is passed to
   * the underlying {@link MersenneTwister}, which deterministically expands it into its internal
   * state.
   *
   * @param seed initial 64-bit seed defining the deterministic output sequence
   */
  public UniformRandomGenerator(long seed) {
    generator = new MersenneTwister(seed);
  }

  /**
   * Generates the next standardized uniform random scalar.
   *
   * <p>The returned value is computed by drawing {@code u} uniformly from {@code [0, 1)} using the
   * underlying {@link MersenneTwister} and applying the linear transform {@code 2*sqrt(3)*u -
   * sqrt(3)}. This yields a uniform distribution on {@code [-sqrt(3), sqrt(3)]}, which has mean
   * {@code 0} and standard deviation {@code 1}.
   *
   * <p>This method has no side effects beyond advancing the generator state. It does not allocate
   * and performs a constant amount of work per call.
   *
   * @return next pseudo-random value uniformly distributed on {@code [-sqrt(3), sqrt(3)]}
   */
  public double nextDouble() {
    return TWOSQRT3 * generator.nextDouble() - SQRT3;
  }

  /** Underlying generator used as the source of {@code [0, 1)} uniform variates. */
  MersenneTwister generator;

  private static final double SQRT3 = Math.sqrt(3.0);

  private static final double TWOSQRT3 = 2.0 * Math.sqrt(3.0);

  @Serial private static final long serialVersionUID = -6913329325753217654L;
}
