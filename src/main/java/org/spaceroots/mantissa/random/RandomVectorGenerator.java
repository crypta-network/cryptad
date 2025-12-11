package org.spaceroots.mantissa.random;

/**
 * Generates random vectors of doubles in a single call.
 *
 * <p>Implementations wrap one or more scalar random sources to deliver complete vectors whose
 * length and statistical properties are defined by the concrete generator (for example, uniform or
 * Gaussian distributions, correlated components, or deterministic seeding strategies). The
 * interface is intentionally minimal so callers can request successive vectors without managing
 * per-component sampling. Typical usage is to obtain the generator from a factory or builder, then
 * invoke {@link #nextVector()} inside simulation or sampling loops. Implementations may reuse
 * internal buffers to minimize allocations; callers must copy results they intend to retain beyond
 * the next call. The generator itself is generally stateless from the caller perspective, but the
 * underlying random state advances with each invocation. Unless documented otherwise by a concrete
 * class, instances are not thread-safe; external synchronization is required when sharing a
 * generator between threads.
 *
 * <ul>
 *   <li>Primary responsibility: emit full-length random vectors on demand.
 *   <li>Common use cases: Monte Carlo simulations, randomized algorithms, and statistical testing.
 *   <li>Performance note: arrays may be recycled to reduce garbage generation.
 * </ul>
 *
 * @version $Id: RandomVectorGenerator.java 1485 2003-02-23 13:34:02Z luc $
 * @author L. Maisonobe
 */
public interface RandomVectorGenerator {

  /**
   * Generates the next random vector produced by this generator.
   *
   * <p>The vector length and distribution of its elements depend on the concrete implementation;
   * callers should consult the specific generator class for exact statistical guarantees. Each
   * invocation advances the internal random state and may reuse an internal array instance for
   * performance. To retain values across calls, copy the returned contents before invoking this
   * method again. Most implementations are not synchronized; coordinate access if used concurrently
   * from multiple threads.
   *
   * @return a mutable array containing the generated components; ownership remains with the
   *     generator, so callers must copy it if they need a stable snapshot for later use.
   */
  double[] nextVector();
}
