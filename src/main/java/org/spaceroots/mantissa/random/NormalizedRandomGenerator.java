package org.spaceroots.mantissa.random;

import java.io.Serializable;

/**
 * Normalized random generator for scalar values with zero mean and unit standard deviation.
 *
 * <p>This interface defines the minimal contract required by higher-level stochastic utilities that
 * need standardized scalar samples. Implementations are free to choose the underlying random number
 * source and probability distribution, provided the generated sequence remains centered at zero
 * with variance one. Typical usage is to obtain repeatable standardized samples that can be scaled
 * or combined into vectors by adapters elsewhere in the library. The interface itself makes no
 * guarantees about independence between successive values, determinism, or performance; those
 * properties depend entirely on the implementing class and its backing generator.
 *
 * <ul>
 *   <li>Provides standardized output suitable for Monte Carlo, simulation, or statistical tests.
 *   <li>Leaves distribution shape (Gaussian, uniform normalization, etc.) to the implementation.
 *   <li>Designed to be wrapped by higher-level generators that build multidimensional samples.
 * </ul>
 *
 * <p>Thread-safety is implementation specific. Users requiring concurrent access should consult the
 * concrete class documentation or wrap instances with appropriate synchronization.
 *
 * @version $Id: NormalizedRandomGenerator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public interface NormalizedRandomGenerator extends Serializable {

  /**
   * Returns the next standardized random scalar with zero mean and unit standard deviation.
   *
   * <p>The contract guarantees only the first two moments of the generated values; the exact
   * probability distribution, correlation structure, and reproducibility are left to the
   * implementation. Callers typically use this method repeatedly and apply their own scaling or
   * transformation to adapt the standardized output to domain-specific ranges. Thread-safety and
   * determinism depend on the concrete generator; clients that share instances across threads
   * should coordinate access according to the implementation notes. Implementations are encouraged
   * to avoid expensive normalization on each invocation to keep repeated sampling efficient.
   *
   * <pre>{@code
   * NormalizedRandomGenerator generator = ...;
   * double sample = generator.nextDouble();
   * }</pre>
   *
   * @return next pseudo-random double normalized to mean 0 and standard deviation 1
   */
  double nextDouble();
}
