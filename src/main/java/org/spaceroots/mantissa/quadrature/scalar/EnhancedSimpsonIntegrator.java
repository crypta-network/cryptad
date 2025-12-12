package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;

/**
 * Adaptive Simpson-style accumulator for streamed samples of a scalar function.
 *
 * <p>The integrator consumes a {@link SampledFunctionIterator} that yields abscissa/value pairs in
 * order and converts them into a running definite integral. It delegates per-step math to {@link
 * EnhancedSimpsonIntegratorSampler}, which applies a Simpson-like rule when three consecutive
 * points are available and falls back to a trapezoidal rule for any trailing pair. Unlike composite
 * Simpson integrators that require uniform spacing, this implementation tolerates varying step
 * widths while still delivering third-order accuracy on well-behaved curves. Typical usage pulls
 * samples from a lazily evaluated function and streams the output integral into higher level
 * routines without holding the entire series in memory.
 *
 * <p>The class is stateful and not thread-safe: each call to {@link
 * #integrate(SampledFunctionIterator)} consumes the supplied iterator exactly once. Callers should
 * provide monotonically increasing abscissae to preserve numerical stability and avoid reusing
 * iterators that are shared across threads. Error conditions propagate directly from the underlying
 * iterator or sampler so callers can react to depleted samples or function-evaluation failures.
 *
 * <ul>
 *   <li>Responsibilities: drive sampling, accumulate area, and return the final integral.
 *   <li>Notable behavior: mixes Simpson and trapezoid rules to handle uneven sample spacing.
 *   <li>Mutability: a new instance carries no state beyond the active integration loop.
 * </ul>
 *
 * @version $Id: EnhancedSimpsonIntegrator.java 1237 2002-03-20 21:01:57Z luc $
 * @author L. Maisonobe
 */
public class EnhancedSimpsonIntegrator implements SampledFunctionIntegrator {

  /**
   * Builds a stateless integrator instance ready for single-threaded use.
   *
   * <p>No initialization is required because per-run state is allocated inside {@link
   * #integrate(SampledFunctionIterator)}. Clients may reuse the same instance across multiple
   * integrations as long as invocations are not concurrent.
   */
  public EnhancedSimpsonIntegrator() {
    // no internal state to initialize
  }

  /**
   * Integrates all samples provided by the iterator into a single accumulated value.
   *
   * <p>The method repeatedly requests successive samples from {@link
   * EnhancedSimpsonIntegratorSampler} until the sampler reports exhaustion. Each step contributes
   * either a Simpson-style area when three consecutive samples are available or a trapezoidal area
   * for the final, possibly incomplete, segment. The iterator is consumed fully; subsequent calls
   * on the same iterator instance are not supported. Callers should ensure the iterator begins with
   * at least one sample and that abscissae progress forward to avoid negative widths and unstable
   * weights. Any function-evaluation failures surface immediately as {@link FunctionException}
   * without altering partial results.
   *
   * <pre>{@code
   * SampledFunctionIterator it = buildIterator();
   * double area = new EnhancedSimpsonIntegrator().integrate(it);
   * }</pre>
   *
   * @param iter iterator delivering ordered scalar samples; must not be {@code null} and must
   *     supply at least one point before exhaustion
   * @return accumulated integral value corresponding to the last sample position; intermediate
   *     results are not exposed or cached
   * @throws ExhaustedSampleException if the iterator is empty at start or ends unexpectedly while
   *     building the initial window of points
   * @throws FunctionException if evaluating the underlying function to obtain a sample fails at any
   *     point in the traversal
   */
  public double integrate(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    EnhancedSimpsonIntegratorSampler sampler = new EnhancedSimpsonIntegratorSampler(iter);
    double sum = 0.0;

    boolean finished = false;
    while (!finished) {
      try {
        sum = sampler.nextSamplePoint().getY();
      } catch (ExhaustedSampleException e) {
        finished = true;
      }
    }

    return sum;
  }
}
