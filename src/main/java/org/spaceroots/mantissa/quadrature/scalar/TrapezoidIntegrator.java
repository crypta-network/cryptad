package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;

/**
 * Numerically integrates a sampled scalar function using the classical trapezoid rule.
 *
 * <p>The integrator consumes values through a {@link SampledFunctionIterator}, treating successive
 * abscissa/ordinate pairs as vertices of adjacent trapezoids. At each step it adds half the sum of
 * the two ordinates multiplied by the interval width, yielding a running approximation of the
 * definite integral. Because the rule presumes linear behavior between samples, accuracy depends on
 * providing sufficiently fine sampling or on the underlying function being close to affine over
 * each interval. The integrator does not attempt adaptive refinement or error estimation; callers
 * should decide sampling density and bounds ahead of time.
 *
 * <p>Instances are stateless and thread-safe: each call to {@link
 * #integrate(SampledFunctionIterator)} builds a short-lived sampler and keeps no global mutable
 * state. Use this type when simplicity and transparency matter more than high-order accuracy, or as
 * a reference implementation while developing more sophisticated quadrature schemes.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> accumulate trapezoid areas from streamed samples.
 *   <li><strong>Notable behavior:</strong> iteration stops when the underlying iterator signals
 *       exhaustion via {@link ExhaustedSampleException}.
 *   <li><strong>Thread-safety:</strong> no shared state; safe for concurrent use with independent
 *       iterators.
 * </ul>
 *
 * @see TrapezoidIntegratorSampler
 * @see SampledFunctionIterator
 * @version $Id: TrapezoidIntegrator.java 1237 2002-03-20 21:01:57Z luc $
 * @author L. Maisonobe
 */
public class TrapezoidIntegrator implements SampledFunctionIntegrator {

  /**
   * Builds a new trapezoid integrator instance with no retained state.
   *
   * <p>The constructor performs no initialization beyond instantiation. Instances are safe to reuse
   * across calls to {@link #integrate(SampledFunctionIterator)} because all computation is confined
   * to the method scope and the per-call sampler.
   */
  public TrapezoidIntegrator() {
    // No fields to initialize; integrator is stateless and per-call allocations happen in
    // integrate.
  }

  /**
   * Integrates a sampled scalar function by summing trapezoid areas between consecutive samples.
   *
   * <p>The method pulls samples from the provided {@link SampledFunctionIterator} until it signals
   * depletion. Each pair of adjacent points contributes a trapezoid whose area updates the running
   * sum; the final value reflects the integral over the iterator's entire domain. Callers should
   * supply samples ordered by increasing abscissa and with spacing fine enough to meet their error
   * tolerances, because no adaptive refinement or error control is applied. The iterator is
   * consumed as part of this call and should not be reused afterward.
   *
   * @param iter forward-only iterator yielding ordered abscissa/value pairs; must not be {@code
   *     null} and should expose the full interval of integration.
   * @return accumulated trapezoid area representing the integral of the sampled function over all
   *     points delivered by the iterator.
   * @throws ExhaustedSampleException if the iterator reports exhaustion before a complete step can
   *     be formed (for example, when invoked on an empty iterator).
   * @throws FunctionException if the iterator encounters a failure while generating the next sample
   *     point, propagating the underlying computation error.
   */
  public double integrate(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iter);
    double sum = 0.0;

    boolean hasMoreSamples = true;
    while (hasMoreSamples) {
      try {
        sum = sampler.nextSamplePoint().getY();
      } catch (ExhaustedSampleException _) {
        hasMoreSamples = false;
      }
    }

    return sum;
  }
}
