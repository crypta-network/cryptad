package org.spaceroots.mantissa.quadrature.vectorial;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;

/**
 * Implements a trapezoidal-rule integrator for vector-valued sampled functions.
 *
 * <p>The integrator consumes values produced by a {@link SampledFunctionIterator} and assumes the
 * underlying function varies linearly between successive abscissas. Each call to {@link
 * #integrate(SampledFunctionIterator)} walks the iterator exactly once, delegates step handling to
 * a {@link TrapezoidIntegratorSampler}, and returns the cumulative integral evaluated at the last
 * available sample. Because the rule is first order, accuracy improves when the iterator provides
 * closely spaced samples; widely spaced or irregular abscissas may amplify interpolation error, so
 * callers should tune the sampling density to their tolerance requirements. The class itself is
 * stateless and can be reused freely; however, the supplied iterator must present a consistent
 * dimensionality and monotonically increasing abscissas to produce meaningful results. Concurrency
 * control is left to callers—create separate instances or guard access when integrating on multiple
 * threads.
 *
 * <ul>
 *   <li>Uses the classical trapezoidal rule with linear interpolation between samples.
 *   <li>Returns the integrated vector at the iterator's final abscissa.
 *   <li>Leaves no residual state after completion, enabling safe reuse per invocation.
 * </ul>
 *
 * @version $Id: TrapezoidIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see TrapezoidIntegratorSampler
 * @see SampledFunctionIterator
 */
public class TrapezoidIntegrator implements SampledFunctionIntegrator {

  /**
   * Builds a new trapezoidal integrator with no retained configuration.
   *
   * <p>The constructor performs no allocation beyond the instance itself and defers all runtime
   * setup to {@link #integrate(SampledFunctionIterator)}. Instances are inexpensive and contain no
   * shared mutable state, so callers may reuse a single integrator sequentially or create one per
   * thread when running integrations concurrently. The behavior of the computation depends entirely
   * on the iterator provided at call time.
   */
  public TrapezoidIntegrator() {
    // default constructor intentionally empty
  }

  /**
   * Integrates a sampled vector-valued function using the trapezoidal rule.
   *
   * <p>The method wraps the supplied {@link SampledFunctionIterator} in a {@link
   * TrapezoidIntegratorSampler}, which performs stepwise accumulation by treating each pair of
   * adjacent samples as the vertices of a trapezoid. The iterator is consumed exactly once; the
   * returned array represents the cumulative integral at the iterator's final abscissa and is a
   * fresh clone produced by the sampler. Callers should ensure the iterator yields monotonically
   * increasing abscissas and a stable dimensionality. Null iterators are not permitted.
   *
   * <pre>{@code
   * SampledFunctionIterator iterator = ...;
   * double[] integral = new TrapezoidIntegrator().integrate(iterator);
   * }</pre>
   *
   * @param iter iterator delivering ordered samples of the function; must not be {@code null} and
   *     should keep a constant dimension across all returned vectors.
   * @return array containing the accumulated integral values after processing the final sample; the
   *     array is newly allocated and safe for the caller to modify.
   * @throws ExhaustedSampleException if the iterator reports exhaustion before the integration
   *     completes or cannot provide the next sample when requested.
   * @throws FunctionException if evaluating the underlying function fails while advancing the
   *     iterator or computing the next sample point.
   */
  public double[] integrate(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(iter);
    double[] sum = null;
    while (sampler.hasNext()) {
      sum = sampler.nextSamplePoint().y;
    }
    return sum;
  }
}
