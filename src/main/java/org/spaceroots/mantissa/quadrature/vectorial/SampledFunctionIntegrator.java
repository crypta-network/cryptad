package org.spaceroots.mantissa.quadrature.vectorial;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;

/**
 * Defines the contract for integrating vector-valued sampled functions.
 *
 * <p>Implementations consume a {@link SampledFunctionIterator} that exposes successive sample
 * points and return the accumulated integral for every component of the vector signal. Typical
 * usage pairs a concrete iterator produced by a sampler with an integrator that knows how to
 * combine the discrete samples (for example, trapezoidal or Simpson schemes) into a continuous
 * estimate. Instances are usually stateless and reusable, but callers should treat any provided
 * iterator as single-use and forward-only.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Validating that the iterator exposes enough points for the chosen integration scheme.
 *   <li>Accumulating component-wise integrals without mutating the iterator source.
 *   <li>Surfacing sampling or function errors via well-defined exceptions rather than silent
 *       truncation.
 * </ul>
 *
 * <p>This interface does not mandate thread safety; callers should wrap instances or iterators if
 * they are shared between threads. Integrators are intended for deterministic, offline computation
 * rather than streaming updates; iteration must complete before results are returned.
 *
 * @see SampledFunctionIterator
 * @see ComputableFunctionIntegrator
 * @version $Id: SampledFunctionIntegrator.java 1231 2002-03-12 20:07:04Z luc $
 * @author L. Maisonobe
 */
public interface SampledFunctionIntegrator {

  /**
   * Integrate the provided iterator over its complete sampling domain.
   *
   * <p>The iterator is consumed sequentially until it signals exhaustion, applying the integration
   * scheme defined by the implementation to every vector component. Implementations may require a
   * minimum number of points (for example, two for trapezoidal rules); if that requirement is not
   * met, an exception is raised instead of returning a partial result. The iterator is not reset or
   * reused; callers must provide a fresh instance for each integration run and should not attempt
   * to read it again after this call completes.
   *
   * <pre>{@code
   * // Example: integrate a sampled three-dimensional curve
   * double[] area = integrator.integrate(curveIterator);
   * }</pre>
   *
   * @param iter iterator supplying ordered sample points; must not be {@code null} and should not
   *     be reused after this call
   * @return array containing the integral of each vector component across the iterator's full
   *     domain; ownership remains with the caller
   * @exception ExhaustedSampleException if the iterator ends before the scheme's minimum sample
   *     count is satisfied
   * @exception FunctionException if computing a sample value fails inside the wrapped function
   */
  double[] integrate(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException;
}
