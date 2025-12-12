package org.spaceroots.mantissa.quadrature.vectorial;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;

/**
 * Implements a Riemann-sum based integrator for vector-valued sampled functions.
 *
 * <p>The integrator walks over a {@link SampledFunctionIterator} and treats each integration step
 * as constant, effectively performing a left-hand Riemann sum. The simplicity of this strategy
 * makes it easy to understand and to extend, but it also means that high accuracy requires very
 * small step sizes. Excessively fine sampling can in turn magnify floating-point round-off and make
 * the accumulated sum numerically fragile, so callers should balance precision needs against
 * stability and performance.
 *
 * <p>Typical usage pairs this integrator with iterators that already expose uniformly spaced
 * samples. The class is stateless beyond the local accumulation performed inside {@link
 * #integrate(SampledFunctionIterator)}; a new instance can therefore be reused across multiple
 * integrations without synchronization. It is intended primarily as a pedagogical baseline or as a
 * minimal template for more sophisticated integrators such as {@link TrapezoidIntegrator}, not as a
 * production-grade choice when error bounds are tight.
 *
 * <ul>
 *   <li>Assumes piecewise-constant behavior over each iterator-provided step.
 *   <li>Suitable when quick, low-accuracy estimates are acceptable.
 *   <li>Thread-safe for concurrent reuse because it holds no mutable shared state.
 * </ul>
 *
 * @see TrapezoidIntegrator
 * @version $Id: RiemannIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class RiemannIntegrator implements SampledFunctionIntegrator {

  /**
   * Builds a new Riemann integrator instance with no retained state.
   *
   * <p>Instances are lightweight and can be reused across multiple integrations because all state
   * is confined to the local accumulation performed inside {@link
   * #integrate(SampledFunctionIterator)}. Creating a fresh instance is inexpensive, but callers may
   * prefer to reuse one when executing many short integrations to avoid repeated allocations.
   */
  public RiemannIntegrator() {
    // No initialization required because the integrator is stateless and relies solely on the
    // iterator supplied to integrate(); the constructor remains empty by design.
  }

  /**
   * Integrates the provided sampled function using a left-hand Riemann sum.
   *
   * <p>The iterator is consumed sequentially; on each step the method assumes the function remains
   * constant over the interval represented by the sample and accumulates the sample value into the
   * running sum. Only the most recent partial sum is retained, so the returned array reflects the
   * cumulative value after the final sample. The iterator is exhausted by this call and must not be
   * reused. Null iterators are not permitted and will trigger the underlying iterator's behavior.
   *
   * <pre>{@code
   * SampledFunctionIterator iterator = ...;
   * double[] integral = new RiemannIntegrator().integrate(iterator);
   * }</pre>
   *
   * @param iter sampled function iterator that delivers points in integration order; must not be
   *     {@code null} and must supply samples until exhaustion.
   * @return array representing the accumulated integral values after processing all samples; the
   *     returned array instance is the final sample's internal buffer.
   * @throws ExhaustedSampleException if the iterator signals premature exhaustion during sampling
   *     before integration completes.
   * @throws FunctionException if evaluating the sampled function fails at any iteration step or
   *     when advancing the iterator.
   */
  public double[] integrate(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iter);
    double[] sum = null;

    while (sampler.hasNext()) {
      sum = sampler.nextSamplePoint().y;
    }

    return sum;
  }
}
