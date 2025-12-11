package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;

/**
 * RiemannIntegrator computes a left-hand Riemann sum over a streamed scalar function.
 *
 * <p>The integrator consumes values from a {@link SampledFunctionIterator} and accumulates the area
 * under the curve by assuming each interval maintains the previous ordinate value. This makes the
 * algorithm easy to reason about and very fast to implement, but it is also sensitive to coarse
 * sampling: the approximation converges slowly and may amplify floating-point round-off when the
 * caller cannot supply tightly spaced abscissae. Because the class is stateless and performs no
 * caching, multiple instances can be created cheaply and reused whenever an explicit type is
 * desired for dependency injection or API clarity.
 *
 * <p>Use this integrator when you need the most basic integration scheme or want a baseline result
 * to compare with more accurate algorithms such as {@link TrapezoidIntegrator}. The class assumes
 * the iterator delivers samples in strictly increasing order of abscissa and does not enforce any
 * thread-safety; callers should confine an instance to a single thread unless their iterator
 * implementation is itself thread-safe. Error handling is delegated to the iterator, so exceptions
 * related to sample exhaustion or function evaluation propagate unchanged to the caller.
 *
 * <ul>
 *   <li>Implements the {@link SampledFunctionIntegrator} contract for scalar-valued samples.
 *   <li>Does not store historical points beyond the current accumulator.
 *   <li>Best suited for educational use or quick prototypes where accuracy demands are modest.
 * </ul>
 *
 * @see TrapezoidIntegrator
 * @version $Id: RiemannIntegrator.java 1237 2002-03-20 21:01:57Z luc $
 * @author L. Maisonobe
 */
public class RiemannIntegrator implements SampledFunctionIntegrator {

  /**
   * Creates a reusable Riemann integrator instance with no retained configuration state.
   *
   * <p>The constructor performs no initialization work beyond creating the object, so callers can
   * freely allocate new instances or cache a shared one when repeatedly integrating different
   * sampled functions. Instances are immutable and thread-safe to the extent that {@link
   * #integrate(SampledFunctionIterator)} is only invoked by one thread at a time or provided with a
   * thread-safe iterator implementation.
   */
  public RiemannIntegrator() {
    // No instance state is required; integrator logic is fully contained in the integrate call.
  }

  /**
   * Integrate a sampled scalar function using a left-hand Riemann sum.
   *
   * <p>The method walks through the supplied {@link SampledFunctionIterator}, consuming each point
   * exactly once and accumulating the signed area implied by consecutive abscissae. It assumes the
   * iterator yields samples in strictly increasing order of {@code x}; providing unsorted data may
   * produce misleading results because interval widths become negative. The integrator does not
   * rewind the iterator, so callers should supply a fresh, unconsumed iterator for each invocation.
   *
   * <pre>{@code
   * SampledFunctionIterator iterator = ...;
   * double area = new RiemannIntegrator().integrate(iterator);
   * }</pre>
   *
   * @param iter iterator that delivers ordered sample points; must not be null or partially used
   * @return cumulative integral estimate after consuming the iterator; value reflects final
   *     accumulator state
   * @throws ExhaustedSampleException if the iterator runs out of samples before a step completes
   * @throws FunctionException if evaluating the underlying function raises an error during sampling
   */
  public double integrate(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    RiemannIntegratorSampler sampler = new RiemannIntegratorSampler(iter);
    double sum = 0.0;

    while (sampler.hasNext()) {
      sum = sampler.nextSamplePoint().getY();
    }

    return sum;
  }
}
