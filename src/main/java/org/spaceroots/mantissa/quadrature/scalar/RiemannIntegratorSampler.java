package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.*;

/**
 * Iterates over the running left-Riemann integral of a sampled scalar function.
 *
 * <p>The sampler wraps an existing {@link SampledFunctionIterator} that emits pairs {@code (x,
 * f(x))} in strictly increasing abscissa order and turns each successive point into the accumulated
 * integral value. Each call to {@link #nextSamplePoint()} advances the underlying iterator by one
 * element and returns a new {@link ScalarValuedPair} whose abscissa equals the most recent {@code
 * x} and whose ordinate is the running sum of rectangular areas computed with the previous point as
 * the left edge. Because the scheme is first-order and assumes a constant value over each
 * sub-interval, high accuracy requires small step sizes and well-behaved functions; the sampler
 * does not attempt adaptive refinement or error control.
 *
 * <p>Instances are lightweight, single-use, and preserve the evaluation order of the wrapped
 * iterator. They hold a minimal internal state consisting of the current point and the aggregated
 * sum, making them suitable for streaming integration pipelines where intermediate results need to
 * be consumed incrementally. The class is not thread-safe; confine instances to the thread driving
 * the sampling loop and avoid sharing the underlying iterator across threads.
 *
 * <ul>
 *   <li>Produces one integral sample per source sample after the first point.
 *   <li>Propagates {@link FunctionException} and {@link ExhaustedSampleException} verbatim from the
 *       wrapped iterator.
 *   <li>Assumes monotonically increasing abscissae; incorrect ordering will yield incorrect area
 *       accumulation.
 * </ul>
 *
 * @see RiemannIntegrator
 * @see SampledFunctionIterator
 * @see ScalarValuedPair
 * @version $Id: RiemannIntegratorSampler.java 1237 2002-03-20 21:01:57Z luc $
 * @author L. Maisonobe
 */
public class RiemannIntegratorSampler implements SampledFunctionIterator {

  /**
   * Underlying sample iterator that supplies monotonically increasing abscissae and raw function
   * values; never null after construction and consumed exactly once.
   */
  private final SampledFunctionIterator iter;

  /**
   * Current point held between successive integration steps; updated on each call to {@link
   * #nextSamplePoint()} and used as the left edge of the next rectangle.
   */
  private ScalarValuedPair current;

  /**
   * Current running sum of the rectangular areas accumulated so far; starts at {@code 0.0} before
   * the first step and increases monotonically as samples advance.
   */
  private double sum;

  /**
   * Creates a sampler that produces cumulative left-Riemann integrals from an existing iterator.
   *
   * <p>The constructor immediately consumes the first sample point from the supplied iterator to
   * establish the initial left edge and resets the running sum to zero. Subsequent calls to {@link
   * #nextSamplePoint()} will start accumulating areas using that stored point. The provided
   * iterator must deliver strictly increasing {@code x} values and remain valid for the lifetime of
   * this sampler; ownership of iteration is transferred and callers should not advance it
   * independently.
   *
   * @param iter iterator over the base function that yields ordered {@link ScalarValuedPair}
   *     samples; must be non-null and positioned at its first element.
   * @throws ExhaustedSampleException if the iterator has no elements to initialize the sampler
   * @throws FunctionException if computing the first sample fails in the underlying iterator
   */
  public RiemannIntegratorSampler(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    this.iter = iter;

    // get the first point
    current = iter.nextSamplePoint();

    // initialize the sum
    sum = 0.0;
  }

  public boolean hasNext() {
    return iter.hasNext();
  }

  /**
   * Advances the sampler by one source sample and returns the updated integral value.
   *
   * <p>The method performs a single left-Riemann step: it fetches the next sample from the wrapped
   * iterator, computes the rectangular area using the previous sample's ordinate and the difference
   * in abscissae, updates the running sum, and returns a fresh {@link ScalarValuedPair} whose
   * abscissa equals the new sample's {@code x} and whose ordinate equals the accumulated integral
   * up to that point. The returned pair is independent of the internal state and may be retained by
   * the caller. This call consumes one element from the underlying iterator; repeated invocations
   * must be preceded by {@link #hasNext()} to avoid premature exhaustion.
   *
   * @return a new pair containing the latest abscissa and the running integral value at that
   *     abscissa; never null.
   * @throws ExhaustedSampleException if no further samples are available from the underlying
   *     iterator
   * @throws FunctionException if the underlying iterator fails while producing the next sample
   */
  public ScalarValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {
    // performs one step of a Riemann scheme
    ScalarValuedPair previous = current;
    current = iter.nextSamplePoint();
    sum += (current.getX() - previous.getX()) * previous.getY();

    return new ScalarValuedPair(current.getX(), sum);
  }
}
