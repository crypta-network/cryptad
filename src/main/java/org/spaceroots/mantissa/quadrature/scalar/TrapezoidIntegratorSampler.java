package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.scalar.*;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Iterator that builds the cumulative integral of a scalar function using the trapezoid rule while
 * it is being sampled.
 *
 * <p>The sampler wraps another {@link SampledFunctionIterator} that yields discrete {@link
 * ScalarValuedPair points}. Each call to {@link #nextSamplePoint()} advances the underlying
 * iterator by one point and returns a new pair whose {@code y} value is the running integral from
 * the first sample up to the current abscissa, computed with the classical trapezoid formula
 * <em>(h/2 · (y0 + y1))</em>. It keeps state between invocations, so callers should consume results
 * in order and avoid concurrent access.
 *
 * <p>Use this class when a lightweight, streaming integrator is needed and a full-fledged adaptive
 * quadrature would be overkill. Accuracy depends directly on the spacing of incoming samples; very
 * coarse or highly irregular spacing may require pre-processing or a different integrator. The
 * sampler does not alter the source iterator and stops once the wrapped iterator reports
 * exhaustion.
 *
 * <ul>
 *   <li>Mutable state: maintains the last sample and accumulated sum.
 *   <li>Thread-safety: not thread-safe; external synchronization is required for shared use.
 *   <li>Error handling: propagates checked exceptions from the underlying iterator unchanged.
 * </ul>
 *
 * @see TrapezoidIntegrator
 * @see SampledFunctionIterator
 * @version $Id: TrapezoidIntegratorSampler.java 1237 2002-03-20 21:01:57Z luc $
 * @author L. Maisonobe
 */
public final class TrapezoidIntegratorSampler implements SampledFunctionIterator {

  /** Underlying sample iterator. */
  private final SampledFunctionIterator iter;

  /** Current point. */
  private ScalarValuedPair current;

  /** Current running sum. */
  private double sum;

  /**
   * Constructor. Build an integrator from an underlying sample iterator.
   *
   * <p>The first sample point is consumed immediately to initialize the internal state; subsequent
   * calls to {@link #nextSamplePoint()} will start integrating from that point forward. The passed
   * iterator must provide monotonically increasing abscissa values for meaningful results, and
   * callers should avoid reusing it elsewhere once wrapped to prevent interleaved consumption. No
   * defensive copy is taken, so any side effects of the iterator are observable through this
   * sampler.
   *
   * @param iter iterator over the base function that yields ordered scalar sample points; must not
   *     be {@code null} and must provide at least one sample.
   * @throws ExhaustedSampleException if the iterator exposes no sample when the sampler is created,
   *     meaning integration cannot start.
   * @throws FunctionException if the underlying iterator fails to produce its first sample due to a
   *     function evaluation problem.
   */
  public TrapezoidIntegratorSampler(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    this.iter = iter;

    // get the first point
    current = iter.nextSamplePoint();

    // initialize the sum
    sum = 0.0;
  }

  /**
   * Check whether another integrated sample can be produced.
   *
   * <p>This method delegates directly to the wrapped iterator without changing integration state.
   * It can therefore be called repeatedly to poll availability. A {@code true} result indicates
   * that a subsequent call to {@link #nextSamplePoint()} will succeed unless the underlying
   * iterator throws during evaluation.
   *
   * @return {@code true} when the underlying iterator reports another sample, {@code false} when
   *     the stream is exhausted and no further integrated values will be available.
   */
  @Override
  public boolean hasNext() {
    return iter.hasNext();
  }

  /**
   * Advance to the next sample and return the updated running integral.
   *
   * <p>The method consumes exactly one sample from the underlying iterator, applies the trapezoid
   * rule using the previously returned point and the new one, and returns a fresh {@link
   * ScalarValuedPair} whose abscissa equals the new sample abscissa and whose ordinate equals the
   * cumulative integral up to that abscissa. Callers should process the results sequentially; no
   * rewinding or skipping is supported. If the iterator produces irregular step sizes, the computed
   * area reflects those varying widths explicitly.
   *
   * <pre>{@code
   * // Example: integrate f(x)=x over [0,2] with unit steps
   * TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(source);
   * ScalarValuedPair p1 = sampler.nextSamplePoint(); // integral at x=1
   * ScalarValuedPair p2 = sampler.nextSamplePoint(); // integral at x=2
   * }</pre>
   *
   * @return new pair containing the latest abscissa and the cumulative trapezoid integral up to
   *     that point; the returned object is independent of internal state.
   * @throws ExhaustedSampleException if the underlying iterator has no further samples to advance
   *     to when called, indicating integration has completed.
   * @throws FunctionException if computing the next sample fails in the underlying iterator due to
   *     function evaluation or sampling errors.
   */
  @Override
  public ScalarValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {
    // performs one step of a trapezoid scheme
    ScalarValuedPair previous = current;
    current = iter.nextSamplePoint();
    sum += 0.5 * (current.getX() - previous.getX()) * (previous.getY() + current.getY());

    return new ScalarValuedPair(current.getX(), sum);
  }
}
