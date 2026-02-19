package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.scalar.*;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Sample iterator that integrates a scalar function on the fly using an enhanced Simpson rule.
 *
 * <p>The sampler wraps another {@link SampledFunctionIterator} and transforms each triple of
 * successive sample points into an incremental area estimate. Compared to the classical Simpson
 * formula, this variant accepts uneven spacing between abscissae and automatically falls back to a
 * trapezoidal step when the final chunk has only two points available. Clients consume it exactly
 * like the underlying iterator: call {@link #hasNext()} and {@link #nextSamplePoint()} to stream
 * accumulated integrals without first materializing the input data set.
 *
 * <p>Typical usage is in post-processing of numerically sampled or measured data where the grid is
 * not perfectly uniform. The class is stateful: each call advances the wrapped iterator and updates
 * an internal running sum stored as a primitive double. Instances are not thread-safe and should be
 * confined to a single traversal. Because the sampler never rewinds, it is best suited to one-pass
 * analyses such as plotting cumulative area or feeding downstream integrators.
 *
 * <ul>
 *   <li>Accepts irregular spacing while preserving Simpson-like accuracy.
 *   <li>Emits {@link ScalarValuedPair} whose abscissa is the last consumed point and ordinate is
 *       the cumulative integral up to that abscissa.
 *   <li>Falls back to trapezoidal integration for the final incomplete segment.
 * </ul>
 *
 * @see EnhancedSimpsonIntegrator
 * @see SampledFunctionIterator
 * @version $Id: EnhancedSimpsonIntegratorSampler.java 1237 2002-03-20 21:01:57Z luc $
 * @author L. Maisonobe
 */
public final class EnhancedSimpsonIntegratorSampler implements SampledFunctionIterator {

  /** Underlying sampled function iterator. */
  private final SampledFunctionIterator iter;

  /** Next point. */
  private ScalarValuedPair next;

  /** Current running sum. */
  private double sum;

  /**
   * Builds an integrating iterator that wraps the provided sampled function stream.
   *
   * <p>The constructor eagerly consumes the first sample point so subsequent calls to {@link
   * #nextSamplePoint()} can operate on complete segments. Callers must supply an iterator that
   * yields at least one point; otherwise an {@link ExhaustedSampleException} is propagated. The
   * running integral starts at zero and accumulates with every call to {@code nextSamplePoint()}.
   * No copies of the underlying samples are retained beyond what is needed for the current step.
   *
   * @param iter iterator over the base function; must be non-null and able to provide at least one
   *     sample without side effects between calls.
   * @throws ExhaustedSampleException if the underlying iterator has no sample available during
   *     construction.
   * @throws FunctionException if the underlying iterator fails while producing the first sample.
   */
  public EnhancedSimpsonIntegratorSampler(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    this.iter = iter;

    // get the first point
    next = iter.nextSamplePoint();

    // initialize the sum
    sum = 0.0;
  }

  /**
   * Reports whether another integrated sample can be produced without advancing state.
   *
   * <p>This method delegates to the wrapped iterator and does not alter the internal running sum.
   * Repeated calls are inexpensive and safe; however, once {@code false} is returned any further
   * call to {@link #nextSamplePoint()} will raise {@link ExhaustedSampleException}.
   *
   * @return {@code true} when at least one more integrated point can be obtained from the
   *     underlying sampler.
   */
  @Override
  public boolean hasNext() {
    return iter.hasNext();
  }

  /**
   * Advances the iterator one step and returns the cumulative integral at the new abscissa.
   *
   * <p>The method consumes one or two points from the wrapped iterator depending on whether a full
   * three-point Simpson window is available. When three consecutive points are present, it applies
   * the enhanced Simpson weights that tolerate non-uniform spacing. If only two points remain at
   * the end of the stream, it uses a trapezoidal approximation for the last segment. The returned
   * pair owns primitive copies of the abscissa and integral; modifying it does not affect internal
   * state. Successive calls accumulate into the same running sum.
   *
   * @return new pair whose abscissa equals the most recently consumed point and whose ordinate is
   *     the total integrated value up to that abscissa.
   * @throws ExhaustedSampleException if called after the underlying iterator is depleted or if the
   *     initial construction exhausted the stream.
   * @throws FunctionException if the wrapped iterator fails while producing any required sample
   *     point.
   */
  @Override
  public ScalarValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {
    // performs one step of an enhanced Simpson scheme
    ScalarValuedPair previous = next;
    ScalarValuedPair current = iter.nextSamplePoint();

    try {
      next = iter.nextSamplePoint();

      double h1 = current.getX() - previous.getX();
      double h2 = next.getX() - current.getX();
      double cP = (h1 + h2) * (2 * h1 - h2) / (6 * h1);
      double cC = (h1 + h2) * (h1 + h2) * (h1 + h2) / (6 * h1 * h2);
      double cN = (h1 + h2) * (2 * h2 - h1) / (6 * h2);

      sum += cP * previous.getY() + cC * current.getY() + cN * next.getY();

    } catch (ExhaustedSampleException _) {
      // we have an incomplete step at the end of the sample
      // we use a trapezoid scheme for this last step
      sum += 0.5 * (current.getX() - previous.getX()) * (previous.getY() + current.getY());
      return new ScalarValuedPair(current.getX(), sum);
    }

    return new ScalarValuedPair(next.getX(), sum);
  }
}
