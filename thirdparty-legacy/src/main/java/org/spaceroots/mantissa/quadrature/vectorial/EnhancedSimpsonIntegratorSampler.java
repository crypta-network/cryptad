package org.spaceroots.mantissa.quadrature.vectorial;

import org.spaceroots.mantissa.functions.vectorial.*;

import java.util.Arrays;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Integrating iterator that produces cumulative areas using an enhanced Simpson rule.
 *
 * <p>The sampler wraps an underlying {@link SampledFunctionIterator} and consumes source points in
 * groups of three to apply a Simpson-like quadratic interpolation that tolerates non-uniform step
 * sizes. Clients iterate over the sampler exactly as they would over the original iterator, but the
 * returned {@link VectorialValuedPair} instances contain the running integral rather than the raw
 * function values. When the remaining source points cannot fill a full three-point window, the
 * sampler falls back to a trapezoidal approximation for the final segment to keep the output
 * monotonic and deterministic. All computations are performed in the dimension reported by the
 * delegate iterator, and each coordinate of the accumulated sum is updated independently.
 *
 * <p>This class is stateful and not thread-safe; callers should confine each instance to a single
 * iteration context. Typical usage pairs it with a {@link SampledFunction} sampler that produces
 * monotonically increasing abscissas, then iterates until {@link #hasNext()} returns {@code false}
 * while consuming the integrated ordinate series. Because the sampler never rewinds or reuses
 * points, each call to {@link #nextSamplePoint()} advances the integration frontier permanently.
 *
 * <ul>
 *   <li>Maintains cumulative sums so later calls include all prior segments.
 *   <li>Accepts irregular spacing without resampling or interpolation of the input.
 *   <li>Handles final incomplete windows with a deterministic trapezoid step.
 * </ul>
 *
 * @see EnhancedSimpsonIntegrator
 * @see SampledFunctionIterator
 * @version $Id: EnhancedSimpsonIntegratorSampler.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public final class EnhancedSimpsonIntegratorSampler implements SampledFunctionIterator {

  /** Underlying sample iterator supplying raw abscissa/ordinate pairs in forward order. */
  private final SampledFunctionIterator iter;

  /** Next point staged from the delegate to support the three-point integration window. */
  private VectorialValuedPair next;

  /** Current running sum of integrated ordinates; mutated in place as the iterator advances. */
  private final double[] sum;

  /**
   * Create an integrating sampler that wraps an existing function sample iterator.
   *
   * <p>The constructor immediately pulls the first source sample so subsequent calls can operate on
   * a three-point window without extra lookups. The dimension of the produced vectors is fixed from
   * the underlying iterator. Callers should ensure the delegate exposes at least two additional
   * points if they require a full Simpson step; otherwise, the final segment will be handled by the
   * trapezoid fallback in {@link #nextSamplePoint()}.
   *
   * @param iter iterator supplying the base function samples; must yield at least one point and a
   *     consistent dimension
   * @throws ExhaustedSampleException if the delegate is already exhausted when the sampler is
   *     constructed or cannot supply the initial point
   * @throws FunctionException if the underlying iterator encounters an evaluation failure while
   *     producing the initial sample
   */
  public EnhancedSimpsonIntegratorSampler(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    this.iter = iter;

    // get the first point
    next = iter.nextSamplePoint();

    // initialize the sum
    sum = new double[iter.getDimension()];
    Arrays.fill(sum, 0.0);
  }

  /**
   * Determine whether another integrated sample can be produced.
   *
   * <p>This method delegates directly to the wrapped iterator without advancing the integration
   * state, so it is safe to call multiple times between {@link #nextSamplePoint()} invocations.
   *
   * @return {@code true} when the sampler can compute and return another cumulative value
   */
  @Override
  public boolean hasNext() {
    return iter.hasNext();
  }

  /**
   * Get the dimensionality of the integrated vectors.
   *
   * <p>The dimension is inherited from the delegate iterator and remains constant for the life of
   * this sampler. Clients may cache the value to size buffers for consuming cumulative outputs.
   *
   * @return number of components present in each returned ordinate vector
   */
  @Override
  public int getDimension() {
    return iter.getDimension();
  }

  /**
   * Advance the iterator and return the next cumulative integral value.
   *
   * <p>The method consumes one or two additional points from the underlying iterator to compute an
   * enhanced Simpson step when possible; otherwise, it applies a trapezoid rule for the terminal
   * segment. The returned pair contains the abscissa of the newest consumed source point and a copy
   * of the running sum array so callers can retain the value independently of further iteration.
   *
   * @return immutable pair holding the latest source abscissa and the cumulative integral vector
   * @throws ExhaustedSampleException if no further source points are available to advance the
   *     integration window
   * @throws FunctionException if the delegate fails to provide the required source samples
   */
  @Override
  public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {
    // performs one step of an enhanced Simpson scheme
    VectorialValuedPair previous = next;
    VectorialValuedPair current = iter.nextSamplePoint();

    try {
      next = iter.nextSamplePoint();

      double h1 = current.x - previous.x;
      double h2 = next.x - current.x;
      double cP = (h1 + h2) * (2 * h1 - h2) / (6 * h1);
      double cC = (h1 + h2) * (h1 + h2) * (h1 + h2) / (6 * h1 * h2);
      double cN = (h1 + h2) * (2 * h2 - h1) / (6 * h2);

      double[] pY = previous.y;
      double[] cY = current.y;
      double[] nY = next.y;
      for (int i = 0; i < sum.length; ++i) {
        sum[i] += cP * pY[i] + cC * cY[i] + cN * nY[i];
      }

    } catch (ExhaustedSampleException _) {
      // we have an incomplete step at the end of the sample
      // we use a trapezoid scheme for this last step
      double halfDx = 0.5 * (current.x - previous.x);
      double[] pY = previous.y;
      double[] cY = current.y;
      for (int i = 0; i < sum.length; ++i) {
        sum[i] += halfDx * (pY[i] + cY[i]);
      }
      return new VectorialValuedPair(current.x, sum);
    }

    return new VectorialValuedPair(next.x, sum.clone());
  }
}
