package org.spaceroots.mantissa.quadrature.vectorial;

import java.util.Arrays;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.*;

/**
 * Riemann-scheme iterator that accumulates the left-hand rectangle integral of a sampled function.
 *
 * <p>Instances wrap another {@link SampledFunctionIterator} and expose an iterator that walks over
 * the cumulative integral values rather than the raw function values. Each call to {@link
 * #nextSamplePoint()} consumes exactly one point from the underlying iterator, multiplies the
 * previous ordinate by the step width, and adds the product to a running sum held per dimension.
 * The class is intentionally simple and deterministic: there is no adaptive step-size control, no
 * tolerance handling, and no smoothing beyond the constant-within-step assumption. It therefore
 * best suits teaching examples, baselines for regression tests, or situations where callers already
 * control sampling density carefully and prefer a transparent accumulation scheme.
 *
 * <p>Invariants: the dimension of the output matches the wrapped iterator, the internal sum starts
 * at zero for every component, and iteration is strictly forward-only. The integrator is mutable
 * and not thread-safe; do not share a single instance across threads without external
 * synchronization. Results returned by {@link #nextSamplePoint()} carry a defensive copy of the
 * running sum so callers can mutate the received array without affecting subsequent iterations.
 *
 * <ul>
 *   <li>Strategy: left Riemann rectangles using the previous ordinate for each step.
 *   <li>Accuracy: depends entirely on the density and ordering of the provided samples.
 *   <li>Failure modes: propagates exhaustion and function-evaluation errors from the wrapped
 *       iterator.
 * </ul>
 *
 * @see RiemannIntegrator
 * @version $Id: RiemannIntegratorSampler.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class RiemannIntegratorSampler implements SampledFunctionIterator {

  /** Underlying sample iterator. */
  private final SampledFunctionIterator iter;

  /** Current point. */
  private VectorialValuedPair current;

  /** Current running sum. */
  private final double[] sum;

  /**
   * Constructor. Build an integrator from an underlying sample iterator.
   *
   * <p>The constructor pulls the first sample immediately, initializes an all-zero accumulation
   * buffer matching the iterator dimension, and prepares the instance for forward iteration. The
   * wrapped iterator is consumed destructively; subsequent callers must not rely on it for raw
   * samples. The integrator performs no validation on step ordering beyond what the delegated
   * iterator provides, so callers should feed monotonically increasing abscissae to obtain
   * meaningful area estimates.
   *
   * <pre>{@code
   * SampledFunctionIterator base = sampler.iterator();
   * RiemannIntegratorSampler riemann = new RiemannIntegratorSampler(base);
   * VectorialValuedPair integral = riemann.nextSamplePoint();
   * }</pre>
   *
   * @param iter iterator over the base function; must yield at least one sample and remain valid
   *     for forward-only consumption
   * @throws ExhaustedSampleException if the wrapped iterator contains no sample to bootstrap the
   *     integral
   * @throws FunctionException if computing the first sample fails in the underlying iterator
   */
  public RiemannIntegratorSampler(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    this.iter = iter;

    // get the first point
    current = iter.nextSamplePoint();

    // initialize the sum
    sum = new double[iter.getDimension()];
    Arrays.fill(sum, 0.0);
  }

  /**
   * Report whether another integrated sample can be produced without triggering exhaustion.
   *
   * <p>The query delegates directly to the wrapped {@link SampledFunctionIterator} and does not
   * advance iteration or mutate the running sum. It is therefore safe to call repeatedly in tight
   * loops or guard conditions. A {@code false} value indicates that a subsequent call to {@link
   * #nextSamplePoint()} will raise {@link ExhaustedSampleException}. Because the underlying
   * iterator is consumed destructively, the result may change after each successful call to {@code
   * nextSamplePoint()} but will never revert to {@code true} once exhaustion is reached.
   *
   * @return {@code true} when the integrator can advance at least one more step; {@code false} once
   *     the wrapped iterator has been fully consumed
   */
  @Override
  public boolean hasNext() {
    return iter.hasNext();
  }

  /**
   * Expose the number of vector components carried by the underlying iterator.
   *
   * <p>The dimension remains stable for the lifetime of the integrator and equals the length of the
   * {@code y} arrays returned by {@link #nextSamplePoint()}. Callers typically use this value to
   * allocate fixed-size buffers or to assert compatibility with downstream numerical routines.
   *
   * @return constant dimensionality of the integrated vector values; never negative
   */
  @Override
  public int getDimension() {
    return iter.getDimension();
  }

  /**
   * Advance the iterator and return the cumulative left Riemann integral at the new abscissa.
   *
   * <p>The method multiplies the previous ordinate by the step width between the previous and new
   * abscissae, adds the product component-wise to an internal running sum, and returns a fresh
   * {@link VectorialValuedPair} containing the updated sum. The returned ordinate is a clone of the
   * internal buffer to avoid accidental external mutation. Callers should guard the invocation with
   * {@link #hasNext()} to prevent exhaustion errors. No attempt is made to reorder or deduplicate
   * samples; incorrect ordering in the source iterator directly affects the computed area.
   *
   * @return pair whose abscissa matches the newly consumed point and whose ordinate contains the
   *     cumulative integral up to that abscissa; the ordinate array is safe to modify by the caller
   * @throws ExhaustedSampleException if no further sample exists in the wrapped iterator
   * @throws FunctionException if the underlying iterator fails to produce the next sample value
   */
  @Override
  public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {

    // performs one step of a Riemann scheme
    VectorialValuedPair previous = current;
    current = iter.nextSamplePoint();
    double step = (current.x - previous.x);
    double[] pY = previous.y;
    for (int i = 0; i < sum.length; ++i) {
      sum[i] += step * pY[i];
    }

    return new VectorialValuedPair(current.x, sum.clone());
  }
}
