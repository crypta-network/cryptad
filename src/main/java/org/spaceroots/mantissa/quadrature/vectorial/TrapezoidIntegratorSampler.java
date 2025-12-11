package org.spaceroots.mantissa.quadrature.vectorial;

import java.util.Arrays;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.*;

/**
 * Iterator that accumulates a vector-valued trapezoid integral over sampled points.
 *
 * <p>This sampler wraps a {@link SampledFunctionIterator} producing {@link VectorialValuedPair}
 * instances and returns the running integral after each step using the trapezoid rule. The
 * trapezoid rule approximates the integral between two consecutive abscissae by assuming the
 * function varies linearly over the interval, i.e. it uses the average of the two endpoint values
 * multiplied by the step size. As iteration progresses, each call to {@link #nextSamplePoint()}
 * consumes exactly one additional underlying sample and updates the cumulative integral vector.
 *
 * <p>Typical usage is to create a sampler from an existing iterator and then iterate until it is
 * exhausted:
 *
 * <pre>{@code
 * SampledFunctionIterator base = sampledFunction.iterator();
 * TrapezoidIntegratorSampler sampler = new TrapezoidIntegratorSampler(base);
 * while (sampler.hasNext()) {
 *   VectorialValuedPair integralAtX = sampler.nextSamplePoint();
 *   // integralAtX.y holds the cumulative integral components
 * }
 * }</pre>
 *
 * <p>The sampler maintains a running sum per dimension and always returns a fresh copy of that sum,
 * so callers may safely mutate the returned ordinate array without affecting later results. The
 * dimensionality is fixed for the life of the sampler and is derived from the underlying iterator.
 * Instances are stateful, advance only forward, and are not thread-safe; use from a single thread
 * unless external synchronization enforces ordering.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> delegate iteration, apply trapezoid accumulation, and
 *       expose the cumulative integral as samples.
 *   <li><strong>Notable behaviors:</strong> step sizes may be negative if the underlying samples
 *       are not ordered by increasing {@code x}, producing negative area contributions.
 * </ul>
 *
 * @see TrapezoidIntegrator
 * @see TrapezoidIntegratorSampler#nextSamplePoint()
 * @version $Id: TrapezoidIntegratorSampler.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class TrapezoidIntegratorSampler implements SampledFunctionIterator {

  /** Underlying sample iterator. */
  private final SampledFunctionIterator iter;

  /** Current point. */
  private VectorialValuedPair current;

  /** Current running sum. */
  private final double[] sum;

  /**
   * Constructor. Build an integrator from an underlying sample iterator.
   *
   * <p>The constructor immediately consumes the first underlying sample point to establish the
   * initial abscissa and ordinate values. The running integral is initialized to zero for every
   * component. Subsequent calls to {@link #nextSamplePoint()} will integrate over intervals formed
   * by consecutive base samples.
   *
   * @param iter iterator over the base function samples; must be non-null and positioned at the
   *     start of its sequence
   * @throws ExhaustedSampleException if the underlying iterator has no initial sample to read
   *     during construction
   * @throws FunctionException if the underlying iterator cannot produce the first sample due to a
   *     function evaluation failure
   */
  public TrapezoidIntegratorSampler(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    this.iter = iter;

    // get the first point
    current = iter.nextSamplePoint();

    // initialize the sum
    sum = new double[iter.getDimension()];
    Arrays.fill(sum, 0.0);
  }

  /**
   * Indicates whether another integrated sample point can be produced.
   *
   * <p>This method delegates to the underlying iterator and does not advance iteration. A return
   * value of {@code true} means that a subsequent call to {@link #nextSamplePoint()} is expected to
   * succeed and integrate over at least one more interval.
   *
   * @return {@code true} if the wrapped iterator reports a remaining sample, {@code false} once
   *     exhausted
   */
  public boolean hasNext() {
    return iter.hasNext();
  }

  /**
   * Returns the dimensionality of the vector-valued function being integrated.
   *
   * <p>The dimension is fixed for the life of this sampler and matches the dimension reported by
   * the wrapped iterator. Callers can use it to size result buffers or validate expected component
   * counts.
   *
   * @return number of components in each integral vector produced by this sampler
   */
  public int getDimension() {
    return iter.getDimension();
  }

  /**
   * Advances to the next base sample and returns the cumulative trapezoid integral at that point.
   *
   * <p>The sampler performs one trapezoid step between the previously consumed base sample {@code
   * (x₀, y₀)} and the newly consumed base sample {@code (x₁, y₁)}. For each dimension {@code i}, it
   * adds {@code 0.5 * (x₁ - x₀) * (y₀[i] + y₁[i])} to the running sum. The returned pair uses the
   * new abscissa {@code x₁} and a defensive copy of the running sum, representing the integral from
   * the initial sample up to {@code x₁}. If the underlying abscissae are not monotone, the step
   * size may be negative and the integral will reflect that signed area.
   *
   * @return a new {@link VectorialValuedPair} whose {@code x} is the current base abscissa and
   *     whose {@code y} is a fresh copy of the cumulative integral per component
   * @throws ExhaustedSampleException if the wrapped iterator has no more base samples to consume
   * @throws FunctionException if evaluating the next base sample fails in the wrapped iterator
   */
  public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {

    // performs one step of a trapezoid scheme
    VectorialValuedPair previous = current;
    current = iter.nextSamplePoint();

    double halfDx = 0.5 * (current.x - previous.x);
    double[] pY = previous.y;
    double[] cY = current.y;
    for (int i = 0; i < sum.length; ++i) {
      sum[i] += halfDx * (pY[i] + cY[i]);
    }

    return new VectorialValuedPair(current.x, sum.clone());
  }
}
