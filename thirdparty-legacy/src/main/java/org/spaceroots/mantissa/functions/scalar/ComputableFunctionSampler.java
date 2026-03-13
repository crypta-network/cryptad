package org.spaceroots.mantissa.functions.scalar;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Sampler that lazily evaluates a {@link ComputableFunction} on an evenly spaced grid of abscissas.
 *
 * <p>Instances capture a function reference together with the starting abscissa, the step between
 * points, and the number of points to expose. They never cache computed values, so each call to
 * {@link #samplePointAt(int)} recomputes the ordinate directly from the underlying function. This
 * makes the sampler inexpensive in memory and suitable for large theoretical or streaming domains
 * where retaining every sample would be prohibitive.
 *
 * <p>The sampler is immutable after construction; all coordinates are derived from the constructor
 * arguments. Thread-safety therefore depends on the thread-safety of the supplied function because
 * invocations are delegated without additional synchronization. Typical call flow is to construct
 * the sampler with one of the provided factory-style constructors and iterate over indices until
 * {@link #size()} to retrieve {@link ScalarValuedPair} instances.
 *
 * <ul>
 *   <li>Support for fixed step and size starting at a specific abscissa.
 *   <li>Support for deriving the step from a bounded range and desired sample count.
 *   <li>Optional step adjustment to force the final point to coincide with the range upper bound.
 * </ul>
 *
 * @see ComputableFunction
 * @see ScalarValuedPair
 * @see SampledFunction
 * @version $Id: ComputableFunctionSampler.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class ComputableFunctionSampler implements SampledFunction, Serializable {

  /** Underlying computable function. */
  private final ComputableFunction function;

  /** Beginning abscissa. */
  private final double begin;

  /** Step between points. */
  private final double step;

  /** Total number of points. */
  private final int n;

  /**
   * Creates a sampler starting at a fixed abscissa with a constant step size.
   *
   * <p>This constructor is convenient when callers already know the exact grid spacing and the
   * precise number of points they want to expose. The sampler merely records the parameters and
   * derives each abscissa as {@code begin + index * step}, leaving responsibility for meaningful
   * values to the caller. Because points are recomputed on every access, this variant avoids any
   * storage overhead but repeats evaluation work if indices are revisited. A common off-by-one
   * pitfall is forgetting that both bounds count as points: to cover {@code 0.0} through {@code
   * 1.0} with a step of {@code 0.1}, you must request {@code 11} points rather than {@code 10}.
   *
   * @param function computable function evaluated to produce each sampled ordinate; non-null.
   * @param begin abscissa of the first sample point; often the range lower bound.
   * @param step distance between successive abscissas; negative values yield descending grids.
   * @param n total number of sample points generated; should be a positive integer.
   */
  public ComputableFunctionSampler(ComputableFunction function, double begin, double step, int n) {
    this.function = function;
    this.begin = begin;
    this.step = step;
    this.n = n;
  }

  /**
   * Creates a sampler spanning a closed range with evenly spaced points.
   *
   * <p>The constructor derives the step size so that the first point matches {@code range[0]} and
   * the final point matches {@code range[1]}, distributing {@code n} points linearly in between.
   * The supplied range array is used directly; callers should pass a two-element array whose first
   * entry is the lower bound and second entry is the upper bound. No validation is performed on the
   * bounds or the count, so a non-positive {@code n} will lead to undefined behavior such as
   * division by zero during step computation.
   *
   * @param function computable function evaluated to produce each sampled ordinate; non-null.
   * @param range two-element array giving inclusive lower and upper abscissa bounds, in that order.
   * @param n number of evenly distributed sample points; should be at least two.
   */
  public ComputableFunctionSampler(ComputableFunction function, double[] range, int n) {
    this.function = function;
    begin = range[0];
    step = (range[1] - range[0]) / (n - 1);
    this.n = n;
  }

  /**
   * Creates a sampler across a range with an explicit step and optional adjustment.
   *
   * <p>When {@code adjustStep} is {@code true}, the sampler reduces the provided step just enough
   * to ensure the final abscissa coincides with {@code range[1]}, keeping the original direction of
   * travel. When {@code adjustStep} is {@code false}, it uses the unmodified step and derives the
   * number of points by flooring the division of the range length by the step, which means the last
   * point may fall short of the upper bound. The range array is consumed as-is; callers should
   * ensure the two entries represent the intended lower and upper bounds for consistent results.
   *
   * @param function computable function evaluated to produce each sampled ordinate; non-null.
   * @param range abscissa range (from <code>range [0]</code> to <code>range [1]</code>)
   * @param step nominal distance between successive abscissas before any optional adjustment.
   * @param adjustStep if true, the step is reduced so the final point equals <code>range[1]</code>.
   */
  public ComputableFunctionSampler(
      ComputableFunction function, double[] range, double step, boolean adjustStep) {
    this.function = function;
    begin = range[0];
    if (adjustStep) {
      n = (int) Math.ceil((range[1] - range[0]) / step);
      this.step = (range[1] - range[0]) / (n - 1);
    } else {
      n = (int) Math.floor((range[1] - range[0]) / step);
      this.step = step;
    }
  }

  /**
   * Returns the number of sample points defined for this sampler.
   *
   * <p>The value equals the count supplied at construction time (or derived from the provided
   * range/step) and never changes afterward. It is useful for bounding iteration because valid
   * indices run from {@code 0} inclusive to {@code size()} exclusive. This method performs no
   * evaluation of the underlying function and therefore executes in constant time regardless of
   * function complexity or external state.
   *
   * @return total number of sample points available from this sampler instance.
   */
  @Override
  public int size() {
    return n;
  }

  /**
   * Returns the sampled abscissa/ordinate pair at the specified zero-based index.
   *
   * <p>The method validates that {@code index} falls within the range {@code [0, size())}; if not,
   * it throws an {@link ArrayIndexOutOfBoundsException}. For valid indices it computes the abscissa
   * lazily and delegates evaluation of the ordinate to the wrapped {@link ComputableFunction}. No
   * caching occurs, so repeated calls for the same index will re-evaluate the function each time.
   * Callers should be prepared for exceptions emitted by the underlying function and account for
   * any performance cost if the function is expensive.
   *
   * <pre>{@code
   * // Example: iterate over all points
   * for (int i = 0; i < sampler.size(); i++) {
   *   ScalarValuedPair p = sampler.samplePointAt(i);
   * }
   * }</pre>
   *
   * @param index zero-based position of the desired point; must satisfy {@code 0 <= index <
   *     size()}.
   * @return sampled coordinate pair constructed on demand from the underlying function.
   * @throws ArrayIndexOutOfBoundsException if the index is negative or greater than or equal to
   *     {@link #size()}.
   * @throws FunctionException if the wrapped function cannot compute the ordinate for the abscissa.
   */
  @Override
  public ScalarValuedPair samplePointAt(int index)
      throws ArrayIndexOutOfBoundsException, FunctionException {

    if (index < 0 || index >= n) {
      throw new ArrayIndexOutOfBoundsException();
    }

    double x = begin + index * step;
    return new ScalarValuedPair(x, function.valueAt(x));
  }

  @Serial private static final long serialVersionUID = -5127043442851795719L;
}
