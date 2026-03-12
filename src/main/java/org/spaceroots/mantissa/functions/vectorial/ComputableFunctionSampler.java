package org.spaceroots.mantissa.functions.vectorial;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Sampler that exposes a regular grid view over a {@link ComputableFunction}.
 *
 * <p>Instances describe an evenly spaced sequence of abscissas and compute vector values lazily
 * when callers request individual sample points. This is useful when algorithms need predictable
 * spacing (for plotting, interpolation warm starts, quick previews) but the underlying function is
 * defined in terms of on-demand evaluations. No point values are cached; repeated calls re-evaluate
 * the function and therefore keep memory usage constant at the price of extra computation.
 *
 * <p>Construction supports several grid definitions:
 *
 * <ul>
 *   <li>an origin, a constant step, and an explicit point count;
 *   <li>a closed range and a desired point count (step inferred);
 *   <li>a closed range and a desired step, with optional adjustment so the upper bound is exactly
 *       included.
 * </ul>
 *
 * <p>Callers typically obtain the expected size via {@link #size()}, inspect the vector length via
 * {@link #getDimension()}, and iterate indices with {@link #samplePointAt(int)}. The class is
 * immutable after construction, thread-safe for concurrent reads assuming the wrapped {@code
 * ComputableFunction} itself is thread-safe, and produces defensive copies of returned ordinate
 * arrays.
 *
 * @see ComputableFunction
 * @see VectorialValuedPair
 * @see SampledFunction
 * @version $Id: ComputableFunctionSampler.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class ComputableFunctionSampler implements SampledFunction, Serializable {

  /**
   * Constructor.
   *
   * <p>Builds a sampler from a fixed origin, a constant step, and an explicit number of points. Use
   * this when the grid is already known or derived from upstream constraints such as plot
   * resolution. Beware of the common off-by-one pattern: a closed range {@code [0, 1]} with step
   * {@code 0.1} requires {@code n == 11}.
   *
   * @param function underlying function to evaluate; must remain valid for every requested point.
   * @param begin abscissa of the first grid point; any finite {@code double} is accepted.
   * @param step positive spacing between successive points, in the same unit as {@code begin}.
   * @param n total number of grid points to expose; must be positive to avoid empty samples.
   */
  public ComputableFunctionSampler(ComputableFunction function, double begin, double step, int n) {
    this.function = function;
    this.begin = begin;
    this.step = step;
    this.n = n;
  }

  /**
   * Constructor. Build a sample from an {@link ComputableFunction}.
   *
   * <p>Creates a regular grid over a closed range by inferring a constant step from the desired
   * number of points. The first point lies at {@code range[0]} and the last at {@code range[1]}},
   * with linear interpolation in between.
   *
   * @param function underlying function to evaluate; must support every point in the supplied
   *     range.
   * @param range two-element array describing {@code [lower, upper]} abscissa bounds; indices 0 and
   *     1 are read directly and are not copied.
   * @param n number of points to produce across the range; must be at least 2 to span the bounds.
   */
  public ComputableFunctionSampler(ComputableFunction function, double[] range, int n) {
    this.function = function;
    begin = range[0];
    step = (range[1] - range[0]) / (n - 1);
    this.n = n;
  }

  /**
   * Constructor. Build a sample from an {@link ComputableFunction}.
   *
   * <p>Creates a grid over a closed range using a preferred step size. When {@code adjustStep} is
   * {@code true}, the sampler slightly shrinks the step so the final point lands exactly on the
   * upper bound; otherwise the final point is the largest value that does not exceed the upper
   * bound by more than one unadjusted step.
   *
   * @param function underlying function to evaluate; must accept every generated abscissa.
   * @param range two-element array describing {@code [lower, upper]} abscissa bounds, read as-is.
   * @param step preferred spacing between points; must be strictly positive to avoid infinite
   *     loops.
   * @param adjustStep whether to reduce the spacing so the last point equals {@code range[1]};
   *     {@code false} keeps the original spacing even if the last point falls short of the bound.
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

  @Override
  public int size() {
    return n;
  }

  /**
   * Get the vector dimension produced by the wrapped function.
   *
   * <p>The returned value is forwarded from {@link ComputableFunction#getDimension()} without local
   * caching; repeated calls therefore keep consistency with dynamic implementations but may incur
   * repeated delegate lookups.
   *
   * @return strictly positive vector dimension consistent with all values produced by the sampler.
   */
  @Override
  public int getDimension() {
    return function.getDimension();
  }

  /**
   * Compute the sample point at a given grid index.
   *
   * <p>The abscissa is derived from the sampler definition ({@code begin + index * step}); the
   * ordinate is the function value at that abscissa. The returned {@link VectorialValuedPair}
   * defensively copies the ordinate array so callers can retain it safely.
   *
   * @param index zero-based index within the grid; must satisfy {@code 0 <= index < size()}.
   * @return pair containing the abscissa and a fresh copy of the ordinate vector at that position.
   * @throws ArrayIndexOutOfBoundsException if {@code index} is negative or greater than or equal to
   *     {@link #size()}.
   * @throws FunctionException if the underlying function rejects the computed abscissa or fails
   *     during evaluation.
   */
  @Override
  public VectorialValuedPair samplePointAt(int index)
      throws ArrayIndexOutOfBoundsException, FunctionException {

    if (index < 0 || index >= n) {
      throw new ArrayIndexOutOfBoundsException();
    }

    double x = begin + index * step;
    return new VectorialValuedPair(x, function.valueAt(x));
  }

  /** Underlying computable function. */
  private final ComputableFunction function;

  /** Beginning abscissa. */
  private final double begin;

  /** Step between points. */
  private final double step;

  /** Total number of points. */
  private final int n;

  @Serial private static final long serialVersionUID = 1368582688313212821L;
}
