package org.spaceroots.mantissa.functions.vectorial;

import java.io.Serial;
import java.io.Serializable;

/**
 * Immutable pair capturing a single abscissa and the vectorial value of a function at that point.
 *
 * <p>This value object travels between samplers, interpolators, and numerical integrators as a
 * concise record of the relation {@code y = f(x)}. The constructor defensively clones the provided
 * ordinate so later mutations of the caller's buffer do not alter the stored sample. Instances are
 * serializable to allow caching sample sets, persisting intermediate results, or sending data
 * across process boundaries without recomputation. Although the fields are {@code final}, callers
 * should treat the exposed {@link #y} array as read-only to avoid surprising consumers that assume
 * immutability.
 *
 * <p>Typical usage patterns include:
 *
 * <ul>
 *   <li>Representing raw measurements returned by {@link SampledFunction} implementations.
 *   <li>Holding interpolation results produced by {@link ComputableFunctionSampler}.
 *   <li>Passing immutable coordinates into algorithms that iterate over sampled curves.
 * </ul>
 *
 * <p>Instances carry no inherent units or scaling; responsibility for consistent dimensionality and
 * axis ordering remains with the calling code. The class itself is thread-safe for concurrent read
 * access, provided consumers do not mutate the shared ordinate array.
 *
 * @see SampledFunction
 * @see SampledFunctionIterator
 * @see ComputableFunctionSampler
 * @version $Id: VectorialValuedPair.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class VectorialValuedPair implements Serializable {

  /**
   * Create a pair from an abscissa and its associated vectorial value.
   *
   * <p>The constructor performs a shallow clone of the supplied ordinate array to shield the stored
   * sample from later in-place edits performed by the caller. The {@code x} coordinate accepts any
   * finite real value; units are defined by the surrounding function or dataset. Passing a null
   * array triggers a {@link NullPointerException} during cloning, and callers should ensure the
   * array length matches the expected dimension of the enclosing {@link SampledFunction}.
   *
   * <pre>{@code
   * // Example: build a point from computed values
   * double[] value = evaluator.apply(input);
   * VectorialValuedPair point = new VectorialValuedPair(input, value);
   * }</pre>
   *
   * @param x abscissa coordinate representing the input position; any real value is accepted
   * @param y vectorial value evaluated at the provided abscissa; must be non-null and is cloned to
   *     preserve immutability of the stored sample
   */
  public VectorialValuedPair(double x, double[] y) {
    this.x = x;
    this.y = y.clone();
  }

  /**
   * Abscissa coordinate associated with this sample point.
   *
   * <p>The value remains constant after construction and should be interpreted using the same units
   * as the function that produced the sample. Callers may reuse the scalar freely because it is a
   * primitive copied by value.
   */
  public final double x;

  /**
   * Vectorial ordinate capturing {@code y = f(x)} for this point.
   *
   * <p>The array reference is {@code final} but its contents are mutable; the constructor clones
   * the original input so external modifications do not affect this instance. Consumers should
   * still treat the array as read-only to maintain thread safety and semantic clarity when sharing
   * instances across processing stages.
   */
  public final double[] y;

  @Serial private static final long serialVersionUID = -7397116933564410103L;
}
