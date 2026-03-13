package org.spaceroots.mantissa.functions.scalar;

import java.io.Serial;
import java.io.Serializable;

/**
 * Holder for a scalar function sample consisting of one abscissa and its scalar value.
 *
 * <p>This mutable data object pairs a single input coordinate {@code x} with the corresponding
 * function value {@code f(x)}. It is primarily used by sampling utilities that exchange lists or
 * streams of measured points, letting algorithms keep the two scalars together without allocating a
 * heavier structure. Instances carry no validation beyond basic storage, so callers remain
 * responsible for domain checks, units, and numerical quality before persisting the pair or
 * forwarding it to interpolators.
 *
 * <p>Typical usage is to create a pair when observing or computing a new sample, pass the object to
 * a {@link SampledFunction} implementation, and later mutate the stored values if the sample is
 * reused for iterative refinement. Because setters update the internal state directly, instances
 * are not thread-safe; share immutable copies or external synchronization when the same object
 * crosses threads. Equality and ordering are intentionally not defined here, leaving callers free
 * to choose their own comparison strategies when sorting or deduplicating sample sets.
 *
 * <ul>
 *   <li>Represents one scalar input/output pair used by sampling and interpolation code.
 *   <li>Supports reuse through mutation while keeping a compact two-double footprint.
 *   <li>Designed for simple transport; no invariants beyond holding the provided coordinates.
 * </ul>
 *
 * @see org.spaceroots.mantissa.functions.scalar.SampledFunction
 * @see org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair
 * @version $Id: ScalarValuedPair.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class ScalarValuedPair implements Serializable {

  /**
   * Builds a new pair from the provided coordinates without applying any validation.
   *
   * <p>The constructor simply records the supplied abscissa and ordinate so that downstream code
   * can transport the sample as a cohesive unit. Use this when creating a fresh measurement or when
   * transforming an existing sample into a mutable representation that may be adjusted during later
   * processing stages. No bounds checking is performed; callers should ensure {@code x} and {@code
   * y} reflect meaningful values for the surrounding algorithm, including finite ranges if required
   * by later consumers.
   *
   * @param x abscissa coordinate to store, typically the function input value in domain units
   * @param y ordinate value to store, representing {@code f(x)} as a finite scalar measurement
   */
  public ScalarValuedPair(double x, double y) {
    this.x = x;
    this.y = y;
  }

  /**
   * Copy-constructor that duplicates the coordinates from another pair instance.
   *
   * <p>This is a convenience for cloning when a caller needs an independent mutable copy of an
   * existing sample. The coordinates are copied by value, so subsequent mutations on either
   * instance do not affect the other. The source reference must not be {@code null}; passing {@code
   * null} will result in a {@link NullPointerException} because the fields are accessed directly.
   *
   * @param p existing pair to duplicate; must be non-null and already contain meaningful values
   */
  public ScalarValuedPair(ScalarValuedPair p) {
    x = p.x;
    y = p.y;
  }

  /**
   * Returns the current abscissa stored in this pair.
   *
   * <p>The method performs no transformation; it simply exposes the latest value set through the
   * constructor or {@link #setX(double)}. Because the class is mutable, the returned value may
   * change over time if callers reuse the instance across iterations. Callers that require stable
   * snapshots should either copy the value immediately or work with defensive copies of the pair.
   *
   * @return the abscissa currently associated with this sample, in the same units supplied earlier
   */
  public double getX() {
    return x;
  }

  /**
   * Returns the current ordinate (function value) stored in this pair.
   *
   * <p>The ordinate reflects the last value supplied to the constructor or {@link #setY(double)}.
   * It is intended to represent {@code f(x)} for the accompanying abscissa, but this class does not
   * enforce any relationship between the two fields. The returned value is a direct primitive copy;
   * further changes to the pair will not retroactively affect earlier callers that already consumed
   * the primitive.
   *
   * @return the scalar ordinate representing the function output for the stored abscissa
   */
  public double getY() {
    return y;
  }

  /**
   * Updates the abscissa associated with this pair.
   *
   * <p>Use this to reuse an existing {@code ScalarValuedPair} instance in iterative algorithms that
   * recompute sample points without reallocating objects. The method overwrites the previous value
   * immediately; there is no synchronization, so coordinate updates that cross threads should be
   * guarded externally. Consider updating the ordinate as well to keep the pair semantically
   * consistent if the function value changes alongside the abscissa.
   *
   * @param x new abscissa to store, using the same units as prior values for consistency
   */
  public void setX(double x) {
    this.x = x;
  }

  /**
   * Updates the ordinate (function value) associated with this pair.
   *
   * <p>This mutator enables reusing a single instance while refining or correcting previously
   * computed outputs. The assignment happens atomically on the field but offers no thread-safety
   * guarantees; coordinate updates should be externally synchronized when visible to multiple
   * threads. Ensure callers maintain meaningful pairing between {@code x} and {@code y} when
   * updating the ordinate independently of the abscissa.
   *
   * @param y new function value to store, typically the result of evaluating {@code f(x)}
   */
  public void setY(double y) {
    this.y = y;
  }

  /** Abscissa of the point. */
  private double x;

  /** Scalar ordinate of the point, y = f (x). */
  private double y;

  @Serial private static final long serialVersionUID = 1884346552569300794L;
}
