package org.spaceroots.mantissa.utilities;

/**
 * Maps a portion of a {@code double[]} to and from an object's internal state.
 *
 * <p>Many numerical algorithms in Mantissa operate on a flat vector of primitive values rather than
 * on domain-specific objects. Examples include ODE integrators (see {@link
 * org.spaceroots.mantissa.ode.FirstOrderDifferentialEquations}) and estimation routines (see {@link
 * org.spaceroots.mantissa.estimation.EstimationProblem}). In real applications the overall state
 * vector is often composed of several cooperating objects: for instance a spacecraft orbit,
 * aerodynamic coefficients, and thruster parameters may all contribute elements to the same array.
 * This interface provides a minimal contract that lets those objects expose their state as a
 * contiguous slice of a larger array and restore themselves from that slice later.
 *
 * <p>The typical usage pattern is:
 *
 * <ul>
 *   <li>each domain object implements {@code ArraySliceMappable}, defining its own slice length,
 *   <li>an algorithm-specific adapter (for example, a {@code FirstOrderDifferentialEquations}
 *       implementation) uses an {@link ArrayMapper} to assign non-overlapping slices, and
 *   <li>during iterative processing, {@code mapStateFromArray} / {@code mapStateToArray} shuttle
 *       values without allocating new objects.
 * </ul>
 *
 * <p>Implementations are generally mutable because they update internal fields from array data.
 * Thread-safety is not prescribed by this interface; callers should assume implementations are not
 * safe for concurrent mutation unless documented otherwise.
 *
 * @see ArrayMapper
 * @author L. Maisonobe
 * @version $Id: ArraySliceMappable.java 1454 2003-01-15 19:28:40Z luc $
 */
public interface ArraySliceMappable {

  /**
   * Returns the number of consecutive array elements that represent this object's state.
   *
   * <p>The returned value defines the width of the slice that {@link #mapStateFromArray(int,
   * double[])} reads and that {@link #mapStateToArray(int, double[])} writes. Callers typically use
   * this dimension when composing a larger state vector from multiple {@code ArraySliceMappable}
   * instances, ensuring slices do not overlap and the backing array is large enough.
   *
   * @return the non-negative size of this object's state slice in array elements
   */
  int getStateDimension();

  /**
   * Reinitializes this object's internal state from a slice of the given array.
   *
   * <p>The slice starts at {@code start} and is {@link #getStateDimension() getStateDimension()}
   * elements long. Implementations should read values in increasing index order and update their
   * internal fields accordingly. This method is intended for use inside iterative algorithms, so it
   * should avoid unnecessary allocations when possible.
   *
   * @param start zero-based index of the first element belonging to this object
   * @param array backing array holding the state vector; must contain this slice
   */
  void mapStateFromArray(int start, double[] array);

  /**
   * Stores this object's current internal state into a slice of the given array.
   *
   * <p>The slice starts at {@code start} and is {@link #getStateDimension() getStateDimension()}
   * elements long. Implementations should write values in increasing index order, matching the
   * layout expected by {@link #mapStateFromArray(int, double[])}. Callers commonly invoke this
   * method before passing the array to a numerical algorithm or when exporting a composite state.
   *
   * @param start zero-based index of the first element to write for this object
   * @param array backing array that receives the state slice; must contain this slice
   */
  void mapStateToArray(int start, double[] array);
}
