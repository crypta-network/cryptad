package org.spaceroots.mantissa.functions.vectorial;

import java.io.Serializable;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Interface for vector-valued functions represented only by sampled points.
 *
 * <p>Implementations expose a finite, ordered sequence of {@code (x, y)} pairs where {@code x}
 * denotes the abscissa of the sample and {@code y} holds the vectorial value evaluated at that
 * abscissa. The interface is intended for data that already exists in discrete form, such as
 * measurements produced by sensors, tabulated results from numerical simulations, or functions that
 * are expensive to recompute analytically. Clients typically read samples sequentially to feed
 * interpolators, resamplers, or numerical integrators.
 *
 * <p>Samples are treated as immutable for the lifetime of a {@code SampledFunction} instance; the
 * ordering of indices is stable and spans {@link #size()} elements starting at zero.
 * Implementations may perform lazy loading or compute values on demand, but they should guarantee
 * that repeated accesses to the same index yield consistent coordinates. Unless specified otherwise
 * by a concrete type, instances are not thread-safe for concurrent mutation of the underlying
 * storage; concurrent read-only access to precomputed samples is generally safe when the
 * implementation does not cache transient state.
 *
 * <p>Typical usage follows one of these patterns:
 *
 * <ul>
 *   <li>Obtain metadata such as {@link #getDimension()} and {@link #size()} to plan processing.
 *   <li>Iterate indices from {@code 0} to {@code size() - 1} and read each {@link
 *       VectorialValuedPair} via {@link #samplePointAt(int)}.
 *   <li>Wrap a {@link ComputableFunction} using {@link ComputableFunctionSampler} to capture a
 *       dense sampling of an otherwise continuous function.
 * </ul>
 *
 * <p>Sampled functions cannot be directly handled by integrators implementing the {@link
 * org.spaceroots.mantissa.quadrature.vectorial.SampledFunctionIntegrator
 * SampledFunctionIntegrator}. These integrators need a {@link SampledFunctionIterator} object to
 * iterate over the sample while preserving any invariants required by the underlying algorithm.
 *
 * @see SampledFunctionIterator
 * @see ComputableFunctionSampler
 * @see ComputableFunction
 * @version $Id: SampledFunction.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public interface SampledFunction extends Serializable {

  /**
   * Return the number of sampled points available from this function.
   *
   * <p>The count includes every valid index starting at zero and ending at {@code size() - 1}.
   * Implementations should keep this value stable for the lifetime of the instance so downstream
   * consumers can preallocate buffers or schedule work without defensive checks. Large samples may
   * reside on disk or stream from remote sources; callers should not assume the method is constant
   * time, though most in-memory implementations will be fast. The returned size does not imply
   * uniform spacing of abscissas or any particular ordering beyond the guarantee that indices are
   * strictly increasing.
   *
   * @return total number of stored sample points, always non-negative and stable across calls
   */
  int size();

  /**
   * Get the dimension of the vectorial values stored in each sample point.
   *
   * <p>The dimension corresponds to the length of the vector component stored in {@link
   * VectorialValuedPair#y}. A constant dimension across all indices is assumed; callers may rely on
   * this to size arrays or matrices used for interpolation and integration. Returning a dimension
   * of zero is permitted for purely scalar data represented with the vectorial container, but
   * typical implementations return a positive value. The method must not perform expensive
   * computations beyond reading readily available metadata.
   *
   * @return the number of elements in each sample vector component; usually a positive integer
   */
  int getDimension();

  /**
   * Retrieve the abscissa and vector value stored at a given sample index.
   *
   * <p>Indexing is zero-based and must fall within the inclusive range {@code 0} to {@code size() -
   * 1}. The returned {@link VectorialValuedPair} should reflect the coordinates as stored by the
   * implementation; callers should not mutate shared instances unless the concrete implementation
   * documents that it returns defensive copies. Access may trigger lazy loading or evaluation of
   * the underlying computable function, so repeated calls with the same index should be expected to
   * return consistent results. This method is not inherently thread-safe; external synchronization
   * is required if concurrent mutation of backing data is possible.
   *
   * <pre>{@code
   * // Example: iterate through all samples
   * for (int i = 0; i < sampled.size(); ++i) {
   *   VectorialValuedPair point = sampled.samplePointAt(i);
   *   process(point.getAbscissa(), point.getValue());
   * }
   * }</pre>
   *
   * @param index zero-based position of the desired sample; must be within bounds of the sequence
   * @return pair containing the abscissa and associated vector value for the requested index
   * @throws ArrayIndexOutOfBoundsException if the provided index is negative or not below {@link
   *     #size()}
   * @throws FunctionException if computation or deferred loading of the underlying function fails
   */
  VectorialValuedPair samplePointAt(int index)
      throws ArrayIndexOutOfBoundsException, FunctionException;
}
