package org.spaceroots.mantissa.functions.scalar;

import java.io.Serializable;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Represents a finite scalar function known only through a discrete set of sampled points.
 *
 * <p>A sampled function exposes an ordered sequence of (x, y) pairs where x is the abscissa and y
 * is the corresponding scalar value. Implementations typically wrap data produced by measurement
 * devices, numerical solvers, or other offline processes rather than computing values on demand.
 * The interface focuses on predictable, read-only traversal of those samples so downstream
 * algorithms can integrate, interpolate, or analyze them without coupling to the sampling origin.
 *
 * <p>Clients normally obtain an instance by collecting data directly or by converting a {@link
 * ComputableFunction} through {@link ComputableFunctionSampler}, which evaluates the computable
 * function at chosen abscissas. Consumers should treat the returned sample as immutable; most
 * implementations fix the number of points and preserve the insertion order so callers can reason
 * about iteration and indexing reliably.
 *
 * <p>Integrators such as {@link org.spaceroots.mantissa.quadrature.scalar.SampledFunctionIntegrator
 * SampledFunctionIntegrator} operate through a {@link SampledFunctionIterator}, which adapts this
 * interface for streaming access. Implementations are generally not thread-safe; if the underlying
 * storage can be mutated or shared across threads, callers must coordinate external
 * synchronization.
 *
 * <ul>
 *   <li>Responsibility: expose the size and indexed access to sampled (x, y) pairs.
 *   <li>Typical use: drive numeric integration, interpolation, or plotting loops.
 *   <li>Lifetime: usually immutable once constructed; indices remain stable.
 * </ul>
 *
 * @see SampledFunctionIterator
 * @see ComputableFunctionSampler
 * @see ComputableFunction
 * @version $Id: SampledFunction.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public interface SampledFunction extends Serializable {

  /**
   * Return the number of points currently stored in the sample.
   *
   * <p>The count reflects the total number of abscissa/value pairs that the implementation exposes
   * for indexed access. For most implementations this value is determined at construction time and
   * does not change, allowing callers to preallocate buffers and bound iteration safely. Use this
   * method before calling {@link #samplePointAt(int)} to avoid out-of-range access and to size any
   * consumer loops. Implementations are expected to return non-negative values; an empty sample is
   * represented by zero.
   *
   * @return non-negative number of abscissa/value points available in deterministic order
   */
  int size();

  /**
   * Get the abscissa and value pair located at the specified zero-based index.
   *
   * <p>Indexed access enables random retrieval without forcing a full iteration. Callers should
   * provide a valid index in the range {@code 0 <= index < size()}; the method signals misuse with
   * {@link ArrayIndexOutOfBoundsException}. Implementations may fetch values from cached storage or
   * lazily from an underlying function; in the latter case failures are reported through {@link
   * FunctionException}. Retrieved pairs should be treated as snapshots of the sampling state at the
   * time of the call.
   *
   * <pre>{@code
   * SampledFunction f = sampler.sample();
   * ScalarValuedPair first = f.samplePointAt(0);
   * }</pre>
   *
   * @param index zero-based position within the sample; must be less than {@link #size()}
   * @return immutable pair containing the abscissa and function value stored at the index
   * @exception ArrayIndexOutOfBoundsException if index is negative or not strictly less than size()
   * @exception FunctionException if computing or retrieving the stored value fails at runtime
   */
  ScalarValuedPair samplePointAt(int index)
      throws ArrayIndexOutOfBoundsException, FunctionException;
}
