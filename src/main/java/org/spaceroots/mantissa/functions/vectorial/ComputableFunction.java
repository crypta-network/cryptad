package org.spaceroots.mantissa.functions.vectorial;

import java.io.Serializable;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Interface for real-to-vector functions that can be evaluated on demand.
 *
 * <p>Implementations expose a consistent, finite vector dimension and provide deterministic
 * evaluations at any real abscissa where the function is defined. The contract makes no assumption
 * about how values are produced: implementations may rely on analytical formulas, interpolation,
 * iterative solvers, or external data sources. The essential guarantee is that callers can request
 * values individually, letting numerical algorithms pick their own sampling strategy without
 * forcing a fixed grid.
 *
 * <p>Typical usage patterns include:
 *
 * <ul>
 *   <li>feeding integrators or optimizers that adaptively choose evaluation points;
 *   <li>sampling into {@link SampledFunction} via {@link ComputableFunctionSampler};
 *   <li>building higher-order operations (e.g., Jacobians) that compose multiple {@code
 *       ComputableFunction} instances.
 * </ul>
 *
 * <p>Implementations should document their domain restrictions, side effects, and thread-safety. A
 * pure function may be safely shared across threads, whereas stateful or caching implementations
 * might need external synchronization. Returned arrays are owned by the caller only if explicitly
 * stated by the implementation; callers should defensively copy when retaining results.
 *
 * @see org.spaceroots.mantissa.quadrature.vectorial.ComputableFunctionIntegrator
 * @see SampledFunction
 * @version $Id: ComputableFunction.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public interface ComputableFunction extends Serializable {
  /**
   * Get the dimension of vectors produced by {@link #valueAt(double)}.
   *
   * <p>The dimension is constant for a given function instance and represents the number of
   * components present in every returned array. Algorithms may cache this value to pre-size buffers
   * or to validate result shapes before proceeding with costly computations. Implementations should
   * return a positive value; zero-dimensional functions are not supported by downstream numerical
   * utilities in this package.
   *
   * @return strictly positive vector dimension, identical for all evaluations
   */
  int getDimension();

  /**
   * Evaluate the function at the specified abscissa and return the vector value.
   *
   * <p>The returned array length must always equal {@link #getDimension()}. Implementations may
   * allocate a new array per call or reuse internal buffers; callers should copy the result if they
   * retain it beyond the immediate scope. Inputs outside the supported domain should trigger a
   * {@link FunctionException} rather than silently clipping or extrapolating unless the
   * implementation explicitly documents such behavior. Implementations should be consistent with
   * respect to thread-safety expectations described at the type level.
   *
   * <pre>{@code
   * // Example: compute the value and inspect its first component
   * ComputableFunction f = ...;
   * double[] v = f.valueAt(0.25);
   * double first = v[0];
   * }</pre>
   *
   * @param x real abscissa at which the function must be evaluated
   * @return new or reused array containing exactly getDimension() components
   * @exception FunctionException if evaluation fails or the point is outside the domain
   */
  double[] valueAt(double x) throws FunctionException;
}
