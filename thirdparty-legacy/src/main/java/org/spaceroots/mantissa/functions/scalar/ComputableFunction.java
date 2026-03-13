package org.spaceroots.mantissa.functions.scalar;

import java.io.Serializable;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Interface describing a scalar function of one real variable that can be evaluated on demand.
 *
 * <p>Implementations represent mathematical functions that accept a single real-valued argument and
 * return a real-valued result. The interface makes no assumptions about how the value is computed:
 * it may be closed-form, approximated through interpolation, numerically solved from an implicit
 * equation, or backed by a cached data set. Callers should treat the object as a pure function
 * whose observable behavior is fully captured by successive {@link #valueAt(double)} evaluations.
 * Whether instances are thread-safe or memoized depends on the concrete implementation; callers
 * should consult specific subclasses when invoking from concurrent code or when reusing instances
 * across multiple algorithms.
 *
 * <p>Typical usage includes numerical integration, root finding, interpolation, or any algorithm
 * that must adaptively evaluate a function at abscissas chosen at runtime. The companion {@link
 * ComputableFunctionSampler} can wrap an implementation to produce a {@link SampledFunction} when
 * discrete samples are required for plotting or tabulation.
 *
 * <ul>
 *   <li>Responsibility: provide deterministic scalar values for supplied abscissas.
 *   <li>Expectation: clearly document domain restrictions or discontinuities in concrete classes.
 *   <li>Interoperability: usable with quadrature utilities such as {@link
 *       org.spaceroots.mantissa.quadrature.scalar.ComputableFunctionIntegrator}.
 * </ul>
 *
 * @see org.spaceroots.mantissa.quadrature.scalar.ComputableFunctionIntegrator
 * @see SampledFunction
 * @version $Id: ComputableFunction.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public interface ComputableFunction extends Serializable {

  /**
   * Compute the value of the function at the supplied abscissa.
   *
   * <p>This operation must synchronously evaluate the current function for the exact argument
   * provided and return the corresponding scalar result. Implementations may perform inexpensive
   * analytic computations or expensive numerical procedures such as solving implicit equations or
   * interpolating tabulated data; performance characteristics and domain constraints are therefore
   * implementation specific. Callers should supply finite values within the supported domain and
   * expect a deterministic result for the same input. Errors arising from invalid abscissas,
   * convergence failures, or other evaluation issues are reported through {@link
   * FunctionException}.
   *
   * <p>Example usage:
   *
   * <pre>{@code
   * ComputableFunction sine = x -> Math.sin(x);
   * double peak = sine.valueAt(Math.PI / 2.0);
   * }</pre>
   *
   * @param x abscissa where the function must be evaluated; implementations may reject NaN or
   *     infinite values and can define narrower valid domains.
   * @return scalar value produced for {@code x}; typically finite and reproducible for identical
   *     arguments.
   * @throws FunctionException if evaluation fails because the argument is outside the supported
   *     domain or a numerical procedure cannot converge.
   */
  double valueAt(double x) throws FunctionException;
}
