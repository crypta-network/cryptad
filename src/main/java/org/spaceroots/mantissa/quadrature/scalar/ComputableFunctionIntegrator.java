package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.ComputableFunction;

/**
 * Contract for numerical integration of single-variable scalar functions.
 *
 * <p>This interface defines the minimal operations required by quadrature engines that evaluate
 * {@link ComputableFunction} instances over finite intervals. Implementations encapsulate the
 * algorithmic details (adaptive refinement, fixed-rule quadrature, error estimation, or sampling
 * reuse) while exposing a stable entry point for callers that only need the integral value. Typical
 * usage is to select an integrator suited to the expected smoothness of the function, create or
 * supply a {@code ComputableFunction} that returns deterministic values for any <em>x</em>, and
 * invoke {@link #integrate(ComputableFunction, double, double)} with the desired bounds. Intervals
 * may be provided in either order; the mathematical orientation of the integral is preserved, so
 * swapped bounds generally produce a sign change rather than an exception.
 *
 * <p>Implementations may be stateful (for example, caching samples or adapting tolerance), so
 * thread-safety is determined by the specific class. Callers should either confine each integrator
 * instance to a single thread or consult the concrete implementation before concurrent use.
 * Numerical stability depends on the chosen algorithm and the function's smoothness; functions with
 * discontinuities or singularities may require specialized integrators or preprocessing. Returned
 * results are usually approximations within an algorithm-defined tolerance rather than exact
 * analytic values.
 *
 * <ul>
 *   <li>Usual responsibilities: set integration bounds, evaluate the supplied function, accumulate
 *       the oriented area.
 *   <li>Expected behavior: reject or propagate evaluation failures from the wrapped function
 *       unchanged.
 *   <li>Common pattern: create integrator → call {@code integrate(f, a, b)} → inspect scalar
 *       result.
 * </ul>
 *
 * @see ComputableFunction
 * @version $Id: ComputableFunctionIntegrator.java 1231 2002-03-12 20:07:04Z luc $
 * @author L. Maisonobe
 */
public interface ComputableFunctionIntegrator {
  /**
   * Integrate the supplied function over the oriented interval {@code [a, b]}.
   *
   * <p>The integrator samples the provided {@link ComputableFunction} across the closed interval,
   * applying whatever quadrature rule the concrete implementation supports. The bounds are allowed
   * in either order; when {@code a > b} the returned value reflects the mathematically negative
   * orientation rather than raising an error. Implementations are expected to honor any internal
   * tolerance or evaluation limits they expose elsewhere, and they may perform adaptive refinement
   * to achieve a stable result. Callers should ensure the function is well-behaved on the interval;
   * steep gradients or discontinuities can degrade accuracy or increase the number of evaluations
   * required. The method is not guaranteed to be idempotent if the function has side effects or
   * depends on external mutable state.
   *
   * @param f computable scalar function supplying deterministic values for quadrature evaluation
   * @param a lower or upper bound; values greater than {@code b} reverse interval orientation
   * @param b upper or lower bound; values less than {@code a} preserve signed integral semantics
   * @return definite integral estimate over {@code [a, b]} with orientation preserved
   * @exception FunctionException if the underlying function throws one during evaluation steps
   */
  double integrate(ComputableFunction f, double a, double b) throws FunctionException;
}
