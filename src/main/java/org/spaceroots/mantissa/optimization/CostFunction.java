package org.spaceroots.mantissa.optimization;

/**
 * This interface represents a cost function to be minimized.
 *
 * <p>Implementations provide a scalar measure of how well a candidate solution satisfies the
 * problem constraints or objectives. Optimizers repeatedly call {@link #cost(double[])} with
 * different parameter vectors, expecting consistent numerical results for the same input during a
 * single optimization run. The interface intentionally stays minimal so that concrete strategies
 * can model everything from deterministic algebraic expressions to stochastic simulators that
 * incorporate penalties for constraint violations. Callers should assume implementations may be
 * stateful or expensive to evaluate and design caching or parallelization accordingly.
 *
 * <p>Typical usage involves creating an implementation that wraps domain-specific calculations (for
 * example, a least-squares residual sum) and passing it to an optimizer from the same package. The
 * optimizer drives the exploration of the parameter space and relies on this interface to obtain a
 * real-valued score. Unless an implementation documents otherwise, no thread-safety guarantees are
 * provided; share instances between threads only with external synchronization or by using
 * independent instances.
 *
 * <ul>
 *   <li>Returned costs should be comparable across successive invocations.
 *   <li>Negative or NaN values are allowed only if the optimizer can handle them.
 *   <li>Implementations should signal unusable inputs via {@link CostException}.
 * </ul>
 *
 * @author Luc Maisonobe
 * @version $Id: CostFunction.java 1580 2004-07-15 20:13:43Z luc $
 */
public interface CostFunction {

  /**
   * Compute the cost associated to the given parameters array.
   *
   * <p>The computation should interpret {@code x} as a complete candidate point in parameter space
   * and return a finite scalar value that the optimizer will attempt to minimize. Implementations
   * may validate bounds or constraints, derive penalty terms, or consult cached intermediate
   * results. Callers should not mutate {@code x} after passing it in if the implementation retains
   * a reference. The method is expected to be side-effect free with respect to optimizer state, but
   * implementations may record diagnostics for later inspection.
   *
   * <p>When computation cannot proceed—because of invalid dimensions, singular matrices, overflow,
   * or domain violations—implementations must throw {@link CostException}. Returning {@code
   * Double.NaN} is discouraged because many optimizers treat it as fatal.
   *
   * <pre>{@code
   * // Example: wrap a simple quadratic cost
   * CostFunction cf = params -> params[0] * params[0] + 4 * params[1] * params[1];
   * double value = cf.cost(new double[] {2.0, -1.5});
   * }</pre>
   *
   * @param x parameters array containing the full point to evaluate; must not be {@code null} and
   *     should match the dimensionality expected by the implementation
   * @return finite scalar cost representing the objective value for the supplied parameters; lower
   *     values generally indicate better solutions for minimization algorithms
   * @throws CostException if the cost cannot be computed because inputs are invalid, constraints
   *     fail, or an internal computation error prevents producing a numeric value
   * @see PointCostPair
   */
  double cost(double[] x) throws CostException;
}
