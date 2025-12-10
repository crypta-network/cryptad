package org.spaceroots.mantissa.optimization;

/**
 * Strategy interface that decides when a {@link DirectSearchOptimizer direct search method} has
 * reached convergence.
 *
 * <p>A convergence checker inspects the ordered simplex produced at each iteration and signals when
 * further evaluations are unlikely to improve the objective. Implementations typically compare the
 * best and worst vertices, track relative or absolute improvements between iterations, or enforce a
 * maximum number of evaluations. The optimizer delegates all stop decisions to this checker, which
 * means the caller can tailor termination to numerical tolerances, runtime limits, or domain
 * constraints without altering the optimization algorithm itself.
 *
 * <p>Instances are often lightweight and stateless, making them reusable across multiple optimizer
 * runs. If an implementation keeps mutable counters or references to previous simplices, callers
 * should not share a single instance across concurrent optimization sessions unless the
 * implementation explicitly documents thread safety. Optimizers invoke the checker after each
 * simplex update, so the method must execute quickly to avoid dominating iteration cost.
 *
 * <ul>
 *   <li>Typical checks: relative size of simplex, absolute cost spread, iteration ceilings.
 *   <li>Input contract: simplex elements are already evaluated and sorted from best to worst.
 *   <li>Output contract: returning {@code true} causes the optimizer to stop immediately.
 * </ul>
 *
 * @version $Id: ConvergenceChecker.java 1580 2004-07-15 20:13:43Z luc $
 * @see DirectSearchOptimizer
 * @see PointCostPair
 * @author L. Maisonobe
 */
public interface ConvergenceChecker {

  /**
   * Check whether the current simplex satisfies the termination conditions.
   *
   * <p>The optimizer calls this method after it has evaluated all vertices of the simplex and
   * sorted them from lowest to highest cost. Implementations may compare cost dispersion,
   * geometrical spread, or relative progress against earlier simplices; they may also include fixed
   * iteration or evaluation limits. Returning {@code true} instructs the optimizer to stop without
   * modifying the simplex further. Callers should assume the provided array will not be mutated by
   * the implementation unless documented otherwise.
   *
   * <pre>{@code
   * // Example: stop when the simplex contracts enough
   * if (checker.converged(simplex)) {
   *   return simplex[0];
   * }
   * }</pre>
   *
   * @param simplex ordered simplex with points evaluated from best cost to worst
   * @return true when termination criteria deem current simplex sufficiently stable to stop search
   */
  boolean converged(PointCostPair[] simplex);
}
