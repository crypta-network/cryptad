package org.spaceroots.mantissa.roots;

import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.ComputableFunction;

/**
 * Contract for algorithms that locate a real root of a scalar function.
 *
 * <p>This interface defines a small, implementation-agnostic API for solving {@link
 * ComputableFunction} instances on a bounded interval. Callers supply the interval endpoints and
 * their already-evaluated function values, along with a {@link ConvergenceChecker} that encodes the
 * stopping criteria (for example, tolerance on the abscissa, on the function value, or on both).
 * Implementations are expected to iterate up to a caller-provided maximum and to record the most
 * recently accepted root estimate for later retrieval.
 *
 * <p>The typical usage pattern is: (1) bracket a root in {@code [x0, x1]}, (2) evaluate the
 * function at the endpoints to obtain {@code f0} and {@code f1}, (3) invoke {@link
 * #findRoot(ComputableFunction, ConvergenceChecker, int, double, double, double, double)}, and (4)
 * if it returns {@code true}, read the solution with {@link #getRoot()}.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> run a deterministic root search within the provided
 *       bounds and expose the accepted root estimate.
 *   <li><strong>Statefulness:</strong> implementations typically store the last root estimate;
 *       callers should not assume thread-safety unless documented by the concrete class.
 * </ul>
 *
 * @version $Id: RootsFinder.java 1499 2003-03-29 12:50:08Z luc $
 * @author L. Maisonobe
 * @see ConvergenceChecker
 * @see ComputableFunction
 */
public interface RootsFinder {

  /**
   * Searches for a root of the supplied function inside the given interval.
   *
   * <p>The caller provides an interval {@code [x0, x1]} that is known (by external reasoning) to
   * contain at least one root, together with the corresponding function values {@code f0} and
   * {@code f1}. Supplying endpoint values allows implementations to avoid redundant evaluations and
   * to validate assumptions about the interval. The algorithm iterates until the {@code checker}
   * reports convergence or {@code maxIter} iterations have been performed. When this method returns
   * {@code true}, {@link #getRoot()} returns the accepted root estimate.
   *
   * @param function function to solve; evaluated repeatedly during the search
   * @param checker convergence policy that decides when the estimate is acceptable
   * @param maxIter maximum number of iterations before giving up
   * @param x0 lower bound abscissa of the search interval
   * @param f0 function value at {@code x0}, provided by the caller
   * @param x1 upper bound abscissa of the search interval
   * @param f1 function value at {@code x1}, provided by the caller
   * @return {@code true} when a converged root estimate is found within bounds
   * @throws FunctionException if the function cannot be evaluated during the search
   */
  boolean findRoot(
      ComputableFunction function,
      ConvergenceChecker checker,
      int maxIter,
      double x0,
      double f0,
      double x1,
      double f1)
      throws FunctionException;

  /**
   * Returns the abscissa of the last root estimate accepted by this finder.
   *
   * <p>This value is meaningful only after a successful call to {@link
   * #findRoot(ComputableFunction, ConvergenceChecker, int, double, double, double, double)}.
   * Implementations may keep the previous estimate when a search fails, so callers should rely on
   * the boolean return value of {@code findRoot} to decide whether this result is current.
   *
   * @return abscissa of the accepted root estimate from the last successful search
   */
  double getRoot();
}
