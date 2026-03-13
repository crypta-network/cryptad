package org.spaceroots.mantissa.roots;

/**
 * Strategy interface used by root-finding algorithms to decide when an iteration has converged.
 *
 * <p>Implementations evaluate the current bracketing interval and return a small integer flag
 * indicating whether the algorithm should continue or stop. The interval is described by the
 * abscissae of its lower and upper bounds and by the corresponding function values. A typical call
 * pattern is that a solver invokes {@link #converged(double, double, double, double)} at the end of
 * each iteration once it has ensured the interval still brackets a root, and terminates when the
 * returned indicator is not {@link #NONE}.
 *
 * <p>The convergence criteria are inherently problem-dependent. Some implementations may rely on
 * interval width, on the magnitude of the function values at the bounds, or on a mix of absolute
 * and relative tolerances. Implementations are expected to be side-effect free and inexpensive
 * because they can be called frequently. Unless stated otherwise by a particular implementation,
 * instances are immutable and therefore safe to share between solvers and threads.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> interpret solver state and report convergence.
 *   <li><strong>Notable behavior:</strong> distinguishes convergence at lower vs upper bounds.
 * </ul>
 *
 * @version $Id: ConvergenceChecker.java 1499 2003-03-29 12:50:08Z luc $
 * @author L. Maisonobe
 */
public interface ConvergenceChecker {

  /**
   * Indicator meaning the solver has not yet converged.
   *
   * <p>Returned from {@link #converged(double, double, double, double)} when the provided interval
   * does not satisfy the implementation's stopping criteria. Solvers should treat this value as a
   * request to continue iterating.
   */
  int NONE = 0;

  /**
   * Indicator meaning convergence is achieved at the lower bound of the interval.
   *
   * <p>Returned when the implementation considers the lower endpoint {@code xLow} to be an
   * acceptable approximation of the root. The distinction from {@link #HIGH} allows solvers to
   * preserve information about which endpoint met the criteria.
   */
  int LOW = 1;

  /**
   * Indicator meaning convergence is achieved at the upper bound of the interval.
   *
   * <p>Returned when the implementation considers the upper endpoint {@code xHigh} to be an
   * acceptable approximation of the root. This value mirrors {@link #LOW} for the opposite
   * endpoint.
   */
  int HIGH = 2;

  /**
   * Checks whether the solver should stop based on the current bracketing interval.
   *
   * <p>The interval defined by the arguments is assumed to bracket a root. Implementations examine
   * the interval endpoints and their function values to decide if convergence has been reached. If
   * convergence is detected, the returned indicator identifies which endpoint should be taken as
   * the root approximation. If convergence is not detected, {@link #NONE} is returned. This method
   * must not modify solver state and should be deterministic for a given set of arguments.
   *
   * @param xLow abscissa of the lower bound of the interval, in solver units
   * @param fLow function value at the lower bound, typically matching {@code f(xLow)}
   * @param xHigh abscissa of the upper bound of the interval, in solver units
   * @param fHigh function value at the upper bound, typically matching {@code f(xHigh)}
   * @return convergence indicator: {@link #NONE} to continue, or {@link #LOW}/{@link #HIGH} to stop
   */
  int converged(double xLow, double fLow, double xHigh, double fHigh);
}
