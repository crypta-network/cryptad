package org.spaceroots.mantissa.roots;

import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.ComputableFunction;

/**
 * Root finder based on Brent’s method for one-dimensional scalar functions.
 *
 * <p>{@code BrentSolver} locates a zero of a {@link ComputableFunction} within a user-provided
 * interval that is known (or assumed) to bracket a root. The implementation follows the classic
 * Brent algorithm: each iteration chooses between bisection and interpolation (secant or inverse
 * quadratic) to guarantee convergence while retaining fast superlinear behavior on smooth
 * functions. Callers typically evaluate the function at both ends of an interval, then invoke
 * {@link #findRoot(ComputableFunction, ConvergenceChecker, int, double, double, double, double)} to
 * advance the search until a {@link ConvergenceChecker} reports convergence or a maximum iteration
 * count is exceeded.
 *
 * <p>The solver is stateful: a successful call to {@code findRoot} stores the last computed root,
 * which can later be retrieved through {@link #getRoot()}. Instances are not thread-safe; if you
 * need to solve multiple problems concurrently, use a separate solver per thread. Apart from the
 * stored root value, the class has no external side effects.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> perform robust bracketing root searches using Brent’s
 *       decision logic and a pluggable convergence policy.
 *   <li><strong>Notable behavior:</strong> falls back to bisection when interpolation steps are
 *       unsafe or stagnating, preserving convergence guarantees.
 * </ul>
 *
 * @see RootsFinder
 * @see ConvergenceChecker
 * @version $Id: BrentSolver.java 1499 2003-03-29 12:50:08Z luc $
 * @author L. Maisonobe
 */
public class BrentSolver implements RootsFinder {

  /** IEEE 754 epsilon. */
  private static final double EPSILON = Math.pow(2.0, -52);

  /** Root found. */
  private double root;

  /**
   * Creates a new solver instance with no previously computed root.
   *
   * <p>The solver starts in an uninitialized state; {@link #getRoot()} will return {@link
   * Double#NaN} until a call to {@link #findRoot(ComputableFunction, ConvergenceChecker, int,
   * double, double, double, double)} succeeds. A single instance may be reused across multiple root
   * searches, but it should not be shared across threads without external synchronization.
   */
  public BrentSolver() {
    root = Double.NaN;
  }

  private static final class State {
    double a;
    double fa;
    double b;
    double fb;
    double c;
    double fc;
    double d;
    double e;

    State(double x0, double f0, double x1, double f1) {
      a = x0;
      fa = f0;
      b = x1;
      fb = f1;
      c = a;
      fc = fa;
      d = b - a;
      e = d;
    }
  }

  /**
   * Searches for a root inside a bracketing interval using Brent’s algorithm.
   *
   * <p>This method assumes that {@code x0} and {@code x1} bound an interval that contains at least
   * one root, i.e. the function values are of opposite signs or another bracketing condition is
   * satisfied by the caller. The algorithm iteratively refines the bracket, selecting interpolation
   * steps when they appear safe and sufficiently progress-making, and otherwise falling back to
   * bisection. On success, the best root estimate is stored in this instance and may be read via
   * {@link #getRoot()}.
   *
   * <p>The convergence policy is delegated to {@code checker}. The solver also treats tiny function
   * values or a bracket width below a machine-scaled tolerance as converged. If the maximum
   * iteration count is reached without convergence, the root value is left at the last iterate and
   * the method returns {@code false}.
   *
   * @param function function to evaluate; should be continuous on the interval for guarantees.
   * @param checker convergence checker that decides when the bracket is acceptable.
   * @param maxIter maximum number of iterations to perform before giving up.
   * @param x0 lower bound of the initial bracketing interval, in x-units.
   * @param f0 precomputed {@code function.valueAt(x0)} for efficiency and consistency.
   * @param x1 upper bound of the initial bracketing interval, in x-units.
   * @param f1 precomputed {@code function.valueAt(x1)} for efficiency and consistency.
   * @return {@code true} when a root satisfying {@code checker} is found; {@code false} otherwise.
   * @throws FunctionException if {@code function.valueAt(...)} fails during evaluation.
   */
  @Override
  public boolean findRoot(
      ComputableFunction function,
      ConvergenceChecker checker,
      int maxIter,
      double x0,
      double f0,
      double x1,
      double f1)
      throws FunctionException {

    State state = new State(x0, f0, x1, f1);
    for (int iter = 0; iter < maxIter; ++iter) {

      invertPointsIfNeeded(state);

      double tolS = 2 * EPSILON * Math.abs(state.b);
      double xm = 0.5 * (state.c - state.b);

      if (tryConverge(state, checker, tolS, xm)) {
        return true;
      }

      updateStep(state, tolS, xm);
      completeStep(state, function, tolS, xm);
    }

    // we have exceeded the maximal number of iterations
    return false;
  }

  @SuppressWarnings("UnnecessaryLocalVariable")
  private static void invertPointsIfNeeded(State state) {
    if (Math.abs(state.fc) < Math.abs(state.fb)) {
      double aNew = state.b;
      double bNew = state.c;
      double cNew = aNew;
      double faNew = state.fb;
      double fbNew = state.fc;
      double fcNew = faNew;

      state.a = aNew;
      state.b = bNew;
      state.c = cNew;
      state.fa = faNew;
      state.fb = fbNew;
      state.fc = fcNew;
    }
  }

  private boolean tryConverge(State state, ConvergenceChecker checker, double tolS, double xm) {
    // convergence test
    double xLow;
    double fLow;
    double xHigh;
    double fHigh;
    if (state.b < state.c) {
      xLow = state.b;
      fLow = state.fb;
      xHigh = state.c;
      fHigh = state.fc;
    } else {
      xLow = state.c;
      fLow = state.fc;
      xHigh = state.b;
      fHigh = state.fb;
    }

    int status = checker.converged(xLow, fLow, xHigh, fHigh);
    if (status == ConvergenceChecker.LOW) {
      root = xLow;
      return true;
    }
    if (status == ConvergenceChecker.HIGH) {
      root = xHigh;
      return true;
    }

    if ((Math.abs(xm) < tolS) || (Math.abs(state.fb) < Double.MIN_VALUE)) {
      root = state.b;
      return true;
    }

    return false;
  }

  private static void updateStep(State state, double tolS, double xm) {
    if ((Math.abs(state.e) < tolS) || (Math.abs(state.fa) <= Math.abs(state.fb))) {
      // use bisection method
      state.d = xm;
      state.e = state.d;
      return;
    }

    // use secant method
    double p;
    double q;
    double r;
    double s = state.fb / state.fa;
    if (Math.abs(state.a - state.c) < EPSILON * Math.max(Math.abs(state.a), Math.abs(state.c))) {
      // linear interpolation using only b and c points
      p = 2.0 * xm * s;
      q = 1.0 - s;
    } else {
      // inverse quadratic interpolation using a, b and c points
      q = state.fa / state.fc;
      r = state.fb / state.fc;
      p = s * (2.0 * xm * q * (q - r) - (state.b - state.a) * (r - 1.0));
      q = (q - 1.0) * (r - 1.0) * (s - 1.0);
    }

    // signs adjustment
    if (p > 0.0) {
      q = -q;
    } else {
      p = -p;
    }

    // is interpolation acceptable ?
    if (((2.0 * p) < (3.0 * xm * q - Math.abs(tolS * q))) && (p < Math.abs(0.5 * state.e * q))) {
      state.e = state.d;
      state.d = p / q;
    } else {
      // no, we need to fall back to bisection
      state.d = xm;
      state.e = state.d;
    }
  }

  private static void completeStep(State state, ComputableFunction function, double tolS, double xm)
      throws FunctionException {
    // complete step
    state.a = state.b;
    state.fa = state.fb;
    double step = state.d;
    if (Math.abs(step) <= tolS) {
      step = xm > 0.0 ? tolS : -tolS;
    }
    state.b += step;
    state.fb = function.valueAt(state.b);

    if (state.fb * state.fc > 0) {
      state.c = state.a;
      state.fc = state.fa;
      state.d = state.b - state.a;
      state.e = state.d;
    }
  }

  /**
   * Returns the abscissa of the most recently computed root.
   *
   * <p>After a successful call to {@link #findRoot(ComputableFunction, ConvergenceChecker, int,
   * double, double, double, double)}, this value is the solver’s best estimate of a root within the
   * last bracketing interval. If no successful solve has been performed yet, the method returns
   * {@link Double#NaN}. The returned value is a snapshot of internal state and does not update
   * unless {@code findRoot} is invoked again.
   *
   * @return last computed root abscissa, or {@link Double#NaN} if none is available.
   */
  @Override
  public double getRoot() {
    return root;
  }
}
