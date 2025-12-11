package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.ComputableFunction;

/**
 * Fixed-step Gauss-Legendre quadrature for scalar, single-variable functions.
 *
 * <p>This integrator evaluates {@link ComputableFunction} instances using precomputed
 * Gauss-Legendre abscissas and weights. It is suited to smooth functions over finite intervals when
 * the caller prefers predictable work per step instead of adaptive refinement. Each step samples
 * the function at {@code n} non-uniform interior points and combines the results with matching
 * weights to reach exactness for polynomials up to degree {@code 2n-1}. Boundary values are never
 * probed, allowing integrands that are undefined or poorly behaved at the interval ends.
 *
 * <p>Usage pattern: construct with a minimal point count and a nominal step size, then invoke
 * {@link #integrate(ComputableFunction, double, double)} for each definite integral needed. The
 * integrator adjusts the raw step to divide the interval evenly while preserving orientation when
 * bounds are reversed. Instances are stateless after construction; reuse across calls is safe from
 * a mutability perspective, but thread confinement is recommended unless the wrapped function is
 * itself thread-safe.
 *
 * <ul>
 *   <li>Quadrature rule: Gauss-Legendre of order 2–5 (inclusive) selected from the provided minimum
 *       point count.
 *   <li>Step model: fixed width derived from the requested raw step to tile the interval exactly.
 *   <li>Error behavior: no adaptive control; accuracy depends on function smoothness and point
 *       count.
 * </ul>
 *
 * @version $Id: GaussLegendreIntegrator.java 1231 2002-03-12 20:07:04Z luc $
 * @author L. Maisonobe
 * @see ComputableFunctionIntegrator
 * @see ComputableFunction
 */
public class GaussLegendreIntegrator implements ComputableFunctionIntegrator {
  /**
   * Create an integrator configured with a minimum number of quadrature points and a nominal step.
   *
   * <p>The constructor selects a built-in Gauss-Legendre rule between two and five points, using
   * the smallest available rule whose order is at least {@code minPoints}. The provided {@code
   * rawStep} is treated as a target width; the integrator will later adjust it slightly so that the
   * requested interval can be tiled with an integer number of equal segments. Coefficients and
   * abscissas are precomputed at construction time and reused for all subsequent evaluations,
   * keeping runtime overhead low and deterministic.
   *
   * @param minPoints minimal acceptable number of Gauss-Legendre abscissas; values below two clamp
   *     to the two-point rule, values above five select the five-point rule.
   * @param rawStep preferred absolute step size in integration variable units; will be scaled to an
   *     exact divisor of the requested integration interval during {@link
   *     #integrate(ComputableFunction, double, double)}.
   */
  public GaussLegendreIntegrator(int minPoints, double rawStep) {
    if (minPoints <= 2) {
      weightedRoots =
          new double[][] {
            {1.0, -1.0 / Math.sqrt(3.0)},
            {1.0, 1.0 / Math.sqrt(3.0)}
          };
    } else if (minPoints == 3) {
      weightedRoots =
          new double[][] {
            {5.0 / 9.0, -Math.sqrt(0.6)},
            {8.0 / 9.0, 0.0},
            {5.0 / 9.0, Math.sqrt(0.6)}
          };
    } else if (minPoints == 4) {
      double sqrt30 = Math.sqrt(30.0);
      double positiveTerm = Math.sqrt((15.0 + 2.0 * sqrt30) / 35.0);
      double negativeTerm = Math.sqrt((15.0 - 2.0 * sqrt30) / 35.0);
      weightedRoots =
          new double[][] {
            {(90.0 - 5.0 * Math.sqrt(30.0)) / 180.0, -positiveTerm},
            {(90.0 + 5.0 * Math.sqrt(30.0)) / 180.0, -negativeTerm},
            {(90.0 + 5.0 * Math.sqrt(30.0)) / 180.0, negativeTerm},
            {(90.0 - 5.0 * Math.sqrt(30.0)) / 180.0, positiveTerm}
          };
    } else {
      double sqrt70 = Math.sqrt(70.0);
      double positiveTerm = Math.sqrt((35.0 + 2.0 * sqrt70) / 63.0);
      double negativeTerm = Math.sqrt((35.0 - 2.0 * sqrt70) / 63.0);
      weightedRoots =
          new double[][] {
            {(322.0 - 13.0 * Math.sqrt(70.0)) / 900.0, -positiveTerm},
            {(322.0 + 13.0 * Math.sqrt(70.0)) / 900.0, -negativeTerm},
            {128.0 / 225.0, 0.0},
            {(322.0 + 13.0 * Math.sqrt(70.0)) / 900.0, negativeTerm},
            {(322.0 - 13.0 * Math.sqrt(70.0)) / 900.0, positiveTerm}
          };
    }

    this.rawStep = rawStep;
  }

  /**
   * Number of function evaluations performed on each fixed step.
   *
   * <p>This value equals the selected Gauss-Legendre order and remains constant for the lifetime of
   * the integrator. Callers can use it to estimate total work or to pre-size caches used by the
   * supplied {@link ComputableFunction} implementation.
   *
   * @return count of {@link ComputableFunction#valueAt(double)} invocations per step of integration
   */
  public int getEvaluationsPerStep() {
    return weightedRoots.length;
  }

  /**
   * Compute the oriented definite integral of the supplied function over the closed interval.
   *
   * <p>The method partitions {@code [a, b]} into equal-width segments whose size is derived from
   * the configured raw step. For each segment it evaluates the function at precomputed interior
   * points, scales the results by the Gauss-Legendre weights, and accumulates a running sum. When
   * the bounds are provided in descending order, the algorithm swaps them to preserve mathematical
   * sign consistency. No adaptive refinement or error estimation is performed; accuracy depends on
   * function smoothness, the chosen rule order, and the resulting step width.
   *
   * <pre>{@code
   * ComputableFunction f = x -> Math.sin(x);
   * ComputableFunctionIntegrator integrator = new GaussLegendreIntegrator(3, 0.1);
   * double area = integrator.integrate(f, 0.0, Math.PI);
   * }</pre>
   *
   * @param f computable scalar function evaluated at Gauss-Legendre abscissas; must be
   *     deterministic over the interval and tolerate the number of evaluations implied by the step
   *     count.
   * @param a lower or upper bound of integration in the function's input units; may be greater than
   *     {@code b} to request a negatively oriented integral.
   * @param b upper or lower bound of integration; paired with {@code a} to define the closed
   *     interval over which quadrature is performed.
   * @return weighted sum approximating the definite integral over {@code [a, b]}, preserving sign
   *     when bounds are reversed and using a fixed number of evaluations per step.
   * @throws FunctionException if the supplied function fails to compute a value at any quadrature
   *     point, typically to signal domain errors or internal evaluation issues.
   */
  @Override
  public double integrate(ComputableFunction f, double a, double b) throws FunctionException {

    // swap the bounds if they are not in ascending order
    if (b < a) {
      double tmp = b;
      b = a;
      a = tmp;
    }

    // adjust the step according to the bounds
    long n = Math.round(0.5 + (b - a) / rawStep);
    double step = (b - a) / n;

    // integrate over all elementary steps
    double halfStep = step / 2.0;
    double midPoint = a + halfStep;
    double sum = 0.0;
    for (long i = 0; i < n; ++i) {
      for (double[] weightedRoot : weightedRoots) {
        sum += weightedRoot[0] * f.valueAt(midPoint + halfStep * weightedRoot[1]);
      }
      midPoint += step;
    }

    return halfStep * sum;
  }

  private final double[][] weightedRoots;

  private final double rawStep;
}
