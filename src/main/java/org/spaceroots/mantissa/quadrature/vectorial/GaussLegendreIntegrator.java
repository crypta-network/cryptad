package org.spaceroots.mantissa.quadrature.vectorial;

import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.ComputableFunction;

/**
 * Gauss-Legendre quadrature for vector-valued functions over finite intervals.
 *
 * <p>This integrator applies precomputed Gauss-Legendre nodes and weights to approximate the
 * definite integral of a {@link ComputableFunction} without sampling the integrand at interval
 * endpoints. Clients configure the number of quadrature points and a nominal step size, and the
 * integrator automatically tiles the user-specified bounds into equal sub-intervals, evaluating the
 * function only at interior abscissas that maximize accuracy for smooth inputs. The algorithm is
 * deterministic, stateless between invocations, and produces identical results given the same
 * function, bounds, and step settings.
 *
 * <p>Typical usage is to create one instance for a chosen accuracy/cost trade-off, then call {@link
 * #integrate(ComputableFunction, double, double)} for each integral. The implementation swaps
 * bounds when they are provided in descending order and scales the weights by the actual step width
 * to keep the quadrature exact for polynomials up to order {@code 2n - 1}.
 *
 * <ul>
 *   <li>Evaluates only interior Gauss-Legendre points; endpoints are never sampled.
 *   <li>Adjusts the raw step to an integer number of segments across {@code [a, b]}.
 *   <li>Works with vector outputs; each component is integrated independently.
 * </ul>
 *
 * @see ComputableFunctionIntegrator
 * @see ComputableFunction
 * @version $Id: GaussLegendreIntegrator.java 1231 2002-03-12 20:07:04Z luc $
 * @author L. Maisonobe
 */
public class GaussLegendreIntegrator implements ComputableFunctionIntegrator {
  /**
   * Create a Gauss-Legendre integrator with a desired quadrature order and nominal step size.
   *
   * <p>The constructor precomputes the roots and weights of the Legendre polynomial of degree
   * {@code minPoints}, selecting a set of abscissas inside {@code [-1, 1]} and their associated
   * coefficients so that polynomials up to degree {@code 2n - 1} are integrated exactly. The
   * resulting rule is later scaled and translated to each sub-interval of the user-specified range.
   * Choosing a larger number of points increases accuracy but also raises the number of function
   * evaluations performed per step. The {@code rawStep} value sets the target width of each
   * sub-interval; it is slightly adjusted so an integer number of steps spans the integration
   * bounds.
   *
   * <pre>{@code
   * // Construct a 5-point integrator with ~0.1 width steps
   * GaussLegendreIntegrator integrator = new GaussLegendreIntegrator(5, 0.1);
   * }</pre>
   *
   * @param minPoints minimal quadrature points to use; must be at least 3 for adaptive roots
   * @param rawStep target integration step width; must be positive and is rescaled to fit the range
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
      double legendreRootA = Math.sqrt((15.0 + 2.0 * Math.sqrt(30.0)) / 35.0);
      double legendreRootB = Math.sqrt((15.0 - 2.0 * Math.sqrt(30.0)) / 35.0);
      weightedRoots =
          new double[][] {
            {(90.0 - 5.0 * Math.sqrt(30.0)) / 180.0, -legendreRootA},
            {(90.0 + 5.0 * Math.sqrt(30.0)) / 180.0, -legendreRootB},
            {(90.0 + 5.0 * Math.sqrt(30.0)) / 180.0, legendreRootB},
            {(90.0 - 5.0 * Math.sqrt(30.0)) / 180.0, legendreRootA}
          };
    } else {
      double legendreRootC = Math.sqrt((35.0 + 2.0 * Math.sqrt(70.0)) / 63.0);
      double legendreRootD = Math.sqrt((35.0 - 2.0 * Math.sqrt(70.0)) / 63.0);
      weightedRoots =
          new double[][] {
            {(322.0 - 13.0 * Math.sqrt(70.0)) / 900.0, -legendreRootC},
            {(322.0 + 13.0 * Math.sqrt(70.0)) / 900.0, -legendreRootD},
            {128.0 / 225.0, 0.0},
            {(322.0 + 13.0 * Math.sqrt(70.0)) / 900.0, legendreRootD},
            {(322.0 - 13.0 * Math.sqrt(70.0)) / 900.0, legendreRootC}
          };
    }

    this.rawStep = rawStep;
  }

  /**
   * Get the number of functions evaluation per step.
   *
   * @return number of interior quadrature evaluations performed for every integration sub-interval
   */
  public int getEvaluationsPerStep() {
    return weightedRoots.length;
  }

  /**
   * Integrate a vector-valued function over a closed interval using fixed-size Gauss-Legendre
   * steps.
   *
   * <p>The method partitions the range {@code [a, b]} into equal segments close to {@code rawStep}
   * and evaluates the supplied {@link ComputableFunction} at the precomputed nodes inside each
   * segment. The orientation of the integral is preserved: if {@code a > b} the computation is
   * performed over {@code [b, a]} and the final vector is negated to follow standard calculus
   * conventions. The returned vector contains one integrated component per function dimension and
   * scales linearly with the number of evaluations. The integrator is deterministic and thread-safe
   * when the provided function is itself thread-safe.
   *
   * @param f vector-valued integrand; must accept points inside each interior sub-interval node
   * @param a lower integration bound, inclusive if {@code a <= b}, otherwise swapped with {@code b}
   * @param b upper integration bound, inclusive if {@code b >= a}, otherwise swapped with {@code a}
   * @return integrated vector where each element accumulates the corresponding component of {@code
   *     f}; array length equals {@code f.getDimension()}
   * @throws FunctionException if the integrand fails to evaluate at any requested abscissa
   */
  @Override
  public double[] integrate(ComputableFunction f, double a, double b) throws FunctionException {

    int orientation = 1;
    // swap the integration bounds if they are not in ascending order and remember orientation
    if (b < a) {
      orientation = -1;
      double tmp = b;
      b = a;
      a = tmp;
    }

    // adjust the integration step according to the bounds
    long n = Math.round(0.5 + (b - a) / rawStep);
    double step = (b - a) / n;

    // integrate over all elementary steps
    double halfStep = step / 2.0;
    double midPoint = a + halfStep;

    double[] sum = new double[f.getDimension()];

    for (long i = 0; i < n; ++i) {
      for (double[] weightedRoot : weightedRoots) {
        double[] value = f.valueAt(midPoint + halfStep * weightedRoot[1]);
        for (int k = 0; k < sum.length; ++k) {
          sum[k] += weightedRoot[0] * value[k];
        }
      }
      midPoint += step;
    }

    for (int k = 0; k < sum.length; ++k) {
      sum[k] *= halfStep;
    }

    if (orientation < 0) {
      for (int k = 0; k < sum.length; ++k) {
        sum[k] = -sum[k];
      }
    }

    return sum;
  }

  double[][] weightedRoots;

  double rawStep;
}
