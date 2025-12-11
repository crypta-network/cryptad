package org.spaceroots.mantissa.optimization;

/**
 * Implements the classical Nelder–Mead downhill simplex direct search algorithm.
 *
 * <p>This optimizer explores an {@code n}-dimensional search space using a simplex of {@code n+1}
 * vertices and only evaluates objective values, never gradients. Each iteration reflects, expands,
 * contracts, or shrinks the simplex based on the relative costs of its vertices, steadily steering
 * toward lower objective values. The class is mutable and intended for single-threaded use: create
 * an instance, configure coefficients, then run one of the inherited {@code minimizes(...)} entry
 * points supplied by {@link DirectSearchOptimizer}. Typical usage flows are:
 *
 * <ul>
 *   <li>Choose coefficients (defaults match the original paper) and an initial simplex strategy.
 *   <li>Provide a {@link CostFunction}, maximum evaluation budget, and a {@link
 *       ConvergenceChecker}.
 *   <li>Inspect the returned {@link PointCostPair} or call {@link
 *       DirectSearchOptimizer#getMinima()} to review all starts.
 * </ul>
 *
 * <p>Vertices are sorted by cost after each iteration; convergence checkers can assume index {@code
 * 0} is the current best point. Instances are not thread-safe and should not be reused across
 * concurrent runs. The algorithm is well suited to noisy or non-differentiable objectives but can
 * stagnate on flat regions or when simplex degeneracy occurs; restart strategies in the base class
 * help alleviate these cases.
 *
 * @author Luc Maisonobe
 * @version $Id: NelderMead.java 1709 2006-12-03 21:16:50Z luc $
 * @see MultiDirectional
 */
public class NelderMead extends DirectSearchOptimizer {

  /**
   * Build a Nelder-Mead optimizer with default coefficients.
   *
   * <p>The default coefficients are 1.0 for rho, 2.0 for khi and 0.5 for both gamma and sigma. Use
   * this constructor when you want the canonical Nelder–Mead settings recommended in most
   * literature and do not need to tune the relative aggressiveness of reflection, expansion, or
   * contraction. After construction, hand the instance to one of the {@code minimizes(...)} methods
   * defined in {@link DirectSearchOptimizer}; coefficients are immutable for the life of the
   * instance, so create a new optimizer if you need different values.
   */
  @SuppressWarnings("unused")
  public NelderMead() {
    super();
    this.rho = 1.0;
    this.khi = 2.0;
    this.gamma = 0.5;
    this.sigma = 0.5;
  }

  /**
   * Build a Nelder-Mead optimizer with specified coefficients.
   *
   * <p>This overload lets callers fine-tune the aggressiveness of the search by supplying custom
   * coefficients for each geometric operation. Use it when domain knowledge suggests slower
   * reflection, stronger expansion, or softer shrinkage. Values are treated as immutable weights
   * applied during every iteration, so pass consistent numbers appropriate for the scale of your
   * objective function; negative values are typically nonsensical and should be avoided.
   *
   * @param rho reflection coefficient controlling how far the simplex jumps away from the worst
   *     vertex; use positive values and adjust down to damp oscillations.
   * @param khi expansion coefficient applied after a successful reflection to probe further along
   *     the promising direction; values above {@code 1.0} increase exploratory reach.
   * @param gamma contraction coefficient applied when reflection fails; choose a positive value
   *     below {@code 1.0} to pull the simplex back toward its centroid.
   * @param sigma shrinkage coefficient used during full simplex contraction; a fraction in (0,1)
   *     scales all vertices toward the current best point.
   */
  @SuppressWarnings("unused")
  public NelderMead(double rho, double khi, double gamma, double sigma) {
    super();
    this.rho = rho;
    this.khi = khi;
    this.gamma = gamma;
    this.sigma = sigma;
  }

  /**
   * Compute the next simplex of the algorithm.
   *
   * <p>This template method performs one Nelder–Mead step on the current simplex, applying
   * reflection, expansion, contraction (inside or outside), or shrink operations depending on
   * relative vertex costs. The simplex array is updated and kept sorted from best to worst after
   * any newly evaluated points. Subclasses should not override this behavior; callers trigger
   * iterations indirectly via {@code minimizes(...)} in {@link DirectSearchOptimizer}, which
   * repeatedly invokes this method until a {@link ConvergenceChecker} signals completion or the
   * evaluation budget is exhausted.
   *
   * @throws CostException if the configured {@link CostFunction} refuses to evaluate a candidate
   *     point or returns a value that cannot be produced.
   */
  protected void iterateSimplex() throws CostException {

    // the simplex has n+1 point if dimension is n
    int n = simplex.length - 1;

    double smallest = simplex[0].cost();
    double secondLargest = simplex[n - 1].cost();
    double largest = simplex[n].cost();
    double[] xLargest = simplex[n].point();

    double[] centroid = computeCentroid(n);
    double[] xR = reflect(centroid, xLargest);
    double costR = evaluateCost(xR);

    if ((smallest <= costR) && (costR < secondLargest)) {
      replaceWorstPoint(new PointCostPair(xR, costR));
      return;
    }

    if (costR < smallest) {
      handleExpansion(centroid, xR, costR);
      return;
    }

    if (costR < largest) {
      if (handleOutsideContraction(centroid, xR, costR)) {
        return;
      }
    } else if (handleInsideContraction(centroid, xLargest, largest)) {
      return;
    }

    shrinkSimplex(n);
  }

  private double[] computeCentroid(int n) {
    double[] centroid = new double[n];
    for (int i = 0; i < n; ++i) {
      double[] x = simplex[i].point();
      for (int j = 0; j < n; ++j) {
        centroid[j] += x[j];
      }
    }
    double scaling = 1.0 / n;
    for (int j = 0; j < n; ++j) {
      centroid[j] *= scaling;
    }
    return centroid;
  }

  private double[] reflect(double[] centroid, double[] xLargest) {
    int n = centroid.length;
    double[] xR = new double[n];
    for (int j = 0; j < n; ++j) {
      xR[j] = centroid[j] + rho * (centroid[j] - xLargest[j]);
    }
    return xR;
  }

  private void handleExpansion(double[] centroid, double[] xR, double costR) throws CostException {
    int n = centroid.length;
    double[] xE = new double[n];
    for (int j = 0; j < n; ++j) {
      xE[j] = centroid[j] + khi * (xR[j] - centroid[j]);
    }
    double costE = evaluateCost(xE);

    if (costE < costR) {
      replaceWorstPoint(new PointCostPair(xE, costE));
    } else {
      replaceWorstPoint(new PointCostPair(xR, costR));
    }
  }

  private boolean handleOutsideContraction(double[] centroid, double[] xR, double costR)
      throws CostException {
    int n = centroid.length;
    double[] xC = new double[n];
    for (int j = 0; j < n; ++j) {
      xC[j] = centroid[j] + gamma * (xR[j] - centroid[j]);
    }
    double costC = evaluateCost(xC);
    if (costC <= costR) {
      replaceWorstPoint(new PointCostPair(xC, costC));
      return true;
    }
    return false;
  }

  private boolean handleInsideContraction(double[] centroid, double[] xLargest, double largest)
      throws CostException {
    int n = centroid.length;
    double[] xC = new double[n];
    for (int j = 0; j < n; ++j) {
      xC[j] = centroid[j] - gamma * (centroid[j] - xLargest[j]);
    }
    double costC = evaluateCost(xC);
    if (costC < largest) {
      replaceWorstPoint(new PointCostPair(xC, costC));
      return true;
    }
    return false;
  }

  private void shrinkSimplex(int n) throws CostException {
    double[] xSmallest = simplex[0].point();
    for (int i = 1; i < simplex.length; ++i) {
      double[] x = simplex[i].point();
      for (int j = 0; j < n; ++j) {
        x[j] = xSmallest[j] + sigma * (x[j] - xSmallest[j]);
      }
      simplex[i] = new PointCostPair(x, Double.NaN);
    }
    evaluateSimplex();
  }

  /** Reflection coefficient. */
  private final double rho;

  /** Expansion coefficient. */
  private final double khi;

  /** Contraction coefficient. */
  private final double gamma;

  /** Shrinkage coefficient. */
  private final double sigma;
}
