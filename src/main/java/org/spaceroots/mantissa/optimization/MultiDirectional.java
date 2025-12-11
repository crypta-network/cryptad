package org.spaceroots.mantissa.optimization;

/**
 * Direct-search optimizer that applies the multi-directional simplex scheme.
 *
 * <p>The algorithm extends the classic Nelder–Mead approach with an explicit expansion step that
 * probes the search space in the reflected direction before deciding whether to keep the reflected
 * or expanded simplex. It is derivative-free and therefore well suited to discontinuous, noisy, or
 * expensive objectives where gradients are unavailable. Typical usage involves configuring the
 * expansion {@code khi} and contraction {@code gamma} coefficients, seeding a simplex via the
 * helper methods in {@link DirectSearchOptimizer}, and repeatedly iterating until a {@link
 * ConvergenceChecker convergence checker} reports completion. Instances are mutable and intended
 * for single-threaded use; create separate instances for concurrent searches.
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Each iteration first reflects the simplex through its best point and may expand further if
 *       the reflection improved the cost.
 *   <li>If neither reflection nor expansion helps, the simplex is contracted toward the best
 *       vertex.
 *   <li>All evaluation and bookkeeping logic is inherited from {@link DirectSearchOptimizer},
 *       including multi-start support and evaluation counting.
 * </ul>
 *
 * @author Luc Maisonobe
 * @version $Id: MultiDirectional.java 1709 2006-12-03 21:16:50Z luc $
 * @see NelderMead
 * @see DirectSearchOptimizer
 */
public class MultiDirectional extends DirectSearchOptimizer {

  /**
   * Build a multi-directional optimizer with default coefficients.
   *
   * <p>The default values are 2.0 for {@code khi} (expansion factor) and 0.5 for {@code gamma}
   * (contraction factor). Use this constructor when the standard balance between exploration and
   * contraction is acceptable and no tuning data is available.
   */
  @SuppressWarnings("unused")
  public MultiDirectional() {
    super();
    this.khi = 2.0;
    this.gamma = 0.5;
  }

  /**
   * Build a multi-directional optimizer with specified coefficients.
   *
   * <p>Choose {@code khi} greater than 1.0 to push the simplex outward after a successful
   * reflection, and {@code gamma} between 0 and 1.0 to shrink the simplex toward its best vertex
   * when reflection fails. Both coefficients remain constant for the lifetime of the optimizer
   * instance.
   *
   * @param khi expansion coefficient used when an expanded simplex is attempted; must be positive
   *     and typically greater than 1.0
   * @param gamma contraction coefficient applied when reflection does not improve the cost; should
   *     be in (0, 1] to reduce simplex size without inversion
   */
  @SuppressWarnings("unused")
  public MultiDirectional(double khi, double gamma) {
    super();
    this.khi = khi;
    this.gamma = gamma;
  }

  /**
   * Compute the next simplex of the algorithm.
   *
   * <p>The step follows three phases: reflect the simplex through its best vertex, possibly expand
   * further in the same direction when reflection improves the cost, or contract toward the best
   * point when reflection does not help. The method updates {@link #simplex} in-place and relies on
   * {@link #evaluateSimplex()} to assign costs to newly generated vertices before sorting them.
   *
   * @throws CostException if the underlying cost function rejects evaluation for any generated
   *     vertex in the reflected, expanded, or contracted simplices
   */
  protected void iterateSimplex() throws CostException {

    while (true) {

      // save the original vertex
      PointCostPair[] original = simplex;
      double originalCost = original[0].cost;

      // perform a reflection step
      double reflectedCost = evaluateNewSimplex(original, 1.0);
      if (reflectedCost < originalCost) {

        // compute the expanded simplex
        PointCostPair[] reflected = simplex;
        double expandedCost = evaluateNewSimplex(original, khi);
        if (reflectedCost <= expandedCost) {
          // accept the reflected simplex
          simplex = reflected;
        }

        return;
      }

      // compute the contracted simplex
      double contractedCost = evaluateNewSimplex(original, gamma);
      if (contractedCost < originalCost) {
        // accept the contracted simplex
        return;
      }
    }
  }

  /**
   * Compute and evaluate a new simplex produced by linear transformation.
   *
   * <p>The method keeps the current best point fixed and projects every other vertex along the line
   * through that point using the supplied scalar coefficient. A coefficient of {@code 1.0} yields a
   * reflection, values above one expand, and values in (0, 1) contract. The original simplex array
   * is left untouched; {@link #simplex} is replaced with the transformed copy.
   *
   * @param original original simplex that supplies geometry and cost ordering; must contain {@code
   *     n + 1} vertices for an {@code n}-dimensional search
   * @param coeff linear coefficient applied to the displacement from the best vertex toward each
   *     remaining vertex; negative values mirror the simplex
   * @return smallest cost found in the transformed simplex after evaluation and resorting
   * @exception CostException if the cost function fails on any transformed vertex during evaluation
   */
  private double evaluateNewSimplex(PointCostPair[] original, double coeff) throws CostException {

    double[] xSmallest = original[0].point;
    int n = xSmallest.length;

    // create the linearly transformed simplex
    simplex = new PointCostPair[n + 1];
    simplex[0] = original[0];
    for (int i = 1; i <= n; ++i) {
      double[] xOriginal = original[i].point;
      double[] xTransformed = new double[n];
      for (int j = 0; j < n; ++j) {
        xTransformed[j] = xSmallest[j] + coeff * (xSmallest[j] - xOriginal[j]);
      }
      simplex[i] = new PointCostPair(xTransformed, Double.NaN);
    }

    // evaluate it
    evaluateSimplex();
    return simplex[0].cost;
  }

  /** Expansion coefficient. */
  private final double khi;

  /** Contraction coefficient. */
  private final double gamma;
}
