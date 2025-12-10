package org.spaceroots.mantissa.optimization;

import java.util.Arrays;
import java.util.Comparator;
import org.spaceroots.mantissa.random.CorrelatedRandomVectorGenerator;
import org.spaceroots.mantissa.random.NotPositiveDefiniteMatrixException;
import org.spaceroots.mantissa.random.RandomVectorGenerator;
import org.spaceroots.mantissa.random.UncorrelatedRandomVectorGenerator;
import org.spaceroots.mantissa.random.UniformRandomGenerator;
import org.spaceroots.mantissa.random.VectorialSampleStatistics;

/**
 * Base support for simplex-based direct search optimization algorithms.
 *
 * <p>This helper wires common tasks such as constructing initial simplices, tracking multi-start
 * restarts, counting function evaluations, and sorting candidate vertices. Concrete subclasses (for
 * example {@link NelderMead} or {@link MultiDirectional}) only have to implement the simplex update
 * strategy while inheriting all scaffolding for evaluating cost functions and managing convergence.
 * Direct search methods consume only objective values and avoid derivative estimates, which makes
 * them suitable for noisy targets, discontinuous responses, and models where derivatives are either
 * unavailable or too expensive to evaluate.
 *
 * <p>Typical use follows a short lifecycle: build or supply a simplex, select single-start or
 * multi-start execution, run {@code minimizes(...)} until convergence, then inspect the best point
 * or all collected minima. Instances are mutable but not thread-safe; each optimizer should be used
 * by a single thread at a time and discarded or reconfigured between independent runs.
 *
 * <ul>
 *   <li>Supports deterministic simplices (boxes) or randomized generators for restart points.
 *   <li>Counts evaluations so callers can enforce budgets via {@code maxEvaluations}.
 *   <li>Retains per-start outcomes, enabling diagnostics of stalled runs and local minima.
 * </ul>
 *
 * @author Luc Maisonobe
 * @version $Id: DirectSearchOptimizer.java 1709 2006-12-03 21:16:50Z luc $
 * @see CostFunction
 * @see NelderMead
 * @see MultiDirectional
 */
public abstract class DirectSearchOptimizer {

  /** Simple constructor. */
  protected DirectSearchOptimizer() {}

  /**
   * Minimizes a cost function starting from the edges of an axis-aligned box.
   *
   * <p>This convenience overload constructs a simplex whose vertices lie on the path that walks the
   * edges between {@code vertexA} and {@code vertexB}. The resulting shape mirrors a regular
   * simplex scaled independently along each coordinate using the projected separation of the two
   * supplied corners. The optimizer runs in single-start mode and stops at the first convergence or
   * when the evaluation budget is exhausted.
   *
   * @param f cost function evaluated for every candidate point; must be side-effect free or
   *     tolerant to repeated calls
   * @param maxEvaluations maximum number of cost evaluations allowed for this run; the final count
   *     may slightly exceed the limit because complete simplices are assessed as atomic steps
   * @param checker strategy that inspects the sorted simplex to decide when convergence has been
   *     reached
   * @param vertexA first box corner used to seed the simplex; array length defines the search
   *     dimension and values are interpreted as coordinates
   * @param vertexB opposite box corner; each coordinate provides the scaling factor relative to
   *     {@code vertexA}
   * @return point/cost pair representing the best vertex at convergence for this single start
   * @throws CostException if the cost function signals a failure while being evaluated
   * @throws NoConvergenceException if the optimizer could not satisfy the checker before the
   *     evaluation budget was exceeded
   */
  @SuppressWarnings("unused")
  public PointCostPair minimizes(
      CostFunction f,
      int maxEvaluations,
      ConvergenceChecker checker,
      double[] vertexA,
      double[] vertexB)
      throws CostException, NoConvergenceException {

    // set up optimizer
    buildSimplex(vertexA, vertexB);
    setSingleStart();

    // compute minimum
    return minimizes(f, maxEvaluations, checker);
  }

  /**
   * Minimizes a cost function using multi-start exploration of a box-derived simplex.
   *
   * <p>The initial simplex mirrors {@link #minimizes(CostFunction, int, ConvergenceChecker,
   * double[], double[])} but restarts the search up to {@code starts} times. Each restart draws a
   * new simplex from a Gaussian generator centered in the provided box with per-axis standard
   * deviations matching half the box width. This increases the chances of escaping poor local
   * minima and provides diagnostics across independent trajectories.
   *
   * @param f cost function evaluated at every candidate vertex; should be deterministic for
   *     meaningful comparisons
   * @param maxEvaluations maximum number of cost evaluations permitted per start; final usage may
   *     exceed the limit by at most the simplex size because evaluations are grouped
   * @param checker strategy that inspects the current simplex ordering to decide when the search
   *     has converged
   * @param vertexA first corner of the axis-aligned box used to scale and place the simplex
   * @param vertexB opposite corner of the box; must have the same dimension as {@code vertexA}
   * @param starts number of independent starts to attempt; values below two fall back to
   *     single-start operation
   * @param seed optional 32-bit seed array used to initialize the restart random generator; when
   *     {@code null}, the generator is seeded from the current time
   * @return best point/cost pair observed across all starts, sorted by ascending cost
   * @throws CostException if evaluating the cost function fails for any candidate point
   * @throws NoConvergenceException if every attempted start exhausts the evaluation budget without
   *     satisfying the convergence checker
   */
  @SuppressWarnings("unused")
  public PointCostPair minimizes(
      CostFunction f,
      int maxEvaluations,
      ConvergenceChecker checker,
      double[] vertexA,
      double[] vertexB,
      int starts,
      int[] seed)
      throws CostException, NoConvergenceException {

    // set up the simplex traveling around the box
    buildSimplex(vertexA, vertexB);

    // we consider the simplex could have been produced by a generator
    // having its mean value at the center of the box, the standard
    // deviation along each axe being the corresponding half size
    double[] mean = new double[vertexA.length];
    double[] standardDeviation = new double[vertexA.length];
    for (int i = 0; i < vertexA.length; ++i) {
      mean[i] = 0.5 * (vertexA[i] + vertexB[i]);
      standardDeviation[i] = 0.5 * Math.abs(vertexA[i] - vertexB[i]);
    }

    RandomVectorGenerator rvg =
        new UncorrelatedRandomVectorGenerator(
            mean, standardDeviation, new UniformRandomGenerator(seed));
    setMultiStart(starts, rvg);

    // compute minimum
    return minimizes(f, maxEvaluations, checker);
  }

  /**
   * Minimizes a cost function from an explicitly provided simplex in single-start mode.
   *
   * <p>Callers supply all simplex vertices, allowing deterministic reproducibility and advanced
   * seeding strategies. The simplex is evaluated once, then iterated using the subclass-defined
   * rule until the convergence checker signals completion or the evaluation limit is reached.
   *
   * @param f cost function invoked for each vertex as needed; should tolerate ordering differences
   *     during sorting
   * @param maxEvaluations maximum number of cost evaluations permitted; batches covering the whole
   *     simplex can cause a slight overrun relative to this cap
   * @param checker convergence logic that inspects the ordered simplex and determines when to stop
   * @param vertices complete simplex vertices; array length must be {@code n + 1} for an {@code
   *     n}-dimensional search space
   * @return point/cost pair representing the best vertex when the single run ends
   * @throws CostException if evaluating {@code f} fails for any supplied vertex
   * @throws NoConvergenceException if convergence is not reached before the evaluation budget is
   *     consumed
   */
  @SuppressWarnings("unused")
  public PointCostPair minimizes(
      CostFunction f, int maxEvaluations, ConvergenceChecker checker, double[][] vertices)
      throws CostException, NoConvergenceException {

    // set up optimizer
    buildSimplex(vertices);
    setSingleStart();

    // compute minimum
    return minimizes(f, maxEvaluations, checker);
  }

  /**
   * Minimizes a cost function from an explicit simplex with optional multi-start restarts.
   *
   * <p>The supplied simplex is analyzed to compute its mean and covariance, which seed a correlated
   * Gaussian generator used to build fresh simplices on each restart. This preserves the caller's
   * initial geometry while enabling exploration around it. Each start is capped by the supplied
   * evaluation budget and judged by the provided convergence checker.
   *
   * @param f cost function invoked for every vertex; should be stable under repeated sampling near
   *     the same point
   * @param maxEvaluations maximum number of cost evaluations per start; full-simplex evaluations
   *     can make the realized total exceed the nominal limit by up to {@code n + 1}
   * @param checker component that inspects the ordered simplex after each iteration to decide
   *     whether convergence has been achieved
   * @param vertices complete set of simplex vertices defining the initial search region; length
   *     must match the dimensionality plus one
   * @param starts number of independent starts to attempt; values under two disable multi-start and
   *     reuse the initial simplex only
   * @param seed optional 32-bit seed array for the correlated generator; {@code null} selects a
   *     time-based seed
   * @return best point/cost pair found across the performed starts in ascending cost order
   * @throws NotPositiveDefiniteMatrixException if the covariance derived from {@code vertices} is
   *     singular or ill-conditioned
   * @throws CostException if the cost function cannot be evaluated for a candidate vertex
   * @throws NoConvergenceException if all starts exhaust their budgets without satisfying the
   *     convergence checker
   */
  @SuppressWarnings("unused")
  public PointCostPair minimizes(
      CostFunction f,
      int maxEvaluations,
      ConvergenceChecker checker,
      double[][] vertices,
      int starts,
      int[] seed)
      throws NotPositiveDefiniteMatrixException, CostException, NoConvergenceException {

    // store the points into the simplex
    buildSimplex(vertices);

    // compute the statistical properties of the simplex points
    VectorialSampleStatistics statistics = new VectorialSampleStatistics();
    for (double[] vertex : vertices) {
      statistics.add(vertex);
    }

    RandomVectorGenerator rvg =
        new CorrelatedRandomVectorGenerator(
            statistics.getMean(),
            statistics.getCovarianceMatrix(null),
            new UniformRandomGenerator(seed));
    setMultiStart(starts, rvg);

    // compute minimum
    return minimizes(f, maxEvaluations, checker);
  }

  /**
   * Minimizes a cost function using a randomly generated simplex in single-start mode.
   *
   * <p>The first vector produced by {@code generator} defines the search dimension and becomes the
   * first simplex vertex; subsequent draws populate the remaining vertices. This variant is useful
   * when callers want stochastic seeding while delegating restart control to the optimizer.
   *
   * @param f cost function evaluated at each vertex; should be robust to random sampling near the
   *     same region
   * @param maxEvaluations maximum number of cost evaluations to perform before aborting the start;
   *     the final tally can exceed the target by up to the simplex size
   * @param checker convergence policy executed after every simplex iteration to decide whether the
   *     search has settled
   * @param generator source of candidate vertices; must always return vectors of identical length
   * @return best point/cost pair reached during the single randomized start
   * @throws CostException if evaluating {@code f} fails for any generated vertex
   * @throws NoConvergenceException if convergence is not detected before the evaluation limit is
   *     hit
   */
  @SuppressWarnings("unused")
  public PointCostPair minimizes(
      CostFunction f,
      int maxEvaluations,
      ConvergenceChecker checker,
      RandomVectorGenerator generator)
      throws CostException, NoConvergenceException {

    // set up optimizer
    buildSimplex(generator);
    setSingleStart();

    // compute minimum
    return minimizes(f, maxEvaluations, checker);
  }

  /**
   * Minimizes a cost function using randomized simplices across multiple starts.
   *
   * <p>Each start draws {@code n + 1} vectors from {@code generator} to form a new simplex and runs
   * until the convergence checker fires or the per-start evaluation limit is reached. This is
   * helpful when the landscape contains many local minima and randomized re-seeding improves
   * coverage of the search space.
   *
   * @param f cost function applied to every candidate point; should yield comparable values across
   *     randomized starts
   * @param maxEvaluations maximum number of evaluations allowed per start; complete simplex passes
   *     can slightly exceed this target
   * @param checker component that inspects the ordered simplex and decides when the algorithm has
   *     converged
   * @param generator random vector generator that must produce consistently sized vectors across
   *     calls
   * @param starts number of independent randomized starts; values below two revert to single-start
   *     behavior without additional random draws
   * @return lowest-cost point/cost pair discovered after sorting the outcomes from all starts
   * @throws CostException if any evaluation of the cost function fails
   * @throws NoConvergenceException if every start exceeds the evaluation cap without satisfying the
   *     convergence checker
   */
  @SuppressWarnings("unused")
  public PointCostPair minimizes(
      CostFunction f,
      int maxEvaluations,
      ConvergenceChecker checker,
      RandomVectorGenerator generator,
      int starts)
      throws CostException, NoConvergenceException {

    // set up optimizer
    buildSimplex(generator);
    setMultiStart(starts, generator);

    // compute minimum
    return minimizes(f, maxEvaluations, checker);
  }

  /**
   * Build a simplex from two extreme vertices.
   *
   * <p>The two vertices are considered to represent two opposite vertices of a box parallel to the
   * canonical axes of the space. The simplex is the subset of vertices encountered while going from
   * vertexA to vertexB traveling along the box edges only. This can be seen as a scaled regular
   * simplex using the projected separation between the given points as the scaling factor along
   * each coordinate axis.
   *
   * @param vertexA first vertex
   * @param vertexB last vertex
   */
  private void buildSimplex(double[] vertexA, double[] vertexB) {

    int n = vertexA.length;
    simplex = new PointCostPair[n + 1];

    // set up the simplex traveling around the box
    for (int i = 0; i <= n; ++i) {
      double[] vertex = new double[n];
      if (i > 0) {
        System.arraycopy(vertexB, 0, vertex, 0, i);
      }
      if (i < n) {
        System.arraycopy(vertexA, i, vertex, i, n - i);
      }
      simplex[i] = new PointCostPair(vertex, Double.NaN);
    }
  }

  /**
   * Build a simplex from all its points.
   *
   * @param vertices array containing all vertices of the simplex
   */
  private void buildSimplex(double[][] vertices) {
    int n = vertices.length - 1;
    simplex = new PointCostPair[n + 1];
    for (int i = 0; i <= n; ++i) {
      simplex[i] = new PointCostPair(vertices[i], Double.NaN);
    }
  }

  /**
   * Build a simplex randomly.
   *
   * @param generator random vector generator
   */
  private void buildSimplex(RandomVectorGenerator generator) {

    // use first vector size to compute the number of points
    double[] vertex = generator.nextVector();
    int n = vertex.length;
    simplex = new PointCostPair[n + 1];
    simplex[0] = new PointCostPair(vertex, Double.NaN);

    // fill up the vertex
    for (int i = 1; i <= n; ++i) {
      simplex[i] = new PointCostPair(generator.nextVector(), Double.NaN);
    }
  }

  /** Set up single-start mode. */
  private void setSingleStart() {
    starts = 1;
    generator = null;
    minima = null;
  }

  /**
   * Set up multi-start mode with the provided generator.
   *
   * <p>Calling this method replaces any previous start configuration. When {@code starts} is less
   * than two the optimizer falls back to single-start mode and clears the generator reference. The
   * caller retains control of generator state and seeding.
   *
   * @param starts number of starts to perform, including the first run; values under two disable
   *     additional restarts
   * @param generator random vector generator used to create fresh simplices between starts; ignored
   *     when single-start fallback is activated
   */
  public void setMultiStart(int starts, RandomVectorGenerator generator) {
    if (starts < 2) {
      this.starts = 1;
      this.generator = null;
    } else {
      this.starts = starts;
      this.generator = generator;
    }
    minima = null;
  }

  /**
   * Get all minima recorded during the last call to {@code minimizes(...)}.
   *
   * <p>The returned array contains one entry per start, sorted from lowest to highest cost for
   * converged runs, followed by {@code null} entries for starts that exhausted their evaluation
   * budgets. In single-start mode the array contains one element. The array is a shallow clone so
   * callers can examine results without mutating optimizer state.
   *
   * @return ordered minima from the previous optimization run, or {@code null} if {@code minimizes}
   *     has not been executed yet
   */
  @SuppressWarnings("unused")
  public PointCostPair[] getMinima() {
    return minima == null ? null : minima.clone();
  }

  /**
   * Core minimization loop shared by all public overloads.
   *
   * <p>This method assumes the simplex and start configuration have already been prepared. It
   * executes each start by iterating the simplex until the convergence checker succeeds or the
   * evaluation cap is reached. Results for every start are retained and sorted before the best one
   * is returned.
   *
   * @param f cost function applied to candidate points; must be thread-compatible with sequential
   *     invocation from this optimizer
   * @param maxEvaluations maximum number of cost function calls allowed per start; full simplex
   *     evaluation steps can raise the observed total slightly above the limit
   * @param checker convergence logic used after each simplex iteration to detect completion
   * @return lowest-cost point/cost pair found across all starts after sorting outcomes
   * @throws CostException if evaluating the cost function fails
   * @throws NoConvergenceException if every attempted start stops because of the evaluation cap
   */
  private PointCostPair minimizes(CostFunction f, int maxEvaluations, ConvergenceChecker checker)
      throws CostException, NoConvergenceException {

    this.f = f;
    minima = new PointCostPair[starts];

    // multi-start loop
    for (int i = 0; i < starts; ++i) {

      evaluations = 0;
      evaluateSimplex();

      boolean finished = false;
      while (!finished) {
        if (checker.converged(simplex)) {
          // we have found a minimum
          minima[i] = simplex[0];
          finished = true;
        } else if (evaluations >= maxEvaluations) {
          // this start did not converge, try a new one
          minima[i] = null;
          finished = true;
        } else {
          iterateSimplex();
        }
      }

      if (i < (starts - 1)) {
        // restart
        buildSimplex(generator);
      }
    }

    // sort the minima from the lowest cost to the highest cost, followed by
    // null elements
    Arrays.sort(minima, pointCostPairComparator);

    // return the found point given the lowest cost
    if (minima[0] == null) {
      throw new NoConvergenceException(
          "none of the {0} start points" + " lead to convergence",
          new String[] {Integer.toString(starts)});
    }
    return minima[0];
  }

  /**
   * Compute the next simplex of the algorithm.
   *
   * <p>Implementations update {@link #simplex} in-place by producing a new set of vertices ordered
   * by ascending cost. Typical strategies include reflection, expansion, contraction, or shrink
   * steps. This method is invoked repeatedly until a convergence checker signals completion or the
   * evaluation budget is exceeded.
   *
   * @throws CostException if evaluating newly generated vertices fails or is refused by the cost
   *     function
   */
  protected abstract void iterateSimplex() throws CostException;

  /**
   * Evaluate the cost on one point.
   *
   * <p>A side effect of this method is to count the number of function evaluations.
   *
   * @param x point on which the cost function should be evaluated; must have the same dimension as
   *     the simplex points
   * @return cost at the given point as reported by the configured {@link CostFunction}
   * @throws CostException if no cost can be computed for the parameters
   */
  protected double evaluateCost(double[] x) throws CostException {
    evaluations++;
    return f.cost(x);
  }

  /**
   * Evaluate all the non-evaluated points of the simplex.
   *
   * <p>Only vertices whose cost is {@link Double#NaN} are evaluated. The simplex is resorted in
   * ascending order after evaluation so that index {@code 0} always holds the current best point.
   *
   * @throws CostException if no cost can be computed for the parameters
   */
  protected void evaluateSimplex() throws CostException {

    // evaluate the cost at all non-evaluated simplex points
    for (int i = 0; i < simplex.length; ++i) {
      PointCostPair pair = simplex[i];
      if (Double.isNaN(pair.cost)) {
        simplex[i] = new PointCostPair(pair.point, evaluateCost(pair.point));
      }
    }

    // sort the simplex from the lowest cost to the highest cost
    Arrays.sort(simplex, pointCostPairComparator);
  }

  /**
   * Replace the worst point of the simplex by a new point.
   *
   * <p>The new point is inserted in cost order, pushing former points toward the end of the array
   * and placing the worst point at the last position. Callers must ensure the provided point has
   * already been evaluated.
   *
   * @param pointCostPair point to insert; its {@code cost} field must be a valid numeric value
   */
  protected void replaceWorstPoint(PointCostPair pointCostPair) {
    int n = simplex.length - 1;
    for (int i = 0; i < n; ++i) {
      if (simplex[i].cost > pointCostPair.cost) {
        PointCostPair tmp = simplex[i];
        simplex[i] = pointCostPair;
        pointCostPair = tmp;
      }
    }
    simplex[n] = pointCostPair;
  }

  /** Comparator for {@link PointCostPair PointCostPair} objects. */
  private static final Comparator<PointCostPair> pointCostPairComparator =
      (o1, o2) -> {
        if (o1 == null) {
          return (o2 == null) ? 0 : 1;
        } else if (o2 == null) {
          return -1;
        }
        return Double.compare(o1.cost, o2.cost);
      };

  /**
   * Simplex currently processed by the optimizer.
   *
   * <p>The array length is always {@code n + 1} for an {@code n}-dimensional problem and remains
   * sorted in ascending cost order after each call to {@link #evaluateSimplex()} or {@link
   * #iterateSimplex()}. Subclasses may mutate elements in-place but should preserve the ordering
   * contract expected by convergence checkers.
   */
  protected PointCostPair[] simplex;

  /** Cost function. */
  private CostFunction f;

  /** Number of evaluations already performed. */
  private int evaluations;

  /** Number of starts to go. */
  private int starts;

  /** Random generator for multi-start. */
  private RandomVectorGenerator generator;

  /** Found minima. */
  private PointCostPair[] minima;
}
