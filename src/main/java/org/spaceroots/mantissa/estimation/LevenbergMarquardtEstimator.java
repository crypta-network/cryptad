package org.spaceroots.mantissa.estimation;

import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import org.jetbrains.annotations.NotNull;

/**
 * Levenberg-Marquardt implementation for weighted nonlinear least-squares problems.
 *
 * <p>This estimator wraps a trust-region variant of the classical Levenberg-Marquardt algorithm as
 * translated from MINPACK's {@code lmder}. Clients configure step-size and convergence tolerances,
 * provide an {@link EstimationProblem}, and invoke {@link #estimate(EstimationProblem)} to mutate
 * the supplied {@link EstimatedParameter} instances until the weighted residual norm cannot be
 * reduced further. The implementation supports over-determined systems by discarding the least
 * influential columns (measured by Jacobian norms), while keeping the QR decomposition rank aware.
 *
 * <p>The solver is stateful and not thread-safe: create a fresh instance per concurrent solution. A
 * typical call sequence is:
 *
 * <ul>
 *   <li>Construct the estimator, optionally overriding default tolerances.
 *   <li>Populate measurements and parameters inside an {@code EstimationProblem}.
 *   <li>Call {@link #estimate(EstimationProblem)}; afterward inspect {@link #getCostEvaluations()}
 *       and {@link #getJacobianEvaluations()}.
 * </ul>
 *
 * <p>Numerical behavior mirrors MINPACK closely: damping is adjusted to balance Gauss-Newton and
 * gradient-descent steps; orthogonality, parameter relative change, and cost relative change govern
 * termination. No internal synchronization is performed, and the class mutates the parameter
 * objects supplied by the problem, so callers should copy inputs when reuse is required.
 *
 * <p><strong>MINPACK copyright notice (1999) University of Chicago. All rights reserved.</strong>
 * Redistribution of this translated work follows the original conditions:
 *
 * <ul>
 *   <li>Source redistributions must retain the copyright notice, conditions, and disclaimer.
 *   <li>Binary redistributions must reproduce the same notices in accompanying materials.
 *   <li>End-user documentation must acknowledge “This product includes software developed by the
 *       University of Chicago, as Operator of Argonne National Laboratory,” unless such credit
 *       already appears in customary locations.
 *   <li><strong>Warranty disclaimer:</strong> the software is provided “as is” without any express
 *       or implied warranties, including merchantability, fitness, title, or non-infringement.
 *   <li><strong>Limitation of liability:</strong> the copyright holder and contributing agencies
 *       are not liable for direct or indirect damages, including lost profits or data, even if
 *       advised of the possibility.
 * </ul>
 *
 * @author Argonne National Laboratory. MINPACK project. March 1980 (original fortran)
 * @author Burton S. Garbow (original fortran)
 * @author Kenneth E. Hillstrom (original fortran)
 * @author Jorge J. More (original fortran)
 * @author Luc Maisonobe (Java translation)
 * @see EstimationProblem
 * @see EstimatedParameter
 */
public class LevenbergMarquardtEstimator implements Serializable, Estimator {

  /**
   * Create an estimator with conservative, convergence-friendly defaults.
   *
   * <p>The constructor seeds all trust-region and tolerance settings with values that favor
   * stability over speed. These defaults mirror the upstream MINPACK recommendations and should be
   * suitable for most small to medium non-linear least-squares problems. Callers may override any
   * parameter through the corresponding setter before invoking {@link #estimate(EstimationProblem)}
   * to match the conditioning and noise level of their data. Instances are reusable across multiple
   * problems but hold mutable state, so allocate a new estimator for concurrent runs.
   *
   * <p>The default values are:
   *
   * <ul>
   *   <li>{@link #setInitialStepBoundFactor initial step bound factor}: 100.0
   *   <li>{@link #setMaxCostEval maximal cost evaluations}: 1000
   *   <li>{@link #setCostRelativeTolerance cost relative tolerance}: 1.0e-10
   *   <li>{@link #setParRelativeTolerance parameters relative tolerance}: 1.0e-10
   *   <li>{@link #setOrthoTolerance orthogonality tolerance}: 1.0e-10
   * </ul>
   */
  public LevenbergMarquardtEstimator() {
    // default values for the tuning parameters
    setInitialStepBoundFactor(100.0);
    setMaxCostEval(1000);
    setCostRelativeTolerance(1.0e-10);
    setParRelativeTolerance(1.0e-10);
    setOrthoTolerance(1.0e-10);
  }

  /**
   * Set the scaling applied to the initial trust-region radius.
   *
   * <p>The first Levenberg-Marquardt step bound is computed as {@code factor * ||diag * x||} when
   * the weighted parameters have a non-zero norm, or simply {@code factor} when all starting values
   * are zero. Larger factors encourage exploratory steps; smaller factors constrain the initial
   * move and can help ill-conditioned or highly non-linear problems. MINPACK recommends values
   * between 0.1 and 100, with 100 remaining the historical default.
   *
   * @param initialStepBoundFactor initial step scaling factor, positive, typically between 0.1 and
   *     100
   * @see #estimate(EstimationProblem)
   */
  public void setInitialStepBoundFactor(double initialStepBoundFactor) {
    this.initialStepBoundFactor = initialStepBoundFactor;
  }

  /**
   * Set an upper bound on objective function evaluations.
   *
   * <p>The algorithm counts every call used to compute residuals and their weighted norm. When the
   * counter reaches this limit, {@link #estimate(EstimationProblem)} aborts with an {@link
   * EstimationException}. Increase the value when working with large systems or loose tolerances
   * and decrease it to force faster failure on divergent models.
   *
   * @param maxCostEval maximal number of cost evaluations permitted before aborting the solving
   * @see #estimate(EstimationProblem)
   */
  public void setMaxCostEval(int maxCostEval) {
    this.maxCostEval = maxCostEval;
  }

  /**
   * Set the stopping threshold on relative change of the cost.
   *
   * <p>Iterations halt when the actual and predicted reductions in the weighted sum of squared
   * residuals both fall below this tolerance (scaled by the current cost). Tight values demand more
   * precise fits but can trigger numerical noise; relaxed values allow earlier termination.
   *
   * @param costRelativeTolerance desired relative error on summed squares, positive and near
   *     machine precision
   * @see #estimate(EstimationProblem)
   */
  public void setCostRelativeTolerance(double costRelativeTolerance) {
    this.costRelativeTolerance = costRelativeTolerance;
  }

  /**
   * Set the stopping threshold on relative parameter changes.
   *
   * <p>When the trust-region radius shrinks below this tolerance multiplied by the current
   * parameter norm, the algorithm considers the solution stable and stops. Use smaller values to
   * chase tighter parameter accuracy, or larger values to accept coarser solutions and reduce
   * runtime.
   *
   * @param parRelativeTolerance desired relative error on parameters, positive and typically small
   * @see #estimate(EstimationProblem)
   */
  public void setParRelativeTolerance(double parRelativeTolerance) {
    this.parRelativeTolerance = parRelativeTolerance;
  }

  /**
   * Set the maximum acceptable cosine between the residual vector and the Jacobian columns.
   *
   * <p>The value controls the orthogonality termination criterion: when the gradient is nearly
   * orthogonal to the residuals, further iterations are unlikely to reduce the cost. Values close
   * to zero demand strong orthogonality; larger values tolerate less alignment and may stop
   * earlier.
   *
   * @param orthoTolerance desired max cosine between residuals and Jacobian columns, usually small
   *     and positive
   * @see #estimate(EstimationProblem)
   */
  public void setOrthoTolerance(double orthoTolerance) {
    this.orthoTolerance = orthoTolerance;
  }

  /**
   * Get the number of cost evaluations performed in the current solution.
   *
   * <p>The counter resets to zero each time {@link #estimate(EstimationProblem)} starts and
   * increases every time weighted residuals are recomputed. It is useful for diagnostics and to
   * confirm whether a stop was triggered by {@link #setMaxCostEval(int)}.
   *
   * @return count of cost function evaluations executed since the last call to {@code estimate}
   */
  public int getCostEvaluations() {
    return costEvaluations;
  }

  /**
   * Get the number of Jacobian evaluations performed in the current solution.
   *
   * <p>The counter resets to zero when {@link #estimate(EstimationProblem)} begins and increments
   * each time the Jacobian matrix is rebuilt. Expensive models can use this to monitor derivative
   * cost or to tune evaluation limits.
   *
   * @return count of Jacobian evaluations executed since the last call to {@code estimate}
   */
  public int getJacobianEvaluations() {
    return jacobianEvaluations;
  }

  private static final class IterationState {
    private double delta;
    private double xNorm;
    private boolean firstIteration = true;
  }

  private static final class LmWorkArrays {
    private final double[] work1;
    private final double[] work2;
    private final double[] work3;

    private LmWorkArrays(double[] work1, double[] work2, double[] work3) {
      this.work1 = work1;
      this.work2 = work2;
      this.work3 = work3;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (!(obj instanceof LmWorkArrays arrays)) {
        return false;
      }
      return Arrays.equals(work1, arrays.work1)
          && Arrays.equals(work2, arrays.work2)
          && Arrays.equals(work3, arrays.work3);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(work1);
      result = 31 * result + Arrays.hashCode(work2);
      result = 31 * result + Arrays.hashCode(work3);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "LmWorkArrays[work1="
          + Arrays.toString(work1)
          + ", work2="
          + Arrays.toString(work2)
          + ", work3="
          + Arrays.toString(work3)
          + "]";
    }
  }

  private static final class IterationWorkspace {
    private final double[] diag;
    private final double[] oldX;
    private final LmWorkArrays workArrays;

    private IterationWorkspace(double[] diag, double[] oldX, LmWorkArrays workArrays) {
      this.diag = diag;
      this.oldX = oldX;
      this.workArrays = workArrays;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (!(obj instanceof IterationWorkspace workspace)) {
        return false;
      }
      return Arrays.equals(diag, workspace.diag)
          && Arrays.equals(oldX, workspace.oldX)
          && workArrays.equals(workspace.workArrays);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(diag);
      result = 31 * result + Arrays.hashCode(oldX);
      result = 31 * result + workArrays.hashCode();
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "IterationWorkspace[diag="
          + Arrays.toString(diag)
          + ", oldX="
          + Arrays.toString(oldX)
          + ", workArrays="
          + workArrays
          + "]";
    }
  }

  private static final class LmParameterContext {
    private final double[] qy;
    private final double delta;
    private final double[] diag;
    private final LmWorkArrays workArrays;

    private LmParameterContext(double[] qy, double delta, double[] diag, LmWorkArrays workArrays) {
      this.qy = qy;
      this.delta = delta;
      this.diag = diag;
      this.workArrays = workArrays;
    }

    @Override
    public boolean equals(Object obj) {
      if (this == obj) {
        return true;
      }
      if (!(obj instanceof LmParameterContext context)) {
        return false;
      }
      return Double.compare(delta, context.delta) == 0
          && Arrays.equals(qy, context.qy)
          && Arrays.equals(diag, context.diag)
          && workArrays.equals(context.workArrays);
    }

    @Override
    public int hashCode() {
      int result = Arrays.hashCode(qy);
      result = 31 * result + Double.hashCode(delta);
      result = 31 * result + Arrays.hashCode(diag);
      result = 31 * result + workArrays.hashCode();
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "LmParameterContext[qy="
          + Arrays.toString(qy)
          + ", delta="
          + delta
          + ", diag="
          + Arrays.toString(diag)
          + ", workArrays="
          + workArrays
          + "]";
    }
  }

  /** Update the jacobian matrix. */
  private void updateJacobian() {
    ++jacobianEvaluations;
    Arrays.fill(jacobian, 0);
    for (int i = 0; i < rows; i++) {
      WeightedMeasurement wm = measurements[i];
      double factor = -Math.sqrt(wm.getWeight());
      int rowStart = i * cols;
      for (int j = 0; j < cols; ++j) {
        jacobian[rowStart + j] = factor * wm.getPartial(parameters[j]);
      }
    }
  }

  /** Update the residuals array and cost function value. */
  private void updateResidualsAndCost() {
    ++costEvaluations;
    cost = 0;
    for (int i = 0; i < rows; i++) {
      WeightedMeasurement wm = measurements[i];
      double residual = wm.getResidual();
      residuals[i] = Math.sqrt(wm.getWeight()) * residual;
      cost += wm.getWeight() * residual * residual;
    }
    cost = Math.sqrt(cost);
  }

  /**
   * Compute the root-mean-square (RMS) of the weighted residuals for a problem.
   *
   * <p>The RMS equals {@code sqrt(sum(weight_i * residual_i^2) / n)} where {@code n} is the number
   * of measurements. It mirrors the criterion minimized by the estimator, scaled by the number of
   * observations, and can be used to compare fit quality across problems with different sizes.
   *
   * @param problem estimation problem providing weighted residuals; must not be {@code null}
   * @return non-negative RMS of the current residuals, computed without altering the estimator
   */
  @Override
  public double getRMS(EstimationProblem problem) {
    WeightedMeasurement[] wm = problem.getMeasurements();
    double criterion = 0;
    for (WeightedMeasurement weightedMeasurement : wm) {
      double residual = weightedMeasurement.getResidual();
      criterion += weightedMeasurement.getWeight() * residual * residual;
    }
    return Math.sqrt(criterion / wm.length);
  }

  /**
   * Solve an {@link EstimationProblem} using the MINPACK-style Levenberg-Marquardt routine.
   *
   * <p>The method mutates the {@link EstimatedParameter} instances owned by the supplied problem in
   * place, iteratively updating them until the trust-region criteria signal convergence or a
   * termination condition is met. It balances Gauss-Newton and gradient-descent behavior through a
   * dynamically adjusted damping factor, employs QR with column pivoting to handle rank deficiency,
   * and stops when any of the configured tolerances indicate diminishing returns. Over-determined
   * systems are supported by truncating low-impact columns while preserving consistent cost and
   * gradient calculations.
   *
   * <p>Typical usage:
   *
   * <pre>{@code
   * LevenbergMarquardtEstimator solver = new LevenbergMarquardtEstimator();
   * solver.setMaxCostEval(2000);
   * solver.estimate(problem);
   * double rms = solver.getRMS(problem);
   * }</pre>
   *
   * <p>The authors of the original Fortran function are Argonne National Laboratory (MINPACK, March
   * 1980), Burton S. Garbow, Kenneth E. Hillstrom, and Jorge J. More. Luc Maisonobe produced the
   * Java translation on which this implementation is based.
   *
   * @param problem estimation problem with measurements and initial parameter guesses; never null
   * @throws EstimationException if convergence fails, evaluations exceed limits, or the system
   *     violates solver assumptions
   * @see #setInitialStepBoundFactor(double)
   * @see #setMaxCostEval(int)
   * @see #setCostRelativeTolerance(double)
   * @see #setParRelativeTolerance(double)
   * @see #setOrthoTolerance(double)
   */
  @Override
  public void estimate(EstimationProblem problem) throws EstimationException {

    // retrieve the equations and the parameters
    measurements = problem.getMeasurements();
    parameters = problem.getUnboundParameters();

    // arrays shared with the other private methods
    rows = measurements.length;
    cols = parameters.length;
    solvedCols = Math.min(rows, cols);
    jacobian = new double[rows * cols];
    diagR = new double[cols];
    jacNorm = new double[cols];
    beta = new double[cols];
    permutation = new int[cols];
    lmDir = new double[cols];
    residuals = new double[rows];

    // local variables
    double delta = 0;
    double xNorm = 0;
    double[] diag = new double[cols];
    double[] oldX = new double[cols];
    double[] oldRes = new double[rows];
    LmWorkArrays workArrays =
        new LmWorkArrays(new double[cols], new double[cols], new double[cols]);
    IterationWorkspace workspace = new IterationWorkspace(diag, oldX, workArrays);

    // evaluate the function at the starting point and calculate its norm
    updateResidualsAndCost();

    lmPar = 0;
    costEvaluations = 0;
    jacobianEvaluations = 0;
    IterationState state = new IterationState();
    state.delta = delta;
    state.xNorm = xNorm;

    runOuterIterations(workspace, oldRes, state);
  }

  private void runOuterIterations(
      IterationWorkspace workspace, double[] oldRes, IterationState state)
      throws EstimationException {
    double[] diag = workspace.diag;
    double[] oldX = workspace.oldX;
    LmWorkArrays workArrays = workspace.workArrays;
    while (costEvaluations < maxCostEval) {
      prepareJacobian();
      if (state.firstIteration) {
        initializeScale(diag, state);
      }

      double maxCosine = computeMaxCosine();
      if (isOrthogonal(maxCosine)) {
        return;
      }

      rescaleDiagonal(diag);
      InnerLoopResult result = performInnerLoop(diag, oldX, oldRes, workArrays, state, maxCosine);
      oldRes = result.oldResiduals;
      if (result.converged) {
        return;
      }
    }

    throw new EstimationException(
        "maximal number of evaluations exceeded ({0})",
        new String[] {Integer.toString(maxCostEval)});
  }

  private void prepareJacobian() {
    updateJacobian();
    qrDecomposition();
    qTy(residuals);
    for (int k = 0; k < solvedCols; ++k) {
      int pk = permutation[k];
      jacobian[k * cols + pk] = diagR[pk];
    }
  }

  private void initializeScale(double[] diag, IterationState state) {
    state.xNorm = 0;
    for (int k = 0; k < cols; ++k) {
      double dk = jacNorm[k];
      if (dk == 0) {
        dk = 1.0;
      }
      double xk = dk * parameters[k].getEstimate();
      state.xNorm += xk * xk;
      diag[k] = dk;
    }
    state.xNorm = Math.sqrt(state.xNorm);
    state.delta =
        (state.xNorm == 0) ? initialStepBoundFactor : (initialStepBoundFactor * state.xNorm);
  }

  private double computeMaxCosine() {
    double maxCosine = 0;
    if (cost != 0) {
      for (int j = 0; j < solvedCols; ++j) {
        int pj = permutation[j];
        double s = jacNorm[pj];
        if (s != 0) {
          double sum = 0;
          for (int i = 0, index = pj; i <= j; ++i, index += cols) {
            sum += jacobian[index] * residuals[i];
          }
          maxCosine = Math.max(maxCosine, Math.abs(sum) / (s * cost));
        }
      }
    }
    return maxCosine;
  }

  private boolean isOrthogonal(double maxCosine) {
    return maxCosine <= orthoTolerance;
  }

  private void rescaleDiagonal(double[] diag) {
    for (int j = 0; j < cols; ++j) {
      diag[j] = Math.max(diag[j], jacNorm[j]);
    }
  }

  private InnerLoopResult performInnerLoop(
      double[] diag,
      double[] oldX,
      double[] oldRes,
      LmWorkArrays workArrays,
      IterationState state,
      double maxCosine)
      throws EstimationException {
    double[] work1 = workArrays.work1;
    double ratio = 0;
    double[] localOldRes = oldRes;
    while (ratio < 1.0e-4) {
      saveCurrentPoint(oldX);
      double previousCost = cost;
      double[] tmpVec = residuals;
      residuals = localOldRes;
      localOldRes = tmpVec;

      determineLMParameter(new LmParameterContext(localOldRes, state.delta, diag, workArrays));

      double lmNorm = computeLmNorm(diag, oldX);
      adjustDeltaOnFirstIteration(state, lmNorm);

      updateResidualsAndCost();

      double actRed = computeActualReduction(previousCost);
      PredictedReduction predicted = computeScaledPredictedReduction(previousCost, work1, lmNorm);
      ratio = predicted.preRed == 0 ? 0 : (actRed / predicted.preRed);

      updateStepBound(state, lmNorm, ratio, actRed, predicted.dirDer, previousCost);

      if (ratio >= 1.0e-4) {
        updateNorm(state, diag);
      } else {
        localOldRes = rollbackIteration(oldX, localOldRes, previousCost);
      }

      if (hasConverged(actRed, predicted.preRed, ratio, state)) {
        return new InnerLoopResult(true, localOldRes);
      }
      if (handleTightTolerances(state, maxCosine, actRed, predicted.preRed, ratio)) {
        return new InnerLoopResult(false, localOldRes);
      }
    }
    return new InnerLoopResult(false, localOldRes);
  }

  private void saveCurrentPoint(double[] oldX) {
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      oldX[pj] = parameters[pj].getEstimate();
    }
  }

  private double computeLmNorm(double[] diag, double[] oldX) {
    double lmNorm = 0;
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      lmDir[pj] = -lmDir[pj];
      parameters[pj].setEstimate(oldX[pj] + lmDir[pj]);
      double s = diag[pj] * lmDir[pj];
      lmNorm += s * s;
    }
    return Math.sqrt(lmNorm);
  }

  private void adjustDeltaOnFirstIteration(IterationState state, double lmNorm) {
    if (state.firstIteration) {
      state.delta = Math.min(state.delta, lmNorm);
    }
  }

  private double computeActualReduction(double previousCost) {
    if (0.1 * cost >= previousCost) {
      return -1.0;
    }
    double r = cost / previousCost;
    return 1.0 - r * r;
  }

  private PredictedReduction computeScaledPredictedReduction(
      double previousCost, double[] work1, double lmNorm) {
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      double dirJ = lmDir[pj];
      work1[j] = 0;
      for (int i = 0, index = pj; i <= j; ++i, index += cols) {
        work1[i] += jacobian[index] * dirJ;
      }
    }
    double coeff1 = 0;
    for (int j = 0; j < solvedCols; ++j) {
      coeff1 += work1[j] * work1[j];
    }
    double pc2 = previousCost * previousCost;
    coeff1 = coeff1 / pc2;
    double coeff2 = lmPar * lmNorm * lmNorm / pc2;
    double preRed = coeff1 + 2 * coeff2;
    double dirDer = -(coeff1 + coeff2);
    return new PredictedReduction(preRed, dirDer);
  }

  private void updateStepBound(
      IterationState state,
      double lmNorm,
      double ratio,
      double actRed,
      double dirDer,
      double previousCost) {
    if (ratio <= 0.25) {
      double tmp = (actRed < 0) ? (0.5 * dirDer / (dirDer + 0.5 * actRed)) : 0.5;
      if ((0.1 * cost >= previousCost) || (tmp < 0.1)) {
        tmp = 0.1;
      }
      state.delta = tmp * Math.min(state.delta, 10.0 * lmNorm);
      lmPar /= tmp;
    } else if ((lmPar == 0) || (ratio >= 0.75)) {
      state.delta = 2 * lmNorm;
      lmPar *= 0.5;
    }
  }

  private void updateNorm(IterationState state, double[] diag) {
    state.firstIteration = false;
    state.xNorm = 0;
    for (int k = 0; k < cols; ++k) {
      double xK = diag[k] * parameters[k].getEstimate();
      state.xNorm += xK * xK;
    }
    state.xNorm = Math.sqrt(state.xNorm);
  }

  private double[] rollbackIteration(double[] oldX, double[] oldRes, double previousCost) {
    cost = previousCost;
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      parameters[pj].setEstimate(oldX[pj]);
    }
    double[] tmpVec = residuals;
    residuals = oldRes;
    return tmpVec;
  }

  private boolean hasConverged(double actRed, double preRed, double ratio, IterationState state) {
    return ((Math.abs(actRed) <= costRelativeTolerance)
            && (preRed <= costRelativeTolerance)
            && (ratio <= 2.0))
        || (state.delta <= parRelativeTolerance * state.xNorm);
  }

  private boolean handleTightTolerances(
      IterationState state, double maxCosine, double actRed, double preRed, double ratio)
      throws EstimationException {
    if (costEvaluations >= maxCostEval) {
      return true;
    }
    if ((Math.abs(actRed) <= 2.2204e-16) && (preRed <= 2.2204e-16) && (ratio <= 2.0)) {
      throw new EstimationException(
          "cost relative tolerance is too small ({0}),"
              + " no further reduction in the"
              + " sum of squares is possible",
          new String[] {Double.toString(costRelativeTolerance)});
    }
    if (state.delta <= 2.2204e-16 * state.xNorm) {
      throw new EstimationException(
          "parameters relative tolerance is too small"
              + " ({0}), no further improvement in"
              + " the approximate solution is possible",
          new String[] {Double.toString(parRelativeTolerance)});
    }
    if (maxCosine <= 2.2204e-16) {
      throw new EstimationException(
          "orthogonality tolerance is too small ({0})," + " solution is orthogonal to the jacobian",
          new String[] {Double.toString(orthoTolerance)});
    }
    return false;
  }

  private static final class ParameterBounds {
    private double parl;
    private double paru;
    private double gNorm;
  }

  private static final class ColumnSelection {
    private final int columnIndex;
    private final double norm2;

    private ColumnSelection(int columnIndex, double norm2) {
      this.columnIndex = columnIndex;
      this.norm2 = norm2;
    }
  }

  private static final class PredictedReduction {
    private final double preRed;
    private final double dirDer;

    private PredictedReduction(double preRed, double dirDer) {
      this.preRed = preRed;
      this.dirDer = dirDer;
    }
  }

  private static final class InnerLoopResult {
    private final boolean converged;
    private final double[] oldResiduals;

    private InnerLoopResult(boolean converged, double[] oldResiduals) {
      this.converged = converged;
      this.oldResiduals = oldResiduals;
    }
  }

  /**
   * Determine the Levenberg-Marquardt parameter.
   *
   * <p>This implementation is a translation in Java of the MINPACK <a
   * href="http://www.netlib.org/minpack/lmpar.f">lmpar</a> routine.
   *
   * <p>This method sets the lmPar and lmDir attributes.
   *
   * <p>The authors of the original fortran function are:
   *
   * <ul>
   *   <li>Argonne National Laboratory. MINPACK project. March 1980
   *   <li>Burton S. Garbow
   *   <li>Kenneth E. Hillstrom
   *   <li>Jorge J. More
   * </ul>
   *
   * <p>Luc Maisonobe did the Java translation.
   *
   * @param context aggregated qTy, delta, diagonal matrix, and work arrays
   */
  private void determineLMParameter(LmParameterContext context) {
    double[] qy = context.qy;
    double delta = context.delta;
    double[] diag = context.diag;
    LmWorkArrays workArrays = context.workArrays;

    computeGaussNewtonDirection(qy);
    double dxNorm = computeDxNorm(diag, workArrays.work1);
    double fp = dxNorm - delta;
    if (fp <= 0.1 * delta) {
      lmPar = 0;
      return;
    }

    ParameterBounds bounds = computeParameterBounds(fp, delta, diag, workArrays.work1, qy, dxNorm);

    lmPar = Math.clamp(lmPar, bounds.parl, bounds.paru);
    if (lmPar == 0) {
      lmPar = bounds.gNorm / dxNorm;
    }

    refineLmParameter(context, bounds, fp);
  }

  private void computeGaussNewtonDirection(double[] qy) {
    for (int j = 0; j < rank; ++j) {
      lmDir[permutation[j]] = qy[j];
    }
    for (int j = rank; j < cols; ++j) {
      lmDir[permutation[j]] = 0;
    }
    for (int k = rank - 1; k >= 0; --k) {
      int pk = permutation[k];
      double ypk = lmDir[pk] / diagR[pk];
      for (int i = 0, index = pk; i < k; ++i, index += cols) {
        lmDir[permutation[i]] -= ypk * jacobian[index];
      }
      lmDir[pk] = ypk;
    }
  }

  private double computeDxNorm(double[] diag, double[] work1) {
    double dxNorm = 0;
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      double s = diag[pj] * lmDir[pj];
      work1[pj] = s;
      dxNorm += s * s;
    }
    return Math.sqrt(dxNorm);
  }

  private ParameterBounds computeParameterBounds(
      double fp, double delta, double[] diag, double[] work1, double[] qy, double dxNorm) {
    ParameterBounds bounds = new ParameterBounds();
    if (rank == solvedCols) {
      for (int j = 0; j < solvedCols; ++j) {
        int pj = permutation[j];
        work1[pj] *= diag[pj] / dxNorm;
      }
      double sum2 = 0;
      for (int j = 0; j < solvedCols; ++j) {
        int pj = permutation[j];
        double sum = 0;
        for (int i = 0, index = pj; i < j; ++i, index += cols) {
          sum += jacobian[index] * work1[permutation[i]];
        }
        double s = (work1[pj] - sum) / diagR[pj];
        work1[pj] = s;
        sum2 += s * s;
      }
      bounds.parl = fp / (delta * sum2);
    }

    double sum2 = 0;
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      double sum = 0;
      for (int i = 0, index = pj; i <= j; ++i, index += cols) {
        sum += jacobian[index] * qy[i];
      }
      sum /= diag[pj];
      sum2 += sum * sum;
    }
    bounds.gNorm = Math.sqrt(sum2);
    bounds.paru = bounds.gNorm / delta;
    if (bounds.paru == 0) {
      bounds.paru = 2.2251e-308 / Math.min(delta, 0.1);
    }
    return bounds;
  }

  private void refineLmParameter(LmParameterContext context, ParameterBounds bounds, double fp) {
    double[] qy = context.qy;
    double delta = context.delta;
    double[] diag = context.diag;
    LmWorkArrays workArrays = context.workArrays;
    double[] work1 = workArrays.work1;
    double[] work2 = workArrays.work2;
    double[] work3 = workArrays.work3;

    double localDxNorm;
    double localFp = fp;
    for (int countdown = 10; countdown >= 0; --countdown) {
      ensurePositiveLmPar(bounds);
      double sPar = Math.sqrt(lmPar);
      prepareScaledDirection(diag, work1, sPar);
      determineLMDirection(qy, work1, work2, work3);

      localDxNorm = computeDxNormForRefinement(diag, work3);
      double previousFP = localFp;
      localFp = localDxNorm - delta;

      if (isFunctionSmallEnough(bounds, delta, localFp, previousFP)) {
        return;
      }

      adjustWorkForCorrection(diag, work1, work2, work3, localDxNorm);
      double correction = computeCorrectionMagnitude(delta, localFp, work1);
      updateParameterBounds(bounds, localFp);
      lmPar = Math.max(bounds.parl, lmPar + correction);
    }
  }

  private void ensurePositiveLmPar(ParameterBounds bounds) {
    if (lmPar == 0) {
      lmPar = Math.max(2.2251e-308, 0.001 * bounds.paru);
    }
  }

  private void prepareScaledDirection(double[] diag, double[] work1, double sPar) {
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      work1[pj] = sPar * diag[pj];
    }
  }

  private double computeDxNormForRefinement(double[] diag, double[] work3) {
    double localDxNorm = 0;
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      double s = diag[pj] * lmDir[pj];
      work3[pj] = s;
      localDxNorm += s * s;
    }
    return Math.sqrt(localDxNorm);
  }

  private boolean isFunctionSmallEnough(
      ParameterBounds bounds, double delta, double localFp, double previousFP) {
    return (Math.abs(localFp) <= 0.1 * delta)
        || ((bounds.parl == 0) && (localFp <= previousFP) && (previousFP < 0));
  }

  private void adjustWorkForCorrection(
      double[] diag, double[] work1, double[] work2, double[] work3, double localDxNorm) {
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      work1[pj] = work3[pj] * diag[pj] / localDxNorm;
    }
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      work1[pj] /= work2[j];
      double tmp = work1[pj];
      for (int i = j + 1; i < solvedCols; ++i) {
        work1[permutation[i]] -= jacobian[i * cols + pj] * tmp;
      }
    }
  }

  private double computeCorrectionMagnitude(double delta, double localFp, double[] work1) {
    double sum2 = 0;
    for (int j = 0; j < solvedCols; ++j) {
      double s = work1[permutation[j]];
      sum2 += s * s;
    }
    return localFp / (delta * sum2);
  }

  private void updateParameterBounds(ParameterBounds bounds, double localFp) {
    if (localFp > 0) {
      bounds.parl = Math.max(bounds.parl, lmPar);
    } else if (localFp < 0) {
      bounds.paru = Math.min(bounds.paru, lmPar);
    }
  }

  /**
   * Solve a*x = b and d*x = 0 in the least squares sense.
   *
   * <p>This implementation is a translation in Java of the MINPACK <a
   * href="http://www.netlib.org/minpack/qrsolv.f">qrsolv</a> routine.
   *
   * <p>This method sets the lmDir and lmDiag attributes.
   *
   * <p>The authors of the original fortran function are:
   *
   * <ul>
   *   <li>Argonne National Laboratory. MINPACK project. March 1980
   *   <li>Burton S. Garbow
   *   <li>Kenneth E. Hillstrom
   *   <li>Jorge J. More
   * </ul>
   *
   * <p>Luc Maisonobe did the Java translation.
   *
   * @param qy array containing qTy
   * @param diag diagonal matrix
   * @param lmDiag diagonal elements associated with lmDir
   * @param work work array
   */
  private void determineLMDirection(double[] qy, double[] diag, double[] lmDiag, double[] work) {
    copyRAndQty(qy, work);
    applyGivensRotations(diag, lmDiag, work);
    int nSing = detectSingularSystem(lmDiag, work);
    if (nSing > 0) {
      solveUpperTriangular(lmDiag, work, nSing);
    }
    permuteDirection(work);
  }

  private void copyRAndQty(double[] qy, double[] work) {
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      for (int i = j + 1; i < solvedCols; ++i) {
        jacobian[i * cols + pj] = jacobian[j * cols + permutation[i]];
      }
      lmDir[j] = diagR[pj];
      work[j] = qy[j];
    }
  }

  private void applyGivensRotations(double[] diag, double[] lmDiag, double[] work) {
    for (int j = 0; j < solvedCols; ++j) {
      int pj = permutation[j];
      prepareLmDiag(diag, lmDiag, j, pj);
      double qtbpj = 0;
      for (int k = j; k < solvedCols; ++k) {
        if (lmDiag[k] != 0) {
          qtbpj = applySingleRotation(lmDiag, work, k, qtbpj);
        }
      }
      int index = j * cols + permutation[j];
      lmDiag[j] = jacobian[index];
      jacobian[index] = lmDir[j];
    }
  }

  private void prepareLmDiag(double[] diag, double[] lmDiag, int j, int pj) {
    double dpj = diag[pj];
    if (dpj != 0) {
      Arrays.fill(lmDiag, j + 1, lmDiag.length, 0);
    }
    lmDiag[j] = dpj;
  }

  private double applySingleRotation(double[] lmDiag, double[] work, int k, double qtbpj) {
    int pk = permutation[k];
    double sin;
    double cos;
    double rkk = jacobian[k * cols + pk];
    if (Math.abs(rkk) < Math.abs(lmDiag[k])) {
      double cotan = rkk / lmDiag[k];
      sin = 1.0 / Math.sqrt(1.0 + cotan * cotan);
      cos = sin * cotan;
    } else {
      double tan = lmDiag[k] / rkk;
      cos = 1.0 / Math.sqrt(1.0 + tan * tan);
      sin = cos * tan;
    }

    jacobian[k * cols + pk] = cos * rkk + sin * lmDiag[k];
    double temp = cos * work[k] + sin * qtbpj;
    qtbpj = -sin * work[k] + cos * qtbpj;
    work[k] = temp;

    for (int i = k + 1; i < solvedCols; ++i) {
      double rik = jacobian[i * cols + pk];
      temp = cos * rik + sin * lmDiag[i];
      lmDiag[i] = -sin * rik + cos * lmDiag[i];
      jacobian[i * cols + pk] = temp;
    }
    return qtbpj;
  }

  private int detectSingularSystem(double[] lmDiag, double[] work) {
    int nSing = solvedCols;
    for (int j = 0; j < solvedCols; ++j) {
      if ((lmDiag[j] == 0) && (nSing == solvedCols)) {
        nSing = j;
      }
      if (nSing < solvedCols) {
        work[j] = 0;
      }
    }
    return nSing;
  }

  private void solveUpperTriangular(double[] lmDiag, double[] work, int nSing) {
    for (int j = nSing - 1; j >= 0; --j) {
      int pj = permutation[j];
      double sum = 0;
      for (int i = j + 1; i < nSing; ++i) {
        sum += jacobian[i * cols + pj] * work[i];
      }
      work[j] = (work[j] - sum) / lmDiag[j];
    }
  }

  private void permuteDirection(double[] work) {
    for (int j = 0; j < lmDir.length; ++j) {
      lmDir[permutation[j]] = work[j];
    }
  }

  /**
   * Decompose a matrix A as A.P = Q.R using Householder transforms.
   *
   * <p>As suggested in the P. Lascaux and R. Theodor book <i>Analyze num&eacute;rique matricielle
   * appliqu&eacute;e &agrave; l'art de l'ing&eacute;nieur</i> (Masson, 1986), instead of
   * representing the Householder transforms with u<sub>k</sub> unit vectors such that:
   *
   * <pre>
   * H<sub>k</sub> = I - 2u<sub>k</sub>.u<sub>k</sub><sup>t</sup>
   * </pre>
   *
   * we use <sub>k</sub> non-unit vectors such that:
   *
   * <pre>
   * H<sub>k</sub> = I - beta<sub>k</sub>v<sub>k</sub>.v<sub>k</sub><sup>t</sup>
   * </pre>
   *
   * Where v<sub>k</sub> = a<sub>k</sub> - alpha<sub>k</sub> e<sub>k</sub>. The beta<sub>k</sub>
   * coefficients are provided upon exit as recomputing them from the v<sub>k</sub> vectors would be
   * costly.
   *
   * <p>This decomposition handles rank deficient cases since the tranformations are performed in
   * non-increasing columns norms order thanks to columns pivoting. The diagonal elements of the R
   * matrix are therefore also in non-increasing absolute values order.
   */
  private void qrDecomposition() {
    initializeColumnNorms();
    for (int k = 0; k < cols; ++k) {
      ColumnSelection selection = selectNextColumn(k);
      if (selection.norm2 == 0) {
        rank = k;
        return;
      }
      pivotPermutation(k, selection.columnIndex);
      performHouseholder(k, permutation[k], selection.norm2);
    }
    rank = solvedCols;
  }

  private void initializeColumnNorms() {
    for (int k = 0; k < cols; ++k) {
      permutation[k] = k;
      jacNorm[k] = Math.sqrt(columnNormSquared(k, k));
    }
  }

  private ColumnSelection selectNextColumn(int k) {
    ColumnSelection selection = new ColumnSelection(-1, Double.NEGATIVE_INFINITY);
    for (int i = k; i < cols; ++i) {
      double norm2 = columnNormSquared(k, permutation[i]);
      if (norm2 > selection.norm2) {
        selection = new ColumnSelection(i, norm2);
      }
    }
    return selection;
  }

  private double columnNormSquared(int startRow, int columnPermutationIndex) {
    double norm2 = 0;
    int iDiag = startRow * cols + columnPermutationIndex;
    for (int index = iDiag; index < jacobian.length; index += cols) {
      double aki = jacobian[index];
      norm2 += aki * aki;
    }
    return norm2;
  }

  private void pivotPermutation(int k, int nextColumn) {
    int pk = permutation[nextColumn];
    permutation[nextColumn] = permutation[k];
    permutation[k] = pk;
  }

  private void performHouseholder(int k, int pk, double ak2) {
    int kDiag = k * cols + pk;
    double akk = jacobian[kDiag];
    double alpha = (akk > 0) ? -Math.sqrt(ak2) : Math.sqrt(ak2);
    double betak = 1.0 / (ak2 - akk * alpha);
    beta[pk] = betak;

    diagR[pk] = alpha;
    jacobian[kDiag] -= alpha;
    applyHouseholderToRemainingColumns(k, pk, kDiag, betak);
  }

  private void applyHouseholderToRemainingColumns(int k, int pk, int kDiag, double betak) {
    for (int dk = cols - 1 - k; dk > 0; --dk) {
      int dkp = permutation[k + dk] - pk;
      double gamma = 0;
      for (int index = kDiag; index < jacobian.length; index += cols) {
        gamma += jacobian[index] * jacobian[index + dkp];
      }
      gamma *= betak;
      for (int index = kDiag; index < jacobian.length; index += cols) {
        jacobian[index + dkp] -= gamma * jacobian[index];
      }
    }
  }

  /**
   * Compute the product Qt.y for some Q.R. decomposition.
   *
   * @param y vector to multiply (will be overwritten with the result)
   */
  private void qTy(double[] y) {
    for (int k = 0; k < cols; ++k) {
      int pk = permutation[k];
      int kDiag = k * cols + pk;
      double gamma = 0;
      for (int i = k, index = kDiag; i < rows; ++i, index += cols) {
        gamma += jacobian[index] * y[i];
      }
      gamma *= beta[pk];
      for (int i = k, index = kDiag; i < rows; ++i, index += cols) {
        y[i] -= gamma * jacobian[index];
      }
    }
  }

  /** Array of measurements. */
  private WeightedMeasurement[] measurements;

  /** Array of parameters. */
  private EstimatedParameter[] parameters;

  /**
   * Jacobian matrix.
   *
   * <p>Depending on the computation phase, this matrix is either in canonical form (just after the
   * calls to updateJacobian) or in Q.R. decomposed form (after calls to qrDecomposition)
   */
  private double[] jacobian;

  /** Number of columns of the jacobian matrix. */
  private int cols;

  /** Number of solved variables. */
  private int solvedCols;

  /** Number of rows of the jacobian matrix. */
  private int rows;

  /** Diagonal elements of the R matrix in the Q.R. decomposition. */
  private double[] diagR;

  /** Norms of the columns of the jacobian matrix. */
  private double[] jacNorm;

  /** Coefficients of the Householder transforms vectors. */
  private double[] beta;

  /** Columns permutation array. */
  private int[] permutation;

  /** Rank of the jacobian matrix. */
  private int rank;

  /** Levenberg-Marquardt parameter. */
  private double lmPar;

  /** Parameters evolution direction associated with lmPar. */
  private double[] lmDir;

  /**
   * Residuals array.
   *
   * <p>Depending on the computation phase, this array is either in canonical form (just after the
   * calls to updateResiduals) or in premultiplied by Qt form (just after calls to qTy)
   */
  private double[] residuals;

  /** Cost value (square root of the sum of the residuals). */
  private double cost;

  /** Positive input variable used in determining the initial step bound. */
  private double initialStepBoundFactor;

  /** Maximal number of cost evaluations. */
  private int maxCostEval;

  /** Number of cost evaluations. */
  private int costEvaluations;

  /** Number of Jacobian evaluations. */
  private int jacobianEvaluations;

  /** Desired relative error in the sum of squares. */
  private double costRelativeTolerance;

  /** Desired relative error in the approximate solution parameters. */
  private double parRelativeTolerance;

  /**
   * Desired max cosine on the orthogonality between the function vector and the columns of the
   * jacobian.
   */
  private double orthoTolerance;

  @Serial private static final long serialVersionUID = 5387476316105068340L;
}
