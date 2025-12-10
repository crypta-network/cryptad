package org.spaceroots.mantissa.ode;

/**
 * Gragg–Bulirsch–Stoer integrator for non-stiff Ordinary Differential Equations with dense output
 * support.
 *
 * <p>This implementation follows the Richardson extrapolation scheme popularized by Hairer and
 * Wanner: it advances the solution with a modified midpoint method, refines the step through
 * polynomial extrapolation, and selects both the order and step size dynamically to minimize the
 * total number of derivative evaluations. It is aimed at smooth problems where very high accuracy
 * is desirable; in practice it surpasses embedded Runge–Kutta methods once the required tolerance
 * falls in the {@code 1e-6} to {@code 1e-11} range depending on problem sensitivity. Dense output
 * and switching functions are handled so callers can sample the solution or trigger events between
 * accepted steps. The integrator is not thread-safe; each instance manages mutable buffers that are
 * reused across calls to {@link #integrate(FirstOrderDifferentialEquations, double, double[],
 * double, double[])}. Typical usage creates one instance per ODE problem, configures optional
 * stability and interpolation controls, then integrates forward or backward in time while providing
 * a {@link StepHandler} for results.
 *
 * <ul>
 *   <li><strong>Responsibilities:</strong> adaptive order/step selection, error estimation, dense
 *       output coefficient generation.
 *   <li><strong>State:</strong> retains extrapolation tables and work arrays between steps; reuse
 *       the same instance only sequentially.
 *   <li><strong>Trade-offs:</strong> excellent accuracy per function call on smooth fields, higher
 *       setup cost than simpler embedded pairs.
 * </ul>
 *
 * <p><strong>License (Hairer/Wanner original odex code, summarized):</strong> redistribution and
 * use in source and binary forms, with or without modification, are permitted provided copyright
 * and disclaimer notices are preserved; the software is supplied “as is” without warranty and with
 * no liability for damages.
 *
 * @author E. Hairer and G. Wanner (fortran version)
 * @author L. Maisonobe (Java port)
 * @version $Id: GraggBulirschStoerIntegrator.java 1719 2007-09-26 19:46:57Z luc $
 * @see DormandPrince853Integrator
 * @see StepHandler
 */
public class GraggBulirschStoerIntegrator extends AdaptiveStepsizeIntegrator {

  private static final String METHOD_NAME = "Gragg-Bulirsch-Stoer";

  /**
   * Create an integrator with scalar tolerances and default control settings.
   *
   * <p>Use this constructor when a single absolute/relative tolerance pair applies to every state
   * component. The integrator allocates internal work buffers sized for the problem dimension,
   * enables dense output automatically when the configured {@link StepHandler} or any switching
   * function requires it, and initializes stability, step-size, order, and interpolation control to
   * values recommended in the Hairer–Wanner literature. Step handlers can be replaced later via
   * {@link #setStepHandler(StepHandler)}; stability and order settings can be tuned after
   * construction. The initial and maximum steps must be strictly positive; backward integration is
   * handled by negating the direction internally.
   *
   * @param minStep minimal step size in integration variable; must be positive but the final step
   *     may be smaller
   * @param maxStep maximal step size allowed (positive even for backward runs)
   * @param scalAbsoluteTolerance absolute tolerance applied uniformly to every state entry
   * @param scalRelativeTolerance relative tolerance applied uniformly to every state entry
   */
  public GraggBulirschStoerIntegrator(
      double minStep, double maxStep, double scalAbsoluteTolerance, double scalRelativeTolerance) {
    super(minStep, maxStep, scalAbsoluteTolerance, scalRelativeTolerance);
    denseOutput = (handler.requiresDenseOutput() || (!switchesHandler.isEmpty()));
    setStabilityCheck(true, -1, -1, -1);
    setStepsizeControl(-1, -1, -1, -1);
    setOrderControl(-1, -1, -1);
    setInterpolationControl(true, -1);
  }

  /**
   * Create an integrator with per-component tolerances and default control settings.
   *
   * <p>Choose this constructor when each state component requires its own absolute and relative
   * tolerance. Vector tolerances must match the dimension returned by the supplied equations. All
   * other defaults mirror the scalar constructor: stability checks enabled, conservative step-size
   * control, and dense output if any listener requires it. The integrator copies no user buffers,
   * so callers retain ownership of the tolerance arrays.
   *
   * @param minStep minimal step size in integration variable; must be strictly positive
   * @param maxStep maximal step size allowed; must be strictly positive
   * @param vecAbsoluteTolerance absolute tolerances per state entry; length equals state dimension
   * @param vecRelativeTolerance relative tolerances per state entry; length equals state dimension
   */
  @SuppressWarnings("unused")
  public GraggBulirschStoerIntegrator(
      double minStep,
      double maxStep,
      double[] vecAbsoluteTolerance,
      double[] vecRelativeTolerance) {
    super(minStep, maxStep, vecAbsoluteTolerance, vecRelativeTolerance);
    denseOutput = (handler.requiresDenseOutput() || (!switchesHandler.isEmpty()));
    setStabilityCheck(true, -1, -1, -1);
    setStepsizeControl(-1, -1, -1, -1);
    setOrderControl(-1, -1, -1);
    setInterpolationControl(true, -1);
  }

  /**
   * Configure stability checks performed during early extrapolation iterations.
   *
   * <p>For each candidate step the integrator compares the first derivative with later midpoint
   * derivatives to detect rapidly growing modes. If the check fails, the step is rejected and the
   * trial step size is reduced by the supplied factor. Checks are limited to the first few
   * extrapolation iterations to avoid excessive cost. Passing negative or zero limits restores the
   * defaults ({@code maxIter=2}, {@code maxChecks=1}, {@code stabilityReduction=0.5}). This setting
   * primarily guards against divergence on coarse steps or poorly scaled problems.
   *
   * @param performTest {@code true} to enable stability checks, {@code false} to skip them entirely
   * @param maxIter maximum extrapolation iterations to probe; non-positive values revert to default
   * @param maxChecks maximum derivative comparisons per iteration; non-positive values revert to
   *     default
   * @param stabilityReduction multiplicative factor applied to the next trial step after a failure;
   *     outside {@code [0.0001, 0.9999]} reverts to the default
   */
  public void setStabilityCheck(
      boolean performTest, int maxIter, int maxChecks, double stabilityReduction) {

    this.performTest = performTest;
    this.maxIter = (maxIter <= 0) ? 2 : maxIter;
    this.maxChecks = (maxChecks <= 0) ? 1 : maxChecks;

    if ((stabilityReduction < 0.0001) || (stabilityReduction > 0.9999)) {
      this.stabilityReduction = 0.5;
    } else {
      this.stabilityReduction = stabilityReduction;
    }
  }

  /**
   * Tune the step-size adaptation coefficients.
   *
   * <p>The next trial step {@code hNew} derives from the current step {@code h} via:
   *
   * <pre>{@code
   * hNew = h * stepControl2 / Math.pow(err / stepControl1, 1.0 / (2 * k + 1))
   * }</pre>
   *
   * <p>where {@code err} is the normalized error estimate and {@code k} is the extrapolation column
   * (starting at zero). The result is further clamped by
   *
   * <pre>{@code
   * Math.pow(stepControl3, 1.0 / (2 * k + 1)) / stepControl4
   *     <= hNew / h
   *     <= 1 / Math.pow(stepControl3, 1.0 / (2 * k + 1))
   * }</pre>
   *
   * <p>Values outside the accepted ranges revert to defaults ({@code stepControl1=0.65}, {@code
   * stepControl2=0.94}, {@code stepControl3=0.02}, {@code stepControl4=4.0}).
   *
   * @param stepControl1 numerator tolerance scale; outside {@code [0.0001, 0.9999]} resets to
   *     default
   * @param stepControl2 multiplicative growth factor; outside {@code [0.0001, 0.9999]} resets to
   *     default
   * @param stepControl3 clamp base for relative change; outside {@code [0.0001, 0.9999]} resets to
   *     default
   * @param stepControl4 clamp divisor limiting growth; outside {@code [1.0001, 999.9]} resets to
   *     default
   */
  public void setStepsizeControl(
      double stepControl1, double stepControl2, double stepControl3, double stepControl4) {

    if ((stepControl1 < 0.0001) || (stepControl1 > 0.9999)) {
      this.stepControl1 = 0.65;
    } else {
      this.stepControl1 = stepControl1;
    }

    if ((stepControl2 < 0.0001) || (stepControl2 > 0.9999)) {
      this.stepControl2 = 0.94;
    } else {
      this.stepControl2 = stepControl2;
    }

    if ((stepControl3 < 0.0001) || (stepControl3 > 0.9999)) {
      this.stepControl3 = 0.02;
    } else {
      this.stepControl3 = stepControl3;
    }

    if ((stepControl4 < 1.0001) || (stepControl4 > 999.9)) {
      this.stepControl4 = 4.0;
    } else {
      this.stepControl4 = stepControl4;
    }
  }

  /**
   * Adjust the order-selection heuristics for the extrapolation table.
   *
   * <p>The integrator raises or lowers the extrapolation order (always even) to minimize work per
   * unit step. Let {@code w(k)} be the estimated cost per unit time at order {@code k}; the rules
   * are:
   *
   * <pre>{@code
   * decrease order if w(k - 1) <= w(k) * orderControl1
   * increase order if w(k)     <= w(k - 1) * orderControl2
   * }</pre>
   *
   * Orders below {@code 6} or odd values revert to the default maximum of {@code 18} (nine table
   * columns). Control factors outside {@code [0.0001, 0.9999]} revert to defaults of {@code 0.8}
   * and {@code 0.9}.
   *
   * @param maxOrder highest extrapolation order allowed; non-even or {@code <= 6} values reset to
   *     the default maximum
   * @param orderControl1 threshold to favor reducing order; outside range reverts to default
   * @param orderControl2 threshold to favor increasing order; outside range reverts to default
   */
  public void setOrderControl(int maxOrder, double orderControl1, double orderControl2) {

    if ((maxOrder <= 6) || (maxOrder % 2 != 0)) {
      this.maxOrder = 18;
    }

    if ((orderControl1 < 0.0001) || (orderControl1 > 0.9999)) {
      this.orderControl1 = 0.8;
    } else {
      this.orderControl1 = orderControl1;
    }

    if ((orderControl2 < 0.0001) || (orderControl2 > 0.9999)) {
      this.orderControl2 = 0.9;
    } else {
      this.orderControl2 = orderControl2;
    }

    // reinitialize the arrays
    initializeArrays();
  }

  /**
   * Install the step handler invoked after each accepted step.
   *
   * <p>The handler receives dense interpolators when dense output is enabled, otherwise a dummy
   * interpolator exposing only end-of-step values. Replacing the handler triggers reallocation of
   * internal buffers because dense output requirements may change. Passing a handler that requests
   * dense output increases memory and CPU usage but enables intermediate sampling.
   *
   * @param handler recipient of accepted steps; must not be {@code null}
   */
  @Override
  public void setStepHandler(StepHandler handler) {

    super.setStepHandler(handler);
    denseOutput = (handler.requiresDenseOutput() || (!switchesHandler.isEmpty()));

    // reinitialize the arrays
    initializeArrays();
  }

  /**
   * Register a switching function (event detector) evaluated during integration.
   *
   * <p>The detector is polled at most every {@code maxCheckInterval} units to avoid missing sign
   * changes; when a root is bracketed, a root-finding phase refines the event time using the given
   * convergence threshold. Adding the first switching function enables dense output internally so
   * the solver can sample the solution between steps.
   *
   * @param function function whose sign changes trigger events; must not be {@code null}
   * @param maxCheckInterval maximum gap between event checks; large values risk missed events
   * @param convergence absolute time accuracy sought when locating the event instant
   */
  @Override
  public void addSwitchingFunction(
      SwitchingFunction function, double maxCheckInterval, double convergence) {
    super.addSwitchingFunction(function, maxCheckInterval, convergence);
    denseOutput = (handler.requiresDenseOutput() || (!switchesHandler.isEmpty()));

    // reinitialize the arrays
    initializeArrays();
  }

  /** Initialize or resize the integrator internal arrays. */
  private void initializeArrays() {

    int size = maxOrder / 2;

    if ((sequence == null) || (sequence.length != size)) {
      // all arrays should be reallocated with the right size
      sequence = new int[size];
      costPerStep = new int[size];
      coeff = new double[size][];
      costPerTimeUnit = new double[size];
      optimalStep = new double[size];
    }

    if (denseOutput) {
      // step size sequence: 2, 6, 10, 14, ...
      for (int k = 0; k < size; ++k) {
        sequence[k] = 4 * k + 2;
      }
    } else {
      // step size sequence: 2, 4, 6, 8, ...
      for (int k = 0; k < size; ++k) {
        sequence[k] = 2 * (k + 1);
      }
    }

    // initialize the order selection cost array
    // (number of function calls for each column of the extrapolation table)
    costPerStep[0] = sequence[0] + 1;
    for (int k = 1; k < size; ++k) {
      costPerStep[k] = costPerStep[k - 1] + sequence[k];
    }

    // initialize the extrapolation tables
    for (int k = 0; k < size; ++k) {
      coeff[k] = (k > 0) ? new double[k] : null;
      for (int l = 0; l < k; ++l) {
        double ratio = ((double) sequence[k]) / sequence[k - l - 1];
        coeff[k][l] = 1.0 / (ratio * ratio - 1.0);
      }
    }
  }

  /**
   * Configure dense-output interpolation behavior.
   *
   * <p>The interpolation order used in {@link GraggBulirschStoerStepInterpolator} equals {@code 2 *
   * k - mudif + 1}, where {@code k} is the last successful extrapolation column. When {@code
   * useInterpolationError} is {@code true}, the interpolator’s error estimate participates in
   * step-size control; otherwise only end-point errors drive adaptation. Values of {@code mudif}
   * outside {@code [1, 6]} revert to the default of {@code 4}.
   *
   * @param useInterpolationError {@code true} to include interpolation error in step-size control;
   *     {@code false} to ignore it
   * @param mudif interpolation order control offset; values {@code <= 0} or {@code >= 7} reset to
   *     the default of four
   */
  public void setInterpolationControl(boolean useInterpolationError, int mudif) {

    this.useInterpolationError = useInterpolationError;

    if ((mudif <= 0) || (mudif >= 7)) {
      this.mudif = 4;
    } else {
      this.mudif = mudif;
    }
  }

  /**
   * Get the human-readable name of this integration method.
   *
   * @return the constant string {@code "Gragg-Bulirsch-Stoer"}; callers must not mutate it
   */
  public String getName() {
    return METHOD_NAME;
  }

  /**
   * Update the scaling array used to normalize local error estimates.
   *
   * <p>Each entry combines absolute and relative tolerances with the larger magnitude among the two
   * provided state vectors, mirroring the scaling used by Hairer and Wanner. When vector tolerances
   * are configured the corresponding element-wise values are used; otherwise scalar tolerances are
   * applied uniformly.
   *
   * @param y1 first state vector sampled for magnitude; must match the problem dimension
   * @param y2 second state vector sampled for magnitude; must match the problem dimension
   * @param scale output buffer receiving per-component scales; length must match {@code y1}
   */
  private void rescale(double[] y1, double[] y2, double[] scale) {
    if (vecAbsoluteTolerance == null) {
      for (int i = 0; i < scale.length; ++i) {
        double yi = Math.max(Math.abs(y1[i]), Math.abs(y2[i]));
        scale[i] = scalAbsoluteTolerance + scalRelativeTolerance * yi;
      }
    } else {
      for (int i = 0; i < scale.length; ++i) {
        double yi = Math.max(Math.abs(y1[i]), Math.abs(y2[i]));
        scale[i] = vecAbsoluteTolerance[i] + vecRelativeTolerance[i] * yi;
      }
    }
  }

  /**
   * Advance one trial step using the modified midpoint sequence for column {@code k}.
   *
   * <p>The method evaluates the derivatives at uniformly spaced substeps, performs the midpoint
   * updates in place, and optionally aborts early if the stability monitor detects divergence. The
   * last substep is symmetrically corrected to keep the scheme centered. Intermediate derivatives
   * and states are written into the provided buffers to avoid allocations.
   *
   * @param equations differential equations being integrated; must match the configured dimension
   * @param t0 start time for the global step
   * @param y0 state vector at {@code t0}; not modified by this method
   * @param step global step length attempted for this iteration
   * @param k extrapolation column index (0-based) selecting the number of substeps
   * @param scale per-component scaling factors for error and stability checks
   * @param f scratch array holding derivatives per substep; {@code f[0]} must already contain the
   *     derivative at {@code t0}
   * @param yMiddle buffer receiving the state at mid-step when needed for dense output
   * @param yEnd buffer receiving the state at the end of the trial step
   * @param yTmp scratch buffer for intermediate midpoint updates
   * @return {@code true} when the full sequence completed; {@code false} if stability checks failed
   *     and the caller should reduce the step
   * @throws DerivativeException if the user-provided derivative function throws during evaluation
   */
  private boolean tryStep(
      FirstOrderDifferentialEquations equations,
      double t0,
      double[] y0,
      double step,
      int k,
      double[] scale,
      double[][] f,
      double[] yMiddle,
      double[] yEnd,
      double[] yTmp)
      throws DerivativeException {

    int n = sequence[k];
    double subStep = step / n;
    double subStep2 = 2 * subStep;

    // first substep
    double t = t0 + subStep;
    for (int i = 0; i < y0.length; ++i) {
      yTmp[i] = y0[i];
      yEnd[i] = y0[i] + subStep * f[0][i];
    }
    equations.computeDerivatives(t, yEnd, f[1]);

    // other substeps
    for (int j = 1; j < n; ++j) {

      if (2 * j == n) {
        // save the point at the middle of the step
        System.arraycopy(yEnd, 0, yMiddle, 0, y0.length);
      }

      t += subStep;
      for (int i = 0; i < y0.length; ++i) {
        double middle = yEnd[i];
        yEnd[i] = yTmp[i] + subStep2 * f[j][i];
        yTmp[i] = middle;
      }

      equations.computeDerivatives(t, yEnd, f[j + 1]);

      // stability check
      if (stabilityCheckFailed(y0, scale, f, j, k)) {
        return false;
      }
    }

    // correction of the last substep (at t0 + step)
    for (int i = 0; i < y0.length; ++i) {
      yEnd[i] = 0.5 * (yTmp[i] + yEnd[i] + subStep * f[n][i]);
    }

    return true;
  }

  private boolean stabilityCheckFailed(double[] y0, double[] scale, double[][] f, int j, int k) {
    if (!(performTest && (j <= maxChecks) && (k < maxIter))) {
      return false;
    }
    double initialNorm = 0.0;
    for (int l = 0; l < y0.length; ++l) {
      double ratio = f[0][l] / scale[l];
      initialNorm += ratio * ratio;
    }
    double deltaNorm = 0.0;
    for (int l = 0; l < y0.length; ++l) {
      double ratio = (f[j + 1][l] - f[0][l]) / scale[l];
      deltaNorm += ratio * ratio;
    }
    return deltaNorm > 4 * Math.max(1.0e-15, initialNorm);
  }

  /**
   * Extrapolate the solution vector using the Aitken–Neville scheme.
   *
   * @param offset offset applied when selecting extrapolation coefficients for dense output rows
   * @param k index of the most recently computed diagonal element
   * @param diag working diagonal slice of the extrapolation table, excluding the newest element
   * @param last newest diagonal element to be updated in place
   */
  private void extrapolate(int offset, int k, double[][] diag, double[] last) {

    // update the diagonal
    for (int j = 1; j < k; ++j) {
      for (int i = 0; i < last.length; ++i) {
        // Aitken-Neville's recursive formula
        diag[k - j - 1][i] =
            diag[k - j][i] + coeff[k + offset][j - 1] * (diag[k - j][i] - diag[k - j - 1][i]);
      }
    }

    // update the last element
    for (int i = 0; i < last.length; ++i) {
      // Aitken-Neville's recursive formula
      last[i] = diag[0][i] + coeff[k + offset][k - 1] * (diag[0][i] - last[i]);
    }
  }

  /**
   * Integrate a first-order ODE from {@code t0} to {@code t} updating {@code y} in place.
   *
   * <p>This method performs adaptive extrapolation until the target time is reached or a switching
   * function requests termination. It supports forward and backward integration. The supplied state
   * array {@code y} is used both as input (initial state) and output (final state); it may be the
   * same instance as {@code y0}. The method validates dimensional consistency and rejects
   * zero-length time spans. Step handlers and switching functions configured on the integrator are
   * invoked during the process.
   *
   * @param equations system of differential equations; its dimension must match {@code y0}
   * @param t0 initial integration time (independent variable value)
   * @param y0 initial state vector at {@code t0}; length must equal problem dimension
   * @param t target time to reach; may be before {@code t0} for backward integration
   * @param y array receiving the computed state at {@code t}; may alias {@code y0}
   * @throws DerivativeException if user-supplied derivative computation fails
   * @throws IntegratorException if dimensions mismatch or the step size becomes unusable
   */
  public void integrate(
      FirstOrderDifferentialEquations equations, double t0, double[] y0, double t, double[] y)
      throws DerivativeException, IntegratorException {
    validateIntegrationInputs(equations, t0, y0, t);

    boolean forward = (t > t0);
    WorkingState workingState = new WorkingState(y0.length);
    if (y != y0) {
      System.arraycopy(y0, 0, y, 0, y0.length);
    }

    double[] scale = new double[y0.length];
    rescale(y, y, scale);

    int targetIter = initialTargetIteration();
    AbstractStepInterpolator interpolator = createInterpolator(y, forward, workingState);
    interpolator.storeTime(t0);

    stepStart = t0;
    StepStatus status = new StepStatus(targetIter);
    handler.reset();
    costPerTimeUnit[0] = 0;

    runIntegrationLoop(equations, t, y, forward, scale, interpolator, workingState, status);
  }

  private void runIntegrationLoop(
      FirstOrderDifferentialEquations equations,
      double targetTime,
      double[] y,
      boolean forward,
      double[] scale,
      AbstractStepInterpolator interpolator,
      WorkingState workingState,
      StepStatus status)
      throws DerivativeException, IntegratorException {

    while (!status.lastStep) {
      performSingleStep(
          equations, targetTime, y, forward, scale, interpolator, workingState, status);
    }
  }

  private void performSingleStep(
      FirstOrderDifferentialEquations equations,
      double targetTime,
      double[] y,
      boolean forward,
      double[] scale,
      AbstractStepInterpolator interpolator,
      WorkingState w,
      StepStatus status)
      throws DerivativeException, IntegratorException {

    status.reject = false;
    status.loopExit = false;
    prepareNewStep(equations, y, forward, scale, interpolator, w, status);

    stepSize = status.hNew;
    status.lastStep = adjustStepForTarget(targetTime, forward);

    int k = runExtrapolationIterations(equations, y, scale, w, status);

    double hInt = getMaxStep();
    if (denseOutput && !status.reject) {
      hInt = handleDenseOutput(equations, y, scale, interpolator, w, k, status);
    }

    if (!status.reject) {
      finalizeAcceptedStep(y, interpolator, w, k, status);
    }

    status.hNew = Math.min(status.hNew, hInt);
    if (!forward) {
      status.hNew = -status.hNew;
    }

    status.firstTime = false;
    updateRejectionStatus(status, status.reject);
  }

  /**
   * Store results for an accepted step, notify handlers, and prepare the next trial size/order.
   *
   * @param y caller-owned state array updated with the accepted end state
   * @param interpolator step interpolator already primed with start state; will store end time here
   * @param w working buffers holding extrapolated end state and derivatives
   * @param k last successful extrapolation column
   * @param status mutable step status tracking rejection history and next targets
   * @throws DerivativeException if switching functions require additional derivative evaluations
   * @throws IntegratorException if event processing or handler logic raises integration-level
   *     errors
   */
  private void finalizeAcceptedStep(
      double[] y, AbstractStepInterpolator interpolator, WorkingState w, int k, StepStatus status)
      throws DerivativeException, IntegratorException {

    stepStart += stepSize;
    System.arraycopy(w.y1, 0, y, 0, y.length);

    switchesHandler.stepAccepted(stepStart, y);
    if (switchesHandler.stop()) {
      status.lastStep = true;
    }

    interpolator.storeTime(stepStart);
    handler.handleStep((StepInterpolator) interpolator, status.lastStep);

    if (switchesHandler.reset(stepStart, y) && !status.lastStep) {
      status.firstStepAlreadyComputed = false;
    }

    status.targetIter = chooseOptimalIteration(k, status);
    status.hNew = computeNextStepSize(k, status);
    status.newStep = true;
  }

  private void updateRejectionStatus(StepStatus status, boolean reject) {
    if (reject) {
      status.lastStep = false;
      status.previousRejected = true;
    } else {
      status.previousRejected = false;
    }
  }

  private void prepareNewStep(
      FirstOrderDifferentialEquations equations,
      double[] y,
      boolean forward,
      double[] scale,
      AbstractStepInterpolator interpolator,
      WorkingState w,
      StepStatus status)
      throws DerivativeException {

    status.reject = false;
    if (!status.newStep) {
      return;
    }

    interpolator.shift();
    if (!status.firstStepAlreadyComputed) {
      equations.computeDerivatives(stepStart, y, w.yDot0);
    }

    if (status.firstTime) {
      status.hNew =
          initializeStep(
              equations,
              forward,
              2 * status.targetIter + 1,
              scale,
              stepStart,
              y,
              w.yDot0,
              w.yTmp,
              w.yTmpDot);
      if (!forward) {
        status.hNew = -status.hNew;
      }
    }

    status.newStep = false;
  }

  private boolean adjustStepForTarget(double targetTime, boolean forward) {
    if ((forward && (stepStart + stepSize > targetTime))
        || ((!forward) && (stepStart + stepSize < targetTime))) {
      stepSize = targetTime - stepStart;
    }
    double nextT = stepStart + stepSize;
    return forward ? (nextT >= targetTime) : (nextT <= targetTime);
  }

  private int runExtrapolationIterations(
      FirstOrderDifferentialEquations equations,
      double[] y,
      double[] scale,
      WorkingState w,
      StepStatus status)
      throws DerivativeException, IntegratorException {

    int k = -1;
    boolean shouldContinue;
    do {
      status.loopExit = false;
      ++k;
      if (!tryCurrentSubStep(equations, y, scale, w, k, status)) {
        break;
      }

      shouldContinue = k == 0;
      if (!shouldContinue) {
        computeExtrapolationAndError(y, scale, w, k, status);
        shouldContinue = !(status.reject || status.loopExit);
      }
    } while (shouldContinue);

    return k;
  }

  private boolean tryCurrentSubStep(
      FirstOrderDifferentialEquations equations,
      double[] y,
      double[] scale,
      WorkingState w,
      int k,
      StepStatus status)
      throws DerivativeException, IntegratorException {

    if (tryStep(
        equations,
        stepStart,
        y,
        stepSize,
        k,
        scale,
        w.fk[k],
        (k == 0) ? w.yMidDots[0] : w.diagonal[k - 1],
        (k == 0) ? w.y1 : w.y1Diag[k - 1],
        w.yTmp)) {
      return true;
    }

    status.hNew = Math.abs(filterStep(stepSize * stabilityReduction, false));
    status.reject = true;
    status.loopExit = true;
    return false;
  }

  private void computeExtrapolationAndError(
      double[] y, double[] scale, WorkingState w, int k, StepStatus status)
      throws IntegratorException {

    extrapolate(0, k, w.y1Diag, w.y1);
    rescale(y, w.y1, scale);

    double error = estimateError(y.length, scale, w);
    if (isErrorUnacceptable(error, k, status)) {
      return;
    }

    updateOptimalStepAndCost(error, k);
    checkConvergence(k, error, status);
  }

  private double estimateError(int dimension, double[] scale, WorkingState w) {
    double error = 0;
    for (int j = 0; j < dimension; ++j) {
      double e = Math.abs(w.y1[j] - w.y1Diag[0][j]) / scale[j];
      error += e * e;
    }
    return Math.sqrt(error / dimension);
  }

  private boolean isErrorUnacceptable(double error, int k, StepStatus status)
      throws IntegratorException {
    if ((error > 1.0e15) || ((k > 1) && (error > status.maxError))) {
      status.hNew = Math.abs(filterStep(stepSize * stabilityReduction, false));
      status.reject = true;
      status.loopExit = true;
      return true;
    }
    status.maxError = Math.max(4 * error, 1.0);
    return false;
  }

  private void updateOptimalStepAndCost(double error, int k) throws IntegratorException {
    double exp = 1.0 / (2 * k + 1);
    double fac = stepControl2 / Math.pow(error / stepControl1, exp);
    double pow = Math.pow(stepControl3, exp);
    fac = Math.clamp(fac, pow / stepControl4, 1 / pow);
    optimalStep[k] = Math.abs(filterStep(stepSize * fac, true));
    costPerTimeUnit[k] = costPerStep[k] / optimalStep[k];
  }

  private void checkConvergence(int k, double error, StepStatus status) {
    status.loopExit = false;
    switch (k - status.targetIter) {
      case -1:
        handleConvergenceBeforeTarget(k, error, status);
        break;
      case 0:
        handleConvergenceAtTarget(error, status);
        break;
      case 1:
        if (error > 1.0) {
          rejectAndReduceOrder(status);
        }
        status.loopExit = true;
        break;
      default:
        if ((status.firstTime || status.lastStep) && (error <= 1.0)) {
          status.loopExit = true;
        }
        break;
    }
  }

  private void handleConvergenceBeforeTarget(int k, double error, StepStatus status) {
    if ((status.targetIter <= 1) || status.previousRejected) {
      return;
    }

    if (error <= 1.0) {
      status.loopExit = true;
      return;
    }

    double ratio = ((double) sequence[k] * sequence[k + 1]) / (sequence[0] * sequence[0]);
    if (error > ratio * ratio) {
      rejectAndReduceOrder(status);
      status.targetIter = k;
      if ((status.targetIter > 1)
          && (costPerTimeUnit[status.targetIter - 1]
              < orderControl1 * costPerTimeUnit[status.targetIter])) {
        --status.targetIter;
      }
      status.hNew = optimalStep[status.targetIter];
      status.loopExit = true;
    }
  }

  private void handleConvergenceAtTarget(double error, StepStatus status) {
    if (error <= 1.0) {
      status.loopExit = true;
      return;
    }

    double ratio = ((double) sequence[status.targetIter + 1]) / sequence[0];
    if (error > ratio * ratio) {
      rejectAndReduceOrder(status);
      if ((status.targetIter > 1)
          && (costPerTimeUnit[status.targetIter - 1]
              < orderControl1 * costPerTimeUnit[status.targetIter])) {
        --status.targetIter;
      }
      status.hNew = optimalStep[status.targetIter];
      status.loopExit = true;
    }
  }

  private void rejectAndReduceOrder(StepStatus status) {
    status.reject = true;
  }

  private double handleDenseOutput(
      FirstOrderDifferentialEquations equations,
      double[] y,
      double[] scale,
      AbstractStepInterpolator interpolator,
      WorkingState w,
      int k,
      StepStatus status)
      throws DerivativeException {

    for (int j = 1; j <= k; ++j) {
      extrapolate(0, j, w.diagonal, w.yMidDots[0]);
    }

    equations.computeDerivatives(stepStart + stepSize, w.y1, w.yDot1);
    int mu = 2 * k - mudif + 3;
    computeDenseOutputDerivatives(y.length, w, k, mu);

    double hInt = getMaxStep();
    if (mu >= 0) {
      hInt = applyInterpolationErrorControl(scale, interpolator, mu, hInt, status);
      if (!status.reject) {
        handleSwitchingFunctions(interpolator, status);
      }
    }

    if (!status.reject) {
      status.firstStepAlreadyComputed = true;
      System.arraycopy(w.yDot1, 0, w.yDot0, 0, y.length);
    }

    return hInt;
  }

  private void computeDenseOutputDerivatives(int dimension, WorkingState w, int k, int mu) {
    for (int l = 0; l < mu; ++l) {
      processDenseOutputLevel(dimension, w, k, l);
    }
  }

  private void processDenseOutputLevel(int dimension, WorkingState w, int k, int l) {
    int l2 = l / 2;
    int middleIndex = w.fk[l2].length / 2;
    double factor = Math.pow(0.5 * sequence[l2], l);

    fillMidDotsForLevel(dimension, w, l, l2, middleIndex, factor);
    updateDiagonalForLevel(dimension, w, k, l, l2);
    scaleMidDotsRow(dimension, w, l);
    updateFiniteDifferences(dimension, w, k, l);
  }

  private void fillMidDotsForLevel(
      int dimension, WorkingState w, int l, int l2, int middleIndex, double factor) {
    for (int i = 0; i < dimension; ++i) {
      w.yMidDots[l + 1][i] = factor * w.fk[l2][middleIndex + l][i];
    }
  }

  private void updateDiagonalForLevel(int dimension, WorkingState w, int k, int l, int l2) {
    for (int j = 1; j <= k - l2; ++j) {
      double factor = Math.pow(0.5 * sequence[j + l2], l);
      int middleIndex = w.fk[l2 + j].length / 2;
      for (int i = 0; i < dimension; ++i) {
        w.diagonal[j - 1][i] = factor * w.fk[l2 + j][middleIndex + l][i];
      }
      extrapolate(l2, j, w.diagonal, w.yMidDots[l + 1]);
    }
  }

  private void scaleMidDotsRow(int dimension, WorkingState w, int l) {
    for (int i = 0; i < dimension; ++i) {
      w.yMidDots[l + 1][i] *= stepSize;
    }
  }

  private void updateFiniteDifferences(int dimension, WorkingState w, int k, int l) {
    for (int j = (l + 1) / 2; j <= k; ++j) {
      for (int m = w.fk[j].length - 1; m >= 2 * (l + 1); --m) {
        for (int i = 0; i < dimension; ++i) {
          w.fk[j][m][i] -= w.fk[j][m - 2][i];
        }
      }
    }
  }

  private double applyInterpolationErrorControl(
      double[] scale,
      AbstractStepInterpolator interpolator,
      int mu,
      double hInt,
      StepStatus status) {

    GraggBulirschStoerStepInterpolator gbsInterpolator =
        (GraggBulirschStoerStepInterpolator) interpolator;
    gbsInterpolator.computeCoefficients(mu, stepSize);

    if (useInterpolationError) {
      double interpError = gbsInterpolator.estimateError(scale);
      hInt = Math.abs(stepSize / Math.max(Math.pow(interpError, 1.0 / (mu + 4)), 0.01));
      if (interpError > 10.0) {
        status.hNew = hInt;
        status.reject = true;
      }
    }
    return hInt;
  }

  private void handleSwitchingFunctions(AbstractStepInterpolator interpolator, StepStatus status) {

    interpolator.storeTime(stepStart + stepSize);
    if (switchesHandler.evaluateStep((StepInterpolator) interpolator)) {
      status.reject = true;
      status.hNew = Math.abs(switchesHandler.getEventTime() - stepStart);
    }
  }

  private int chooseOptimalIteration(int k, StepStatus status) {
    if (k == 1) {
      return status.previousRejected ? 1 : 2;
    }
    if (k <= status.targetIter) {
      int optimalIter = k;
      if (costPerTimeUnit[k - 1] < orderControl1 * costPerTimeUnit[k]) {
        optimalIter = k - 1;
      } else if (costPerTimeUnit[k] < orderControl2 * costPerTimeUnit[k - 1]) {
        optimalIter = Math.min(k + 1, sequence.length - 2);
      }
      return optimalIter;
    }

    int optimalIter = k - 1;
    if ((k > 2) && (costPerTimeUnit[k - 2] < orderControl1 * costPerTimeUnit[k - 1])) {
      optimalIter = k - 2;
    }
    if (costPerTimeUnit[k] < orderControl2 * costPerTimeUnit[optimalIter]) {
      optimalIter = Math.min(k, sequence.length - 2);
    }
    return optimalIter;
  }

  private double computeNextStepSize(int k, StepStatus status) throws IntegratorException {
    if (status.previousRejected) {
      status.targetIter = Math.min(status.targetIter, k);
      return Math.min(Math.abs(stepSize), optimalStep[status.targetIter]);
    }

    if (status.targetIter <= k) {
      return optimalStep[status.targetIter];
    }

    if (costPerTimeUnit[k] < orderControl2 * costPerTimeUnit[k - 1]) {
      return filterStep(
          optimalStep[k] * costPerStep[status.targetIter + 1] / costPerStep[k], false);
    }
    return filterStep(optimalStep[k] * costPerStep[status.targetIter] / costPerStep[k], false);
  }

  private int initialTargetIteration() {
    double log10R =
        Math.log(
                Math.max(
                    1.0e-10,
                    (vecRelativeTolerance == null)
                        ? scalRelativeTolerance
                        : vecRelativeTolerance[0]))
            / Math.log(10.0);
    int target = (int) Math.floor(0.5 - 0.6 * log10R);
    return Math.clamp(target, 1, sequence.length - 2);
  }

  private AbstractStepInterpolator createInterpolator(
      double[] y, boolean forward, WorkingState workingState) {
    if (denseOutput || (!switchesHandler.isEmpty())) {
      return new GraggBulirschStoerStepInterpolator(
          y,
          workingState.yDot0,
          workingState.y1,
          workingState.yDot1,
          workingState.yMidDots,
          forward);
    }
    return new DummyStepInterpolator(y, forward);
  }

  private void validateIntegrationInputs(
      FirstOrderDifferentialEquations equations, double t0, double[] y0, double t)
      throws IntegratorException {

    if (equations.getDimension() != y0.length) {
      throw new IntegratorException(
          "dimensions mismatch: "
              + "ODE problem has dimension {0}"
              + ", state vector has dimension {1}",
          new String[] {Integer.toString(equations.getDimension()), Integer.toString(y0.length)});
    }
    if (Math.abs(t - t0) <= 1.0e-12 * Math.max(Math.abs(t0), Math.abs(t))) {
      throw new IntegratorException(
          "too small integration interval: length = {0}",
          new String[] {Double.toString(Math.abs(t - t0))});
    }
  }

  private final class WorkingState {
    final double[] yDot0;
    final double[] y1;
    final double[] yTmp;
    final double[] yTmpDot;
    final double[][] diagonal;
    final double[][] y1Diag;
    final double[][][] fk;
    final double[] yDot1;
    final double[][] yMidDots;

    WorkingState(int dimension) {
      yDot0 = new double[dimension];
      y1 = new double[dimension];
      yTmp = new double[dimension];
      yTmpDot = new double[dimension];

      diagonal = new double[sequence.length - 1][];
      y1Diag = new double[sequence.length - 1][];
      for (int k = 0; k < sequence.length - 1; ++k) {
        diagonal[k] = new double[dimension];
        y1Diag[k] = new double[dimension];
      }

      fk = new double[sequence.length][][];
      for (int k = 0; k < sequence.length; ++k) {
        fk[k] = new double[sequence[k] + 1][];
        fk[k][0] = yDot0;
        for (int l = 0; l < sequence[k]; ++l) {
          fk[k][l + 1] = new double[dimension];
        }
      }

      if (denseOutput) {
        yDot1 = new double[dimension];
        yMidDots = new double[1 + 2 * sequence.length][];
        for (int j = 0; j < yMidDots.length; ++j) {
          yMidDots[j] = new double[dimension];
        }
      } else {
        yDot1 = null;
        yMidDots = new double[1][];
        yMidDots[0] = new double[dimension];
      }
    }
  }

  private static final class StepStatus {
    double hNew;
    double maxError = Double.MAX_VALUE;
    boolean previousRejected = false;
    boolean firstTime = true;
    boolean newStep = true;
    boolean lastStep = false;
    boolean firstStepAlreadyComputed = false;
    boolean reject = false;
    boolean loopExit = false;
    int targetIter;

    StepStatus(int targetIter) {
      this.targetIter = targetIter;
    }
  }

  /** maximal order. */
  private int maxOrder;

  /** step size sequence. */
  private int[] sequence;

  /** overall cost of applying step reduction up to iteration k+1, in number of calls. */
  private int[] costPerStep;

  /** cost per unit step. */
  private double[] costPerTimeUnit;

  /** optimal steps for each order. */
  private double[] optimalStep;

  /** extrapolation coefficients. */
  private double[][] coeff;

  /** stability check enabling parameter. */
  private boolean performTest;

  /** maximal number of checks for each iteration. */
  private int maxChecks;

  /** maximal number of iterations for which checks are performed. */
  private int maxIter;

  /** stepsize reduction factor in case of stability check failure. */
  private double stabilityReduction;

  /** first stepsize control factor. */
  private double stepControl1;

  /** second stepsize control factor. */
  private double stepControl2;

  /** third stepsize control factor. */
  private double stepControl3;

  /** fourth stepsize control factor. */
  private double stepControl4;

  /** first order control factor. */
  private double orderControl1;

  /** second order control factor. */
  private double orderControl2;

  /** dense outpute required. */
  private boolean denseOutput;

  /** use interpolation error in stepsize control. */
  private boolean useInterpolationError;

  /** interpolation order control parameter. */
  private int mudif;
}
