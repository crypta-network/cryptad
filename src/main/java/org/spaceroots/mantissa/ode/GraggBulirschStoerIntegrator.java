package org.spaceroots.mantissa.ode;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Adaptive Gragg-Bulirsch-Stoer integrator for non-stiff first-order ODEs with dense output.
 *
 * <p>This integrator advances the state with a modified midpoint scheme, then refines it using
 * Richardson extrapolation and a polynomial tableau. It dynamically selects both step size and
 * extrapolation to reduce total derivative evaluations while meeting accuracy goals. Typical usage
 * creates a new instance per problem, configures stability and interpolation controls as needed,
 * registers a {@link StepHandler} and any switching functions, then calls {@link
 * #integrate(FirstOrderDifferentialEquations, double, double[], double, double[])}. The
 * implementation stores working buffers across steps, so it is not thread-safe and should be reused
 * only for sequential integrations. It is most effective on smooth problems requiring high
 * accuracy; coarse steps on rough dynamics may trigger stability reductions.
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
 * and disclaimer notices are preserved; the software is supplied "as is" without warranty and with
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
   * <p>Choose this constructor when a single absolute/relative tolerance pair applies to every
   * state component. The integrator allocates internal work buffers sized for the problem dimension
   * and enables dense output automatically when the configured {@link StepHandler} or any switching
   * function requires it. Stability checks, step-size control, order control, and interpolation
   * control are initialized to the recommended defaults, and you may adjust them later via the
   * corresponding setters. Both step bounds must be strictly positive; backward integration is
   * handled by internally negating the direction and step size as needed.
   *
   * @param minStep minimal step size in integration time units; must be positive
   * @param maxStep maximal step size magnitude permitted; positive even for backward runs
   * @param scalAbsoluteTolerance absolute tolerance applied uniformly to each state component
   * @param scalRelativeTolerance relative tolerance applied uniformly to each state component
   */
  public GraggBulirschStoerIntegrator(
      double minStep, double maxStep, double scalAbsoluteTolerance, double scalRelativeTolerance) {
    super(minStep, maxStep, scalAbsoluteTolerance, scalRelativeTolerance);
    denseOutput = handler.requiresDenseOutput() || !switchesHandler.isEmpty();
    setStabilityCheck(true, -1, -1, -1);
    setStepsizeControl(-1, -1, -1, -1);
    setOrderControl(-1, -1, -1);
    setInterpolationControl(true, -1);
  }

  /**
   * Create an integrator with per-component tolerances and default control settings.
   *
   * <p>Use this constructor when each state component needs its own absolute and relative tolerance
   * values. The tolerance arrays must match the dimension returned by the supplied equations and be
   * used directly, so callers retain ownership of the buffers. As with the scalar constructor,
   * stability checks are enabled, conservative step-size control is selected, and dense output is
   * automatically enabled when a handler or switching function requires it. Both step bounds must
   * be strictly positive; backward integration is handled internally by negating the step
   * direction.
   *
   * @param minStep minimal step size in integration time units; must be positive
   * @param maxStep maximal step size magnitude permitted; must be positive
   * @param vecAbsoluteTolerance absolute tolerances per state entry; length equals dimension
   * @param vecRelativeTolerance relative tolerances per state entry; length equals dimension
   */
  @SuppressWarnings("unused")
  public GraggBulirschStoerIntegrator(
      double minStep,
      double maxStep,
      double[] vecAbsoluteTolerance,
      double[] vecRelativeTolerance) {
    super(minStep, maxStep, vecAbsoluteTolerance, vecRelativeTolerance);
    denseOutput = handler.requiresDenseOutput() || !switchesHandler.isEmpty();
    setStabilityCheck(true, -1, -1, -1);
    setStepsizeControl(-1, -1, -1, -1);
    setOrderControl(-1, -1, -1);
    setInterpolationControl(true, -1);
  }

  /**
   * Configure stability checks performed during early extrapolation iterations.
   *
   * <p>For each candidate step the integrator compares the first derivative with later midpoint
   * derivatives to detect rapidly growing modes. If the check fails, the step is rejected, and the
   * trial step size is reduced by the supplied factor. Checks are limited to the first few
   * extrapolation iterations to avoid excessive cost. Passing non-positive limits restores defaults
   * ({@code maxIter=2}, {@code maxChecks=1}, {@code stabilityReduction=0.5}). This setting
   * primarily guards against divergence on coarse steps or poorly scaled problems.
   *
   * @param performTest {@code true} to enable checks; {@code false} disables all checks
   * @param maxIter maximum extrapolation iterations to probe; non-positive restores default
   * @param maxChecks maximum derivative comparisons per iteration; non-positive restores default
   * @param stabilityReduction multiplicative factor for next trial step after failure; out of range
   *     restores default
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
   * <p>Where {@code err} is the normalized error estimate and {@code k} is the extrapolation column
   * (starting at zero). The result is further clamped by
   *
   * <pre>{@code
   * Math.pow(stepControl3, 1.0 / (2 * k + 1)) / stepControl4
   *     <= hNew / h
   *     <= 1 / Math.pow(stepControl3, 1.0 / (2 * k + 1))
   * }</pre>
   *
   * <p>Values outside the accepted ranges revert to defaults ({@code stepControl1=0.65}, {@code
   * stepControl2=0.94}, {@code stepControl3=0.02}, {@code stepControl4=4.0}). These coefficients
   * influence how aggressively the method grows or shrinks step sizes after each accepted step.
   *
   * @param stepControl1 numerator tolerance scale; outside {@code [0.0001, 0.9999]} resets default
   * @param stepControl2 multiplicative growth factor; outside {@code [0.0001, 0.9999]} resets
   *     default
   * @param stepControl3 clamp base for relative change; outside {@code [0.0001, 0.9999]} resets
   *     default
   * @param stepControl4 clamp divisor limiting growth; outside {@code [1.0001, 999.9]} resets
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
   * <p>Orders below {@code 6} or odd values revert to the default maximum of {@code 18} (nine table
   * columns). Control factors outside {@code [0.0001, 0.9999]} revert to defaults of {@code 0.8}
   * and {@code 0.9}. Use this method when tuning performance for a specific accuracy target.
   *
   * @param maxOrder highest extrapolation order allowed; non-even or {@code <= 6} resets default
   * @param orderControl1 threshold favoring order reduction; outside range resets default
   * @param orderControl2 threshold favoring order increase; outside range resets default
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
   * <p>The handler receives a dense interpolator when dense output is enabled, otherwise a dummy
   * interpolator exposing only end-of-step values. Replacing the handler triggers reallocation of
   * internal buffers because dense output requirements may change. Passing a handler that requests
   * dense output increases memory and CPU usage but enables intermediate sampling and event
   * processing between accepted steps. The supplied handler must be non-null and be used
   * immediately for later integration calls.
   *
   * @param handler recipient of accepted steps; must be non-null and retained by this instance
   */
  @Override
  public void setStepHandler(StepHandler handler) {

    super.setStepHandler(handler);
    denseOutput = handler.requiresDenseOutput() || !switchesHandler.isEmpty();

    // reinitialize the arrays
    initializeArrays();
  }

  /**
   * Register a switching function (event detector) evaluated during integration.
   *
   * <p>The detector is polled at most every {@code maxCheckInterval} units of integration time to
   * avoid missing sign changes; when a root is bracketed, a root-finding phase refines the event
   * time using the given convergence threshold. Adding the first switching function enables dense
   * output internally so the solver can sample the solution between steps. The function is retained
   * until removed by the base class API or the integrator instance is discarded.
   *
   * @param function function whose sign changes trigger events; must be non-null
   * @param maxCheckInterval maximum time gap between event checks; large values risk missed events
   * @param convergence absolute time accuracy sought when locating the event instant
   */
  @Override
  public void addSwitchingFunction(
      SwitchingFunction function, double maxCheckInterval, double convergence) {
    super.addSwitchingFunction(function, maxCheckInterval, convergence);
    denseOutput = handler.requiresDenseOutput() || !switchesHandler.isEmpty();

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
    // (number of function-calls for each column of the extrapolation table)
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
   * outside {@code [1, 6]} revert to the default of {@code 4}. This setting affects the cost and
   * accuracy of dense output without changing the accepted end-point solution.
   *
   * @param useInterpolationError {@code true} to include interpolation error in step-size control
   * @param mudif interpolation order control offset; values {@code <= 0} or {@code >= 7} reset
   *     default
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
   * <p>The returned value is a stable identifier for logging and reporting. It does not depend on
   * runtime configuration and is safe to compare using string equality. Callers can use this value
   * when presenting solver choices to users or when tagging diagnostic output for later analysis.
   * The value never changes during the lifetime of the process.
   *
   * @return constant string {@code "Gragg-Bulirsch-Stoer"} identifying this integrator
   */
  @Override
  public String getName() {
    return METHOD_NAME;
  }

  /**
   * Update the scaling array used to normalize local error estimates.
   *
   * <p>Each entry combines absolute and relative tolerances with the larger magnitude among the two
   * provided state vectors, mirroring the scaling used by Hairer and Wanner. When vector tolerances
   * are configured, the corresponding element-wise values are used; otherwise scalar tolerances are
   * applied uniformly.
   *
   * @param y1 the first state vector sampled for magnitude; must match the problem dimension
   * @param y2 the second state vector sampled for magnitude; must match the problem dimension
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
   * @param context bundle carrying the equations, step configuration, and scratch buffers used by
   *     the modified midpoint sequence
   * @return {@code true} when the full sequence completed; {@code false} if stability checks failed
   *     and the caller should reduce the step
   * @throws DerivativeException if the user-provided derivative function throws during evaluation
   */
  private boolean tryStep(ModifiedMidpointContext context) throws DerivativeException {

    FirstOrderDifferentialEquations equations = context.equations;
    double t0 = context.t0;
    double[] y0 = context.y0;
    double step = context.step;
    int k = context.k;
    double[] scale = context.scale;
    double[][] f = context.f;
    double[] yMiddle = context.yMiddle;
    double[] yEnd = context.yEnd;
    double[] yTmp = context.yTmp;

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
   * invoked during the process, and dense output is used when required by those handlers.
   *
   * @param equations system of differential equations; dimension must match {@code y0} length
   * @param t0 initial integration time in problem units; may be any finite value
   * @param y0 initial state vector at {@code t0}; length must equal problem dimension
   * @param t target time to reach; may be before {@code t0} for backward runs
   * @param y array receiving the computed state at {@code t}; may alias {@code y0}
   * @throws DerivativeException if the derivative computation fails during evaluation
   * @throws IntegratorException if dimensions mismatch or the step size becomes unusable
   */
  @Override
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

    IntegrationState integrationState =
        new IntegrationState(y, scale, interpolator, workingState, status);
    IntegrationContext integrationContext =
        new IntegrationContext(equations, t, forward, integrationState);
    runIntegrationLoop(integrationContext);
  }

  private void runIntegrationLoop(IntegrationContext context)
      throws DerivativeException, IntegratorException {

    while (!context.status.lastStep) {
      performSingleStep(context);
    }
  }

  private void performSingleStep(IntegrationContext context)
      throws DerivativeException, IntegratorException {

    double targetTime = context.targetTime;
    boolean forward = context.forward;
    StepStatus status = context.status;

    status.reject = false;
    status.loopExit = false;
    prepareNewStep(context);

    stepSize = status.hNew;
    status.lastStep = adjustStepForTarget(targetTime, forward);

    int k = runExtrapolationIterations(context);

    double hInt = getMaxStep();
    if (denseOutput && !status.reject) {
      hInt = handleDenseOutput(context, k);
    }

    if (!status.reject) {
      finalizeAcceptedStep(context, k);
    }

    status.hNew = Math.min(status.hNew, hInt);
    if (!forward) {
      status.hNew = -status.hNew;
    }

    status.firstTime = false;
    updateRejectionStatus(status, status.reject);
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class IntegrationState {
    private final double[] y;
    private final double[] scale;
    private final AbstractStepInterpolator interpolator;
    private final WorkingState workingState;
    private final StepStatus status;

    private IntegrationState(
        double[] y,
        double[] scale,
        AbstractStepInterpolator interpolator,
        WorkingState workingState,
        StepStatus status) {
      this.y = y;
      this.scale = scale;
      this.interpolator = interpolator;
      this.workingState = workingState;
      this.status = status;
    }
  }

  private static final class IntegrationContext {
    private final FirstOrderDifferentialEquations equations;
    private final double targetTime;
    private final double[] y;
    private final boolean forward;
    private final double[] scale;
    private final AbstractStepInterpolator interpolator;
    private final WorkingState workingState;
    private final StepStatus status;

    private IntegrationContext(
        FirstOrderDifferentialEquations equations,
        double targetTime,
        boolean forward,
        IntegrationState state) {
      this.equations = equations;
      this.targetTime = targetTime;
      this.forward = forward;
      this.y = state.y;
      this.scale = state.scale;
      this.interpolator = state.interpolator;
      this.workingState = state.workingState;
      this.status = state.status;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof IntegrationContext context)) {
        return false;
      }
      return context.forward == forward
          && Double.doubleToLongBits(context.targetTime) == Double.doubleToLongBits(targetTime)
          && Objects.equals(context.equations, equations)
          && Arrays.equals(context.y, y)
          && Arrays.equals(context.scale, scale)
          && Objects.equals(context.interpolator, interpolator)
          && Objects.equals(context.workingState, workingState)
          && Objects.equals(context.status, status);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(equations, targetTime, forward, interpolator, workingState, status);
      result = 31 * result + Arrays.hashCode(y);
      result = 31 * result + Arrays.hashCode(scale);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "IntegrationContext["
          + "equations="
          + equations
          + ", targetTime="
          + targetTime
          + ", y="
          + Arrays.toString(y)
          + ", forward="
          + forward
          + ", scale="
          + Arrays.toString(scale)
          + ", interpolator="
          + interpolator
          + ", workingState="
          + workingState
          + ", status="
          + status
          + "]";
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class ModifiedMidpointState {
    private final double t0;
    private final double[] y0;
    private final double step;
    private final int k;

    private ModifiedMidpointState(double t0, double[] y0, double step, int k) {
      this.t0 = t0;
      this.y0 = y0;
      this.step = step;
      this.k = k;
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class ModifiedMidpointBuffers {
    private final double[] scale;
    private final double[][] f;
    private final double[] yMiddle;
    private final double[] yEnd;
    private final double[] yTmp;

    private ModifiedMidpointBuffers(
        double[] scale, double[][] f, double[] yMiddle, double[] yEnd, double[] yTmp) {
      this.scale = scale;
      this.f = f;
      this.yMiddle = yMiddle;
      this.yEnd = yEnd;
      this.yTmp = yTmp;
    }
  }

  private static final class ModifiedMidpointContext {
    private final FirstOrderDifferentialEquations equations;
    private final double t0;
    private final double[] y0;
    private final double step;
    private final int k;
    private final double[] scale;
    private final double[][] f;
    private final double[] yMiddle;
    private final double[] yEnd;
    private final double[] yTmp;

    private ModifiedMidpointContext(
        FirstOrderDifferentialEquations equations,
        ModifiedMidpointState state,
        ModifiedMidpointBuffers buffers) {
      this.equations = equations;
      this.t0 = state.t0;
      this.y0 = state.y0;
      this.step = state.step;
      this.k = state.k;
      this.scale = buffers.scale;
      this.f = buffers.f;
      this.yMiddle = buffers.yMiddle;
      this.yEnd = buffers.yEnd;
      this.yTmp = buffers.yTmp;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof ModifiedMidpointContext context)) {
        return false;
      }
      return context.k == k
          && Double.doubleToLongBits(context.t0) == Double.doubleToLongBits(t0)
          && Double.doubleToLongBits(context.step) == Double.doubleToLongBits(step)
          && Objects.equals(context.equations, equations)
          && Arrays.equals(context.y0, y0)
          && Arrays.equals(context.scale, scale)
          && Arrays.deepEquals(context.f, f)
          && Arrays.equals(context.yMiddle, yMiddle)
          && Arrays.equals(context.yEnd, yEnd)
          && Arrays.equals(context.yTmp, yTmp);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(equations, t0, step, k);
      result = 31 * result + Arrays.hashCode(y0);
      result = 31 * result + Arrays.hashCode(scale);
      result = 31 * result + Arrays.deepHashCode(f);
      result = 31 * result + Arrays.hashCode(yMiddle);
      result = 31 * result + Arrays.hashCode(yEnd);
      result = 31 * result + Arrays.hashCode(yTmp);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "ModifiedMidpointContext["
          + "equations="
          + equations
          + ", t0="
          + t0
          + ", y0="
          + Arrays.toString(y0)
          + ", step="
          + step
          + ", k="
          + k
          + ", scale="
          + Arrays.toString(scale)
          + ", f="
          + Arrays.deepToString(f)
          + ", yMiddle="
          + Arrays.toString(yMiddle)
          + ", yEnd="
          + Arrays.toString(yEnd)
          + ", yTmp="
          + Arrays.toString(yTmp)
          + "]";
    }
  }

  /**
   * Store results for an accepted step, notify handlers, and prepare the next trial size/order.
   *
   * @param context integration context carrying state, interpolator, and working buffers
   * @param k last successful extrapolation column
   * @throws DerivativeException if switching functions require additional derivative evaluations
   * @throws IntegratorException if event processing or handler logic raises integration-level
   *     errors
   */
  private void finalizeAcceptedStep(IntegrationContext context, int k)
      throws DerivativeException, IntegratorException {

    double[] y = context.y;
    AbstractStepInterpolator interpolator = context.interpolator;
    WorkingState w = context.workingState;
    StepStatus status = context.status;

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

  private void prepareNewStep(IntegrationContext context) throws DerivativeException {

    FirstOrderDifferentialEquations equations = context.equations;
    double[] y = context.y;
    boolean forward = context.forward;
    double[] scale = context.scale;
    AbstractStepInterpolator interpolator = context.interpolator;
    WorkingState w = context.workingState;
    StepStatus status = context.status;

    status.reject = false;
    if (!status.newStep) {
      return;
    }

    interpolator.shift();
    if (!status.firstStepAlreadyComputed) {
      equations.computeDerivatives(stepStart, y, w.yDot0);
    }

    if (status.firstTime) {
      StepInitializationInputs inputs =
          new StepInitializationInputs(
              equations, forward, 2 * status.targetIter + 1, scale, stepStart, y, w.yDot0);
      StepInitializationWorkspace workspace = new StepInitializationWorkspace(w.yTmp, w.yTmpDot);
      status.hNew = initializeStep(new StepInitializationContext(inputs, workspace));
      if (!forward) {
        status.hNew = -status.hNew;
      }
    }

    status.newStep = false;
  }

  private boolean adjustStepForTarget(double targetTime, boolean forward) {
    if ((forward && (stepStart + stepSize > targetTime))
        || (!forward && (stepStart + stepSize < targetTime))) {
      stepSize = targetTime - stepStart;
    }
    double nextT = stepStart + stepSize;
    return forward ? (nextT >= targetTime) : (nextT <= targetTime);
  }

  private int runExtrapolationIterations(IntegrationContext context)
      throws DerivativeException, IntegratorException {

    StepStatus status = context.status;
    int k = -1;
    boolean shouldContinue;
    do {
      status.loopExit = false;
      ++k;
      if (!tryCurrentSubStep(context, k)) {
        break;
      }

      shouldContinue = k == 0;
      if (!shouldContinue) {
        computeExtrapolationAndError(context, k);
        shouldContinue = !(status.reject || status.loopExit);
      }
    } while (shouldContinue);

    return k;
  }

  private boolean tryCurrentSubStep(IntegrationContext context, int k)
      throws DerivativeException, IntegratorException {

    FirstOrderDifferentialEquations equations = context.equations;
    double[] y = context.y;
    double[] scale = context.scale;
    WorkingState w = context.workingState;
    StepStatus status = context.status;

    ModifiedMidpointState stepState = new ModifiedMidpointState(stepStart, y, stepSize, k);
    ModifiedMidpointBuffers buffers =
        new ModifiedMidpointBuffers(
            scale,
            w.fk[k],
            (k == 0) ? w.yMidDots[0] : w.diagonal[k - 1],
            (k == 0) ? w.y1 : w.y1Diag[k - 1],
            w.yTmp);
    if (tryStep(new ModifiedMidpointContext(equations, stepState, buffers))) {
      return true;
    }

    status.hNew = Math.abs(filterStep(stepSize * stabilityReduction, false));
    status.reject = true;
    status.loopExit = true;
    return false;
  }

  private void computeExtrapolationAndError(IntegrationContext context, int k)
      throws IntegratorException {

    double[] y = context.y;
    double[] scale = context.scale;
    WorkingState w = context.workingState;
    StepStatus status = context.status;

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
      case -1 -> handleConvergenceBeforeTarget(k, error, status);
      case 0 -> handleConvergenceAtTarget(error, status);
      case 1 -> {
        if (error > 1.0) {
          rejectAndReduceOrder(status);
        }
        status.loopExit = true;
      }
      default -> {
        if ((status.firstTime || status.lastStep) && (error <= 1.0)) {
          status.loopExit = true;
        }
      }
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

  private double handleDenseOutput(IntegrationContext context, int k) throws DerivativeException {

    FirstOrderDifferentialEquations equations = context.equations;
    double[] y = context.y;
    AbstractStepInterpolator interpolator = context.interpolator;
    WorkingState w = context.workingState;
    StepStatus status = context.status;

    for (int j = 1; j <= k; ++j) {
      extrapolate(0, j, w.diagonal, w.yMidDots[0]);
    }

    equations.computeDerivatives(stepStart + stepSize, w.y1, w.yDot1);
    int mu = 2 * k - mudif + 3;
    computeDenseOutputDerivatives(y.length, w, k, mu);

    double hInt = getMaxStep();
    if (mu >= 0) {
      hInt = applyInterpolationErrorControl(context, mu, hInt);
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

  private double applyInterpolationErrorControl(IntegrationContext context, int mu, double hInt) {

    double[] scale = context.scale;
    AbstractStepInterpolator interpolator = context.interpolator;
    StepStatus status = context.status;

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
    if (denseOutput || !switchesHandler.isEmpty()) {
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

    @Override
    public String toString() {
      return "WorkingState[dimension="
          + y1.length
          + ", sequenceLength="
          + sequence.length
          + ", denseOutput="
          + denseOutput
          + "]";
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

    @Override
    public String toString() {
      return "StepStatus[hNew="
          + hNew
          + ", maxError="
          + maxError
          + ", targetIter="
          + targetIter
          + ", firstTime="
          + firstTime
          + ", lastStep="
          + lastStep
          + ", reject="
          + reject
          + "]";
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
