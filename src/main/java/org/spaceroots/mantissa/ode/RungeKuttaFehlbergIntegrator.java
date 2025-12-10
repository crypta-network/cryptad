package org.spaceroots.mantissa.ode;

import java.util.Arrays;

/**
 * This class implements the common part of all Runge-Kutta-Fehlberg integrators for Ordinary
 * Differential Equations.
 *
 * <p>These methods are embedded explicit Runge-Kutta methods with two sets of coefficients allowing
 * to estimate the error, their Butcher arrays are as follows :
 *
 * <pre>
 *    0  |
 *   c2  | a21
 *   c3  | a31  a32
 *   ... |        ...
 *   cs  | as1  as2  ...  ass-1
 *       |--------------------------
 *       |  b1   b2  ...   bs-1  bs
 *       |  b'1  b'2 ...   b's-1 b's
 * </pre>
 *
 * <p>In fact, we rather use the array defined by ej = bj - b'j to compute directly the error rather
 * than computing two estimates and then comparing them.
 *
 * <p>Some methods are qualified as <i>fsal</i> (first same as last) methods. This means the last
 * evaluation of the derivatives in one step is the same as the first in the next step. Then, this
 * evaluation can be reused from one step to the next one and the cost of such a method is really
 * s-1 evaluations despite the method still has s stages. This behaviour is true only for successful
 * steps, if the step is rejected after the error estimation phase, no evaluation is saved. For an
 * <i>fsal</i> method, we have cs = 1 and asi = bi for all i.
 *
 * @version $Id: RungeKuttaFehlbergIntegrator.java 1719 2007-09-26 19:46:57Z luc $
 * @author L. Maisonobe
 */
public abstract class RungeKuttaFehlbergIntegrator extends AdaptiveStepsizeIntegrator {

  /**
   * Build a Runge-Kutta integrator with the given Butcher array.
   *
   * @param fsal indicate that the method is an <i>fsal</i>
   * @param c time steps from Butcher array (without the first zero)
   * @param a internal weights from Butcher array (without the first empty row)
   * @param b external weights for the high order method from Butcher array
   * @param prototype prototype of the step interpolator to use
   * @param minStep minimal step (must be positive even for backward integration), the last step can
   *     be smaller than this
   * @param maxStep maximal step (must be positive even for backward integration)
   * @param scalAbsoluteTolerance allowed absolute error
   * @param scalRelativeTolerance allowed relative error
   */
  protected RungeKuttaFehlbergIntegrator(
      boolean fsal,
      double[] c,
      double[][] a,
      double[] b,
      RungeKuttaStepInterpolator prototype,
      double minStep,
      double maxStep,
      double scalAbsoluteTolerance,
      double scalRelativeTolerance) {

    super(minStep, maxStep, scalAbsoluteTolerance, scalRelativeTolerance);

    this.fsal = fsal;
    this.c = c;
    this.a = a;
    this.b = b;
    this.prototype = prototype;

    exp = -1.0 / getOrder();

    this.safety = 0.9;

    // set the default values of the algorithm control parameters
    setMinReduction(0.2);
    setMaxGrowth(10.0);
  }

  /**
   * Build a Runge-Kutta integrator with the given Butcher array.
   *
   * @param fsal indicate that the method is an <i>fsal</i>
   * @param c time steps from Butcher array (without the first zero)
   * @param a internal weights from Butcher array (without the first empty row)
   * @param b external weights for the high order method from Butcher array
   * @param prototype prototype of the step interpolator to use
   * @param minStep minimal step (must be positive even for backward integration), the last step can
   *     be smaller than this
   * @param maxStep maximal step (must be positive even for backward integration)
   * @param vecAbsoluteTolerance allowed absolute error
   * @param vecRelativeTolerance allowed relative error
   */
  protected RungeKuttaFehlbergIntegrator(
      boolean fsal,
      double[] c,
      double[][] a,
      double[] b,
      RungeKuttaStepInterpolator prototype,
      double minStep,
      double maxStep,
      double[] vecAbsoluteTolerance,
      double[] vecRelativeTolerance) {

    super(minStep, maxStep, vecAbsoluteTolerance, vecRelativeTolerance);

    this.fsal = fsal;
    this.c = c;
    this.a = a;
    this.b = b;
    this.prototype = prototype;

    exp = -1.0 / getOrder();

    this.safety = 0.9;

    // set the default values of the algorithm control parameters
    setMinReduction(0.2);
    setMaxGrowth(10.0);
  }

  /**
   * Get the order of the method.
   *
   * @return order of the method
   */
  public abstract int getOrder();

  /**
   * Get the safety factor for stepsize control.
   *
   * @return safety factor
   */
  public double getSafety() {
    return safety;
  }

  /**
   * Set the safety factor for stepsize control.
   *
   * @param safety safety factor
   */
  public void setSafety(double safety) {
    this.safety = safety;
  }

  public void integrate(
      FirstOrderDifferentialEquations equations, double t0, double[] y0, double t, double[] y)
      throws DerivativeException, IntegratorException {

    checkSanity(equations, t0, y0, t);
    boolean forward = (t > t0);
    int stages = c.length + 1;
    if (y != y0) {
      System.arraycopy(y0, 0, y, 0, y0.length);
    }

    StepContext context = new StepContext(stages, y0.length);
    AbstractStepInterpolator interpolator =
        createInterpolator(equations, context.yTmp, context.yDotK, forward);
    interpolator.storeTime(t0);

    stepStart = t0;
    handler.reset();
    boolean lastStep;
    do {
      lastStep = performStep(equations, t, y, forward, stages, context, interpolator);
    } while (!lastStep);

    resetInternalState();
  }

  /**
   * Get the minimal reduction factor for stepsize control.
   *
   * @return minimal reduction factor
   */
  @SuppressWarnings("unused")
  public double getMinReduction() {
    return minReduction;
  }

  /**
   * Set the minimal reduction factor for stepsize control.
   *
   * @param minReduction minimal reduction factor
   */
  public void setMinReduction(double minReduction) {
    this.minReduction = minReduction;
  }

  /**
   * Get the maximal growth factor for stepsize control.
   *
   * @return maximal growth factor
   */
  @SuppressWarnings("unused")
  public double getMaxGrowth() {
    return maxGrowth;
  }

  /**
   * Set the maximal growth factor for stepsize control.
   *
   * @param maxGrowth maximal growth factor
   */
  public void setMaxGrowth(double maxGrowth) {
    this.maxGrowth = maxGrowth;
  }

  /**
   * Compute the error ratio.
   *
   * @param yDotK derivatives computed during the first stages
   * @param y0 estimate of the step at the start of the step
   * @param y1 estimate of the step at the end of the step
   * @param h current step
   * @return error ratio, greater than 1 if step should be rejected
   */
  protected abstract double estimateError(double[][] yDotK, double[] y0, double[] y1, double h);

  private void checkSanity(
      FirstOrderDifferentialEquations equations, double t0, double[] y0, double t)
      throws IntegratorException {

    if (equations.getDimension() != y0.length) {
      throw new IntegratorException(
          "dimensions mismatch: ODE problem has dimension {0}," + " state vector has dimension {1}",
          new String[] {Integer.toString(equations.getDimension()), Integer.toString(y0.length)});
    }
    if (Math.abs(t - t0) <= 1.0e-12 * Math.max(Math.abs(t0), Math.abs(t))) {
      throw new IntegratorException(
          "too small integration interval: length = {0}",
          new String[] {Double.toString(Math.abs(t - t0))});
    }
  }

  private AbstractStepInterpolator createInterpolator(
      FirstOrderDifferentialEquations equations, double[] yTmp, double[][] yDotK, boolean forward) {

    if (handler.requiresDenseOutput() || (!switchesHandler.isEmpty())) {
      RungeKuttaStepInterpolator rki = (RungeKuttaStepInterpolator) prototype.copy();
      rki.reinitialize(equations, yTmp, yDotK, forward);
      return rki;
    }
    return new DummyStepInterpolator(yTmp, forward);
  }

  private boolean performStep(
      FirstOrderDifferentialEquations equations,
      double t,
      double[] y,
      boolean forward,
      int stages,
      StepContext context,
      AbstractStepInterpolator interpolator)
      throws DerivativeException, IntegratorException {

    interpolator.shift();

    double error = 0.0;
    boolean accepted = false;
    while (!accepted) {
      computeFirstStageIfNeeded(equations, y, context);
      initializeStepIfFirstTime(equations, forward, y, context);
      adjustStepSizeNearTarget(t, forward, context);
      computeStages(equations, stages, y, context);
      estimateEndState(y, stages, context);
      error = estimateError(context.yDotK, y, context.yTmp, stepSize);
      accepted = evaluateStepAcceptance(interpolator, error, context);
    }

    updateAfterAcceptance(equations, t, y, forward, stages, context, error, interpolator);
    return computeLastStepFlag(t, forward);
  }

  private void computeFirstStageIfNeeded(
      FirstOrderDifferentialEquations equations, double[] y, StepContext context)
      throws DerivativeException {

    if (context.firstTime || !fsal) {
      equations.computeDerivatives(stepStart, y, context.yDotK[0]);
    }
  }

  private void initializeStepIfFirstTime(
      FirstOrderDifferentialEquations equations, boolean forward, double[] y, StepContext context)
      throws DerivativeException {

    if (!context.firstTime) {
      return;
    }

    double[] scale = (vecAbsoluteTolerance != null) ? vecAbsoluteTolerance : buildScalarScale(y);
    context.hNew =
        initializeStep(
            equations,
            forward,
            getOrder(),
            scale,
            stepStart,
            y,
            context.yDotK[0],
            context.yTmp,
            context.yDotK[1]);
    context.firstTime = false;
  }

  private double[] buildScalarScale(double[] y) {
    double[] scale = new double[y.length];
    Arrays.fill(scale, scalAbsoluteTolerance);
    return scale;
  }

  private void adjustStepSizeNearTarget(double t, boolean forward, StepContext context) {
    stepSize = context.hNew;
    boolean beyondTarget =
        (forward && (stepStart + stepSize > t)) || ((!forward) && (stepStart + stepSize < t));
    if (beyondTarget) {
      stepSize = t - stepStart;
    }
  }

  private void computeStages(
      FirstOrderDifferentialEquations equations, int stages, double[] y, StepContext context)
      throws DerivativeException {

    for (int k = 1; k < stages; ++k) {
      for (int j = 0; j < y.length; ++j) {
        double sum = a[k - 1][0] * context.yDotK[0][j];
        for (int l = 1; l < k; ++l) {
          sum += a[k - 1][l] * context.yDotK[l][j];
        }
        context.yTmp[j] = y[j] + stepSize * sum;
      }
      equations.computeDerivatives(stepStart + c[k - 1] * stepSize, context.yTmp, context.yDotK[k]);
    }
  }

  private void estimateEndState(double[] y, int stages, StepContext context) {
    for (int j = 0; j < y.length; ++j) {
      double sum = b[0] * context.yDotK[0][j];
      for (int l = 1; l < stages; ++l) {
        sum += b[l] * context.yDotK[l][j];
      }
      context.yTmp[j] = y[j] + stepSize * sum;
    }
  }

  private boolean evaluateStepAcceptance(
      AbstractStepInterpolator interpolator, double error, StepContext context)
      throws IntegratorException {

    if (error > 1.0) {
      double factor = Math.clamp(safety * Math.pow(error, exp), minReduction, maxGrowth);
      context.hNew = filterStep(stepSize * factor, false);
      return false;
    }

    interpolator.storeTime(stepStart + stepSize);
    if (switchesHandler.evaluateStep((StepInterpolator) interpolator)) {
      context.hNew = switchesHandler.getEventTime() - stepStart;
      return false;
    }
    return true;
  }

  private void updateAfterAcceptance(
      FirstOrderDifferentialEquations equations,
      double t,
      double[] y,
      boolean forward,
      int stages,
      StepContext context,
      double error,
      AbstractStepInterpolator interpolator)
      throws DerivativeException, IntegratorException {

    stepStart += stepSize;
    System.arraycopy(context.yTmp, 0, y, 0, y.length);
    switchesHandler.stepAccepted(stepStart, y);
    boolean lastStep = computeLastStepFlag(t, forward);
    interpolator.storeTime(stepStart);
    handler.handleStep((StepInterpolator) interpolator, lastStep);

    if (fsal) {
      System.arraycopy(context.yDotK[stages - 1], 0, context.yDotK[0], 0, y.length);
    }

    if (switchesHandler.reset(stepStart, y) && !lastStep) {
      equations.computeDerivatives(stepStart, y, context.yDotK[0]);
    }

    if (!lastStep) {
      double factor = Math.clamp(safety * Math.pow(error, exp), minReduction, maxGrowth);
      double scaledH = stepSize * factor;
      double nextT = stepStart + scaledH;
      boolean nextIsLast = forward ? (nextT >= t) : (nextT <= t);
      context.hNew = filterStep(scaledH, nextIsLast);
    }
  }

  private boolean computeLastStepFlag(double t, boolean forward) {
    boolean stop = switchesHandler.stop();
    if (stop) {
      return true;
    }
    return forward ? (stepStart >= t) : (stepStart <= t);
  }

  private static final class StepContext {
    private final double[][] yDotK;
    private final double[] yTmp;
    private double hNew;
    private boolean firstTime = true;

    private StepContext(int stages, int dimension) {
      yDotK = new double[stages][];
      for (int i = 0; i < stages; ++i) {
        yDotK[i] = new double[dimension];
      }
      yTmp = new double[dimension];
    }
  }

  /** Indicator for <i>fsal</i> methods. */
  private final boolean fsal;

  /** Time steps from Butcher array (without the first zero). */
  private final double[] c;

  /** Internal weights from Butcher array (without the first empty row). */
  private final double[][] a;

  /** External weights for the high order method from Butcher array. */
  private final double[] b;

  /** Prototype of the step interpolator. */
  private final RungeKuttaStepInterpolator prototype;

  /** Stepsize control exponent. */
  private final double exp;

  /** Safety factor for stepsize control. */
  private double safety;

  /** Minimal reduction factor for stepsize control. */
  private double minReduction;

  /** Maximal growth factor for stepsize control. */
  private double maxGrowth;
}
