package org.spaceroots.mantissa.ode;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serial;

/**
 * Dense-output interpolator used by the Gragg-Bulirsch-Stoer integrator.
 *
 * <p>The interpolator reconstructs states and derivatives anywhere inside the last accepted step
 * produced by {@link GraggBulirschStoerIntegrator}. It evaluates Hermite-like polynomials whose
 * coefficients are derived from step end-points and midpoint derivative estimates, allowing client
 * code to query the solution with sub-step resolution without re-running the integrator. Typical
 * usage is to call {@link #computeCoefficients(int, double)} once a step is accepted, then invoke
 * {@link #setInterpolatedTime(double)} (inherited from the base class) repeatedly to obtain dense
 * output through {@link #getInterpolatedState()}.
 *
 * <p>The class maintains no internal synchronization; instances are mutable and must be confined to
 * a single integration thread. State remains valid only until the integrator advances past the
 * buffered step. Polynomial degree grows with extrapolation order, trading accuracy for additional
 * computation; {@link #estimateError(double[])} gives a normalized error hint for callers deciding
 * whether dense evaluations are trustworthy at the chosen order.
 *
 * <ul>
 *   <li>Computes and stores interpolation polynomials up to the requested degree.
 *   <li>Supports serialization so checkpointed integrators can be restored mid-step.
 *   <li>Mirrors the algorithms from the original Fortran <a
 *       href="http://www.unige.ch/math/folks/hairer/prog/nonstiff/odex.f">odex</a> implementation,
 *       retaining the same error-control heuristics.
 * </ul>
 *
 * <p>Redistribution and use in source and binary forms, with or without modification, are permitted
 * under the terms reproduced from the original distribution notice available <a
 * href="http://www.unige.ch/~hairer/prog/licence.txt">here</a>.
 *
 * @see GraggBulirschStoerIntegrator
 * @version $Id: GraggBulirschStoerStepInterpolator.java 1702 2006-09-10 19:52:58Z luc $
 * @author E. Hairer and G. Wanner (fortran version)
 * @author L. Maisonobe (Java port)
 */
class GraggBulirschStoerStepInterpolator extends AbstractStepInterpolator
    implements StepInterpolator {

  /** Slope at the beginning of the step. */
  private final double[] y0Dot;

  /** State at the end of the step. */
  private final double[] y1;

  /** Slope at the end of the step. */
  private final double[] y1Dot;

  /**
   * Derivatives at the middle of the step. element 0 is state at midpoint, element 1 is first
   * derivative ...
   */
  private final double[][] yMidDots;

  /** Interpolation polynoms. */
  private double[][] polynoms;

  /** Error coefficients for the interpolation. */
  private double[] errfac;

  /** Degree of the interpolation polynoms. */
  private int currentDegree;

  /**
   * Reallocate the internal tables in order to be able to handle interpolation polynoms up to the
   * given degree.
   *
   * @param maxDegree maximal degree to handle when recomputing polynomial storage
   */
  private void resetTables(int maxDegree) {

    if (maxDegree < 0) {
      clearTables();
      return;
    }

    initializePolynoms(maxDegree);
    initializeErrorFactors(maxDegree);
    currentDegree = 0;
  }

  private void clearTables() {
    polynoms = null;
    errfac = null;
    currentDegree = -1;
  }

  private void initializePolynoms(int maxDegree) {
    double[][] newPols = new double[maxDegree + 1][];
    if (polynoms != null) {
      System.arraycopy(polynoms, 0, newPols, 0, polynoms.length);
      for (int i = polynoms.length; i < newPols.length; ++i) {
        newPols[i] = new double[currentState.length];
      }
    } else {
      for (int i = 0; i < newPols.length; ++i) {
        newPols[i] = new double[currentState.length];
      }
    }
    polynoms = newPols;
  }

  private void initializeErrorFactors(int maxDegree) {
    if (maxDegree <= 4) {
      errfac = null;
      return;
    }

    errfac = new double[maxDegree - 4];
    for (int i = 0; i < errfac.length; ++i) {
      int ip5 = i + 5;
      errfac[i] = 1.0 / (ip5 * ip5);
      double e = 0.5 * Math.sqrt(((double) (i + 1)) / ip5);
      for (int j = 0; j <= i; ++j) {
        errfac[i] *= e / (j + 1);
      }
    }
  }

  /**
   * Simple constructor intended only for the serialization framework.
   *
   * <p>Creates an uninitialized instance whose arrays are null and whose internal tables are sized
   * for no interpolation degree. Regular callers should let the owning integrator build instances
   * with the parameterized constructor so state vectors are immediately wired; this form exists so
   * deserialization can populate fields manually before use.
   */
  public GraggBulirschStoerStepInterpolator() {
    y0Dot = null;
    y1 = null;
    y1Dot = null;
    yMidDots = null;
    resetTables(-1);
  }

  /**
   * Constructor wiring the current step data produced by the integrator.
   *
   * @param y reference to the integrator array holding the current state values, reused by the
   *     interpolator without copying
   * @param y0Dot reference to the integrator array holding the slope at the beginning of the step;
   *     same length and indexing as {@code y}
   * @param y1 reference to the integrator array holding the state at the end of the step that will
   *     be interpolated
   * @param y1Dot reference to the integrator array holding the slope at the end of the step, used
   *     for Hermite coefficients
   * @param yMidDots reference to the integrator array holding the derivatives at the middle point
   *     of the step for increasing interpolation orders
   * @param forward integration direction indicator; {@code true} for forward time, {@code false}
   *     for backward integration
   */
  public GraggBulirschStoerStepInterpolator(
      double[] y,
      double[] y0Dot,
      double[] y1,
      double[] y1Dot,
      double[][] yMidDots,
      boolean forward) {

    super(y, forward);
    this.y0Dot = y0Dot;
    this.y1 = y1;
    this.y1Dot = y1Dot;
    this.yMidDots = yMidDots;

    resetTables(yMidDots.length + 4);
  }

  /**
   * Copy constructor performing a deep copy of polynomial storage.
   *
   * <p>Copies base interpolator state and duplicates all polynomial arrays up to the current degree
   * so that dense evaluations on the new instance do not share mutable storage with the source.
   * Temporary derivative buffers are deliberately left null to minimize memory footprint.
   *
   * @param interpolator interpolator to copy from; array contents are duplicated so the new
   *     instance evolves independently of the source
   */
  public GraggBulirschStoerStepInterpolator(GraggBulirschStoerStepInterpolator interpolator) {

    super(interpolator);

    int dimension = currentState.length;

    // the interpolator has been finalized,
    // the following arrays are not needed anymore
    y0Dot = null;
    y1 = null;
    y1Dot = null;
    yMidDots = null;

    // copy the interpolation polynoms (up to the current degree only)
    if (interpolator.polynoms == null) {
      polynoms = null;
      currentDegree = -1;
    } else {
      resetTables(interpolator.currentDegree);
      for (int i = 0; i < polynoms.length; ++i) {
        polynoms[i] = new double[dimension];
        System.arraycopy(interpolator.polynoms[i], 0, polynoms[i], 0, dimension);
      }
      currentDegree = interpolator.currentDegree;
      errfac = interpolator.errfac == null ? null : interpolator.errfac.clone();
      return;
    }

    errfac = null;
  }

  /**
   * Create a deep copy of this interpolator.
   *
   * <p>The returned instance preserves the same polynomial degree and coefficients so it can
   * produce identical dense output for the current step, yet owns independent arrays to avoid
   * accidental cross-thread mutation. Subsequent calls to {@link #computeCoefficients(int, double)}
   * on either instance will diverge safely.
   *
   * @return a new interpolator carrying the same step data while owning separate mutable storage
   */
  @Override
  public GraggBulirschStoerStepInterpolator copy() {
    return new GraggBulirschStoerStepInterpolator(this);
  }

  /**
   * Compute the interpolation coefficients for dense output.
   *
   * <p>This method must be invoked once a trial step is accepted so that subsequent calls to {@link
   * #setInterpolatedTime(double)} can evaluate intermediate states. It fills the polynomial arrays
   * up to degree {@code mu + 4}, expanding storage if necessary. Callers should reuse the instance
   * across steps to avoid allocations.
   *
   * @param mu degree of the interpolation polynom, typically derived from the extrapolation order
   *     chosen by the integrator
   * @param h current step size in integration units; sign matches the integration direction
   */
  public void computeCoefficients(int mu, double h) {

    if ((polynoms == null) || (polynoms.length <= (mu + 4))) {
      resetTables(mu + 4);
    }

    currentDegree = mu + 4;

    for (int i = 0; i < currentState.length; ++i) {
      computeCoefficientsForIndex(mu, h, i);
    }
  }

  private void computeCoefficientsForIndex(int mu, double h, int index) {

    double yp0 = h * y0Dot[index];
    double yp1 = h * y1Dot[index];
    double ydiff = y1[index] - currentState[index];
    double aspl = ydiff - yp1;
    double bspl = yp0 - ydiff;

    polynoms[0][index] = currentState[index];
    polynoms[1][index] = ydiff;
    polynoms[2][index] = aspl;
    polynoms[3][index] = bspl;

    if (mu < 0) {
      return;
    }

    computeHigherDegreeCoefficients(mu, index, yp0, yp1, ydiff, aspl, bspl);
  }

  private void computeHigherDegreeCoefficients(
      int mu, int index, double yp0, double yp1, double ydiff, double aspl, double bspl) {

    double ph0 = 0.5 * (currentState[index] + y1[index]) + 0.125 * (aspl + bspl);
    polynoms[4][index] = 16 * (yMidDots[0][index] - ph0);

    if (mu == 0) {
      return;
    }

    double ph1 = ydiff + 0.25 * (aspl - bspl);
    polynoms[5][index] = 16 * (yMidDots[1][index] - ph1);

    if (mu == 1) {
      return;
    }

    double ph2 = yp1 - yp0;
    polynoms[6][index] = 16 * (yMidDots[2][index] - ph2 + polynoms[4][index]);

    if (mu == 2) {
      return;
    }

    double ph3 = 6 * (bspl - aspl);
    polynoms[7][index] = 16 * (yMidDots[3][index] - ph3 + 3 * polynoms[5][index]);

    for (int j = 4; j <= mu; ++j) {
      double fac1 = 0.5 * j * (j - 1);
      double fac2 = 2 * fac1 * (j - 2) * (j - 3);
      polynoms[j + 4][index] =
          16 * (yMidDots[j][index] + fac1 * polynoms[j + 2][index] - fac2 * polynoms[j][index]);
    }
  }

  /**
   * Estimate interpolation error.
   *
   * <p>The estimate uses the highest available polynomial degree and the precomputed error factors
   * described in the original algorithm. It returns a weighted root-mean-square norm of the leading
   * term scaled by {@code scale}, and falls back to zero when the degree is insufficient to form an
   * error estimate.
   *
   * @param scale scaling array matching the state dimension; each entry must be non-zero to avoid
   *     division errors and should reflect acceptable absolute or relative magnitudes
   * @return estimate of the interpolation error; zero when degree is below five or scaling hides
   *     the contribution
   */
  public double estimateError(double[] scale) {
    double error = 0;
    if (currentDegree >= 5) {
      for (int i = 0; i < currentState.length; ++i) {
        double e = polynoms[currentDegree][i] / scale[i];
        error += e * e;
      }
      error = Math.sqrt(error / currentState.length) * errfac[currentDegree - 5];
    }
    return error;
  }

  /**
   * Compute the state at the interpolated time.
   *
   * <p>Uses the stored polynomial coefficients to build the dense solution corresponding to the
   * current value of {@code theta}. The computation is side-effect free except for writing the
   * inherited {@code interpolatedState} array. The method assumes coefficients have already been
   * prepared by {@link #computeCoefficients(int, double)} for the current step.
   *
   * @param theta normalized interpolation abscissa within the step; {@code 0} targets the previous
   *     step end, {@code 1} targets the current end, and intermediate values return dense output
   * @param oneMinusThetaH time gap between the interpolated time and the current time; must match
   *     the step direction so derived classes can reuse it consistently
   * @throws DerivativeException propagated unchanged if the underlying user function signalled an
   *     error while evaluating derivatives needed for interpolation
   */
  @Override
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    int dimension = currentState.length;

    double oneMinusTheta = 1.0 - theta;
    double theta05 = theta - 0.5;
    double t4 = theta * oneMinusTheta;
    t4 = t4 * t4;

    for (int i = 0; i < dimension; ++i) {
      interpolatedState[i] =
          baseInterpolatedValue(
              theta, oneMinusTheta, polynoms[0][i], polynoms[1][i], polynoms[2][i], polynoms[3][i]);

      if (currentDegree > 3) {
        interpolatedState[i] += t4 * interpolateHigherDegree(theta05, i);
      }
    }
  }

  private double baseInterpolatedValue(
      double theta, double oneMinusTheta, double p0, double p1, double p2, double p3) {
    return p0 + theta * (p1 + oneMinusTheta * (p2 * theta + p3 * oneMinusTheta));
  }

  private double interpolateHigherDegree(double theta05, int index) {
    double c = polynoms[currentDegree][index];
    for (int j = currentDegree - 1; j > 3; --j) {
      c = polynoms[j][index] + c * theta05 / (j - 3);
    }
    return c;
  }

  /**
   * Save the state of the instance.
   *
   * <p>Serialization stores only the polynomial coefficients and degree for the current step; it
   * does not persist transient work arrays. Callers must ensure the base interpolator state has
   * already been prepared before invoking this method.
   *
   * @param out stream where to save the state; must remain open for the duration of the write
   * @throws IOException in case of write error or if the target stream rejects data
   */
  @Override
  public void writeExternal(ObjectOutput out) throws IOException {

    int dimension = currentState.length;

    // save the state of the base class
    writeBaseExternal(out);

    // save the local attributes (but not the temporary vectors)
    out.writeInt(currentDegree);
    for (int k = 0; k <= currentDegree; ++k) {
      for (int l = 0; l < dimension; ++l) {
        out.writeDouble(polynoms[k][l]);
      }
    }
  }

  /**
   * Read the state of the instance.
   *
   * <p>Restores the base interpolator data and all polynomial coefficients for the pending step.
   * After deserialization, the interpolator is ready to answer dense-output queries at the time
   * supplied through {@link #setInterpolatedTime(double)} during this method.
   *
   * @param in stream where to read the state from; must supply the same structure written by {@link
   *     #writeExternal(ObjectOutput)}
   * @throws IOException in case of read error or when a derivative evaluation fails while restoring
   *     the interpolated time
   */
  @Override
  public void readExternal(ObjectInput in) throws IOException {

    // read the base class
    double t = readBaseExternal(in);
    int dimension = currentState.length;

    // read the local attributes
    int degree = in.readInt();
    resetTables(degree);
    currentDegree = degree;

    for (int k = 0; k <= currentDegree; ++k) {
      for (int l = 0; l < dimension; ++l) {
        polynoms[k][l] = in.readDouble();
      }
    }

    try {
      // we can now set the interpolated time and state
      setInterpolatedTime(t);
    } catch (DerivativeException e) {
      throw new IOException(e);
    }
  }

  @Serial private static final long serialVersionUID = 7320613236731409847L;
}
