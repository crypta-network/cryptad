package org.spaceroots.mantissa.ode;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serial;

/**
 * Step interpolator for the Dormand–Prince 8(5,3) Runge-Kutta method.
 *
 * <p>This implementation reconstructs intermediate states inside the last accepted integration
 * step, allowing dense output and precise event localization without re-running derivative
 * evaluations. Instances are typically created as lightweight prototypes by {@link
 * DormandPrince853Integrator} and are reinitialized per step with shared work arrays to minimize
 * allocations. The interpolator assumes the owning integrator keeps the Butcher tableau weights and
 * all stage derivatives consistent with the 8(5,3) scheme and that {@link #doFinalize()} is invoked
 * before any interpolation after a step is stored.
 *
 * <p>Objects are mutable and reused; they hold transient state like cached slope vectors {@code v}
 * and temporary buffers. They are not thread-safe and must stay confined to the integrator thread.
 * Typical usage flow is: construct (or clone) → {@link
 * #reinitialize(FirstOrderDifferentialEquations, double[], double[][], boolean)} → {@link
 * #storeTime(double)} → (lazy) {@link #computeInterpolatedState(double, double)} whenever a handler
 * requests intermediate values.
 *
 * <ul>
 *   <li>Produces dense trajectories consistent with the Dormand–Prince error estimator.
 *   <li>Performs up to three extra derivative evaluations to complete high-order interpolation
 *       stages.
 *   <li>Serializable to support restartable integrations with cached slopes.
 * </ul>
 *
 * @see DormandPrince853Integrator
 * @version $Id: DormandPrince853StepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
class DormandPrince853StepInterpolator extends RungeKuttaStepInterpolator
    implements StepInterpolator {

  /**
   * Simple constructor for prototype creation.
   *
   * <p>The instance starts without allocated work arrays because the dimension of the state vector
   * is unknown at this point. It becomes usable only after a call to {@link
   * #reinitialize(FirstOrderDifferentialEquations, double[], double[][], boolean)}, which allocates
   * slope caches and temporary buffers based on the current problem size. Integrators create one
   * prototype and then clone it per step to avoid repeatedly wiring new interpolators from scratch;
   * the lazy setup keeps cloning cheap while deferring allocations until the first actual step.
   */
  public DormandPrince853StepInterpolator() {
    super();
    yDotKLast = null;
    yTmp = null;
    v = null;
    vectorsInitialized = false;
  }

  /**
   * Copy constructor that deep-copies cached slopes and vectors.
   *
   * <p>The new instance duplicates the interpolation buffers and the three lazily evaluated slope
   * arrays so that later mutations do not affect the source interpolator. If the source has not yet
   * been initialized with a state vector, the clone remains uninitialized and will allocate its
   * buffers during the next {@link #reinitialize(FirstOrderDifferentialEquations, double[],
   * double[][], boolean)} call.
   *
   * @param interpolator interpolator to copy from; may be uninitialized, in which case the clone
   *     also starts without allocated vectors but retains the same finalized-step status.
   */
  public DormandPrince853StepInterpolator(DormandPrince853StepInterpolator interpolator) {

    super(interpolator);

    if (interpolator.currentState == null) {

      yDotKLast = null;
      v = null;
      vectorsInitialized = false;

    } else {

      int dimension = interpolator.currentState.length;

      yDotKLast = new double[3][];
      for (int k = 0; k < yDotKLast.length; ++k) {
        yDotKLast[k] = new double[dimension];
        System.arraycopy(interpolator.yDotKLast[k], 0, yDotKLast[k], 0, dimension);
      }

      v = new double[7][];
      for (int k = 0; k < v.length; ++k) {
        v[k] = new double[dimension];
        System.arraycopy(interpolator.v[k], 0, v[k], 0, dimension);
      }

      vectorsInitialized = interpolator.vectorsInitialized;
    }

    // the step has been finalized, we don't need this anymore
    yTmp = null;
  }

  /**
   * Create an independent copy of this interpolator.
   *
   * <p>The clone preserves the cached step data, interpolation vectors, and lazily computed stage
   * derivatives so that it can provide identical dense output even after the original advances to
   * another step. Callers typically clone before handing the interpolator to user code to avoid
   * races with the integrator reusing the instance for subsequent steps. The copy remains mutable
   * and should not be shared across threads.
   *
   * @return a new interpolator instance whose internal arrays are deep-copied from this one to
   *     prevent shared mutable state between clones.
   */
  @Override
  public DormandPrince853StepInterpolator copy() {
    return new DormandPrince853StepInterpolator(this);
  }

  /**
   * Reinitialize the interpolator with the data of the current step.
   *
   * <p>This method binds the shared state and slope arrays produced by the integrator to this
   * interpolator, allocates per-dimension buffers, and resets the lazily computed interpolation
   * vectors. It must be invoked once per accepted step before any call to {@link
   * #computeInterpolatedState(double, double)}. Subsequent calls overwrite previous bindings and
   * discard cached vectors to reflect the new step data.
   *
   * @param equations set of differential equations being integrated; never {@code null} and used
   *     for any deferred derivative evaluations.
   * @param y reference to the integrator array holding the state at the end of the step; contents
   *     are read but not copied.
   * @param yDotK reference to the integrator array holding all intermediate stage slopes from the
   *     Dormand–Prince tableau; the array is reused directly.
   * @param forward integration direction indicator; {@code true} for increasing time, {@code false}
   *     for backward integration.
   */
  @Override
  public void reinitialize(
      FirstOrderDifferentialEquations equations, double[] y, double[][] yDotK, boolean forward) {

    super.reinitialize(equations, y, yDotK, forward);

    int dimension = currentState.length;

    yDotKLast = new double[3][];
    for (int k = 0; k < yDotKLast.length; ++k) {
      yDotKLast[k] = new double[dimension];
    }

    yTmp = new double[dimension];

    v = new double[7][];
    for (int k = 0; k < v.length; ++k) {
      v[k] = new double[dimension];
    }

    vectorsInitialized = false;
  }

  /**
   * Store the current step time and invalidate cached vectors.
   *
   * <p>Calling this resets the interpolation buffers so that subsequent calls to {@link
   * #computeInterpolatedState(double, double)} will recompute the interpolation polynomials for the
   * new step boundaries. Integrators call this once each time a step is accepted and before any
   * dense output requests are served.
   *
   * @param t current time, expressed in the same units as the integrator independent variable.
   */
  @Override
  public void storeTime(double t) {
    super.storeTime(t);
    vectorsInitialized = false;
  }

  /**
   * Compute the interpolated state inside the current step.
   *
   * <p>The method lazily builds high-order interpolation vectors the first time it is invoked after
   * a step is stored, performing up to three additional derivative evaluations via {@link
   * #doFinalize()} if they have not already been executed. Subsequent calls within the same step
   * reuse the cached vectors. The interpolation uses the Dormand–Prince dense output coefficients
   * and preserves the direction of integration for both forward and backward flows.
   *
   * @param theta normalized interpolation abscissa within the step; {@code 0} corresponds to the
   *     start of the step and {@code 1} to its end.
   * @param oneMinusThetaH time gap between the interpolated time and the current step end; computed
   *     as {@code (1 - theta) * h} and may be negative for backward integration.
   * @throws DerivativeException propagated if the user-supplied derivative function throws while
   *     evaluating any of the deferred stages needed for interpolation.
   */
  @Override
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {

    if (!vectorsInitialized) {

      if (v == null) {
        v = new double[7][];
        for (int k = 0; k < 7; ++k) {
          v[k] = new double[interpolatedState.length];
        }
      }

      // perform the last evaluations if they have not been done yet
      finalizeStep();

      // compute the interpolation vectors for this time step
      for (int i = 0; i < interpolatedState.length; ++i) {
        v[0][i] =
            h
                * (B_01 * yDotK[0][i]
                    + B_06 * yDotK[5][i]
                    + B_07 * yDotK[6][i]
                    + B_08 * yDotK[7][i]
                    + B_09 * yDotK[8][i]
                    + B_10 * yDotK[9][i]
                    + B_11 * yDotK[10][i]
                    + B_12 * yDotK[11][i]);
        v[1][i] = h * yDotK[0][i] - v[0][i];
        v[2][i] = v[0][i] - v[1][i] - h * yDotK[12][i];
        for (int k = 0; k < d.length; ++k) {
          v[k + 3][i] =
              h
                  * (d[k][0] * yDotK[0][i]
                      + d[k][1] * yDotK[5][i]
                      + d[k][2] * yDotK[6][i]
                      + d[k][3] * yDotK[7][i]
                      + d[k][4] * yDotK[8][i]
                      + d[k][5] * yDotK[9][i]
                      + d[k][6] * yDotK[10][i]
                      + d[k][7] * yDotK[11][i]
                      + d[k][8] * yDotK[12][i]
                      + d[k][9] * yDotKLast[0][i]
                      + d[k][10] * yDotKLast[1][i]
                      + d[k][11] * yDotKLast[2][i]);
        }
      }

      vectorsInitialized = true;
    }

    double eta = oneMinusThetaH / h;

    for (int i = 0; i < interpolatedState.length; ++i) {
      interpolatedState[i] =
          currentState[i]
              - eta
                  * (v[0][i]
                      - theta
                          * (v[1][i]
                              + theta
                                  * (v[2][i]
                                      + eta
                                          * (v[3][i]
                                              + theta
                                                  * (v[4][i]
                                                      + eta * (v[5][i] + theta * (v[6][i])))))));
    }
  }

  /**
   * Complete the step by evaluating the remaining Dormand–Prince stages.
   *
   * <p>This method computes the stage derivatives k14, k15, and k16 required only for dense output,
   * not for the embedded error estimate. It reuses the shared work arrays and writes the results
   * into {@code yDotKLast}. The method is invoked lazily by {@link
   * #computeInterpolatedState(double, double)} when interpolation data are first needed.
   *
   * @throws DerivativeException propagated if the user-supplied differential equations object
   *     throws during any of the additional derivative evaluations.
   */
  @Override
  protected void doFinalize() throws DerivativeException {

    double s;

    // k14
    for (int j = 0; j < currentState.length; ++j) {
      s =
          K14_01 * yDotK[0][j]
              + K14_06 * yDotK[5][j]
              + K14_07 * yDotK[6][j]
              + K14_08 * yDotK[7][j]
              + K14_09 * yDotK[8][j]
              + K14_10 * yDotK[9][j]
              + K14_11 * yDotK[10][j]
              + K14_12 * yDotK[11][j]
              + K14_13 * yDotK[12][j];
      yTmp[j] = currentState[j] + h * s;
    }
    equations.computeDerivatives(previousTime + C14 * h, yTmp, yDotKLast[0]);

    // k15
    for (int j = 0; j < currentState.length; ++j) {
      s =
          K15_01 * yDotK[0][j]
              + K15_06 * yDotK[5][j]
              + K15_07 * yDotK[6][j]
              + K15_08 * yDotK[7][j]
              + K15_09 * yDotK[8][j]
              + K15_10 * yDotK[9][j]
              + K15_11 * yDotK[10][j]
              + K15_12 * yDotK[11][j]
              + K15_13 * yDotK[12][j]
              + K15_14 * yDotKLast[0][j];
      yTmp[j] = currentState[j] + h * s;
    }
    equations.computeDerivatives(previousTime + C15 * h, yTmp, yDotKLast[1]);

    // k16
    for (int j = 0; j < currentState.length; ++j) {
      s =
          K16_01 * yDotK[0][j]
              + K16_06 * yDotK[5][j]
              + K16_07 * yDotK[6][j]
              + K16_08 * yDotK[7][j]
              + K16_09 * yDotK[8][j]
              + K16_10 * yDotK[9][j]
              + K16_11 * yDotK[10][j]
              + K16_12 * yDotK[11][j]
              + K16_13 * yDotK[12][j]
              + K16_14 * yDotKLast[0][j]
              + K16_15 * yDotKLast[1][j];
      yTmp[j] = currentState[j] + h * s;
    }
    equations.computeDerivatives(previousTime + C16 * h, yTmp, yDotKLast[2]);
  }

  /**
   * Save the state of the interpolator for serialization.
   *
   * <p>The method ensures deferred stages are computed, then writes the cached slopes and the base
   * class data so that the interpolator can be restored later with identical interpolation
   * capabilities. It preserves ordering so {@link #readExternal(ObjectInput)} can mirror the
   * layout.
   *
   * @param out stream where to save the state; must remain open for the duration of the write.
   * @exception IOException in case of write error while persisting slopes or delegated base state.
   */
  @Override
  public void writeExternal(ObjectOutput out) throws IOException {

    try {
      // save the local attributes
      finalizeStep();
    } catch (DerivativeException e) {
      throw new IOException(e);
    }
    out.writeInt(currentState.length);
    for (int i = 0; i < currentState.length; ++i) {
      out.writeDouble(yDotKLast[0][i]);
      out.writeDouble(yDotKLast[1][i]);
      out.writeDouble(yDotKLast[2][i]);
    }

    // save the state of the base class
    super.writeExternal(out);
  }

  /**
   * Read the state of the interpolator from an external stream.
   *
   * <p>All slope arrays and the base interpolator state are restored to allow dense output to
   * resume exactly where a serialized integration left off. The method allocates necessary arrays
   * based on the serialized dimension before delegating to the superclass for shared fields.
   *
   * @param in stream where to read the state from; the caller retains ownership of the stream.
   * @exception IOException in case of read error or truncated data that prevent slope recovery.
   */
  @Override
  public void readExternal(ObjectInput in) throws IOException {

    // read the local attributes
    yDotKLast = new double[3][];
    int dimension = in.readInt();
    yDotKLast[0] = new double[dimension];
    yDotKLast[1] = new double[dimension];
    yDotKLast[2] = new double[dimension];

    for (int i = 0; i < dimension; ++i) {
      yDotKLast[0][i] = in.readDouble();
      yDotKLast[1][i] = in.readDouble();
      yDotKLast[2][i] = in.readDouble();
    }

    // read the base state
    super.readExternal(in);
  }

  /** Cached stage derivatives k14, k15, and k16 computed lazily for dense output. */
  private double[][] yDotKLast;

  /** Temporary state vector used when forming intermediate trial states for derivative calls. */
  private double[] yTmp;

  /** Interpolation polynomial vectors built once per step and reused for subsequent queries. */
  private double[][] v;

  /** Flag indicating whether {@link #v} contains data consistent with the stored step. */
  private boolean vectorsInitialized;

  // external weights of the integrator,
  // note that b_02 through b_05 are null
  /** External weight {@code b1} from the Dormand–Prince 8(5,3) Butcher tableau. */
  private static final double B_01 = 104257.0 / 1920240.0;

  /** External weight {@code b6} used in the dense output polynomial. */
  private static final double B_06 = 3399327.0 / 763840.0;

  /** External weight {@code b7} scaling the seventh stage derivative. */
  private static final double B_07 = 66578432.0 / 35198415.0;

  /** External weight {@code b8} applied to the eighth stage derivative. */
  private static final double B_08 = -1674902723.0 / 288716400.0;

  /** External weight {@code b9} contributing to the principal solution estimate. */
  private static final double B_09 = 54980371265625.0 / 176692375811392.0;

  /** External weight {@code b10} for the tenth stage derivative. */
  private static final double B_10 = -734375.0 / 4826304.0;

  /** External weight {@code b11} for the eleventh stage derivative. */
  private static final double B_11 = 171414593.0 / 851261400.0;

  /** External weight {@code b12} involved in the twelfth stage combination. */
  private static final double B_12 = 137909.0 / 3084480.0;

  // k14 for interpolation only
  /** Abscissa for the fourteenth stage used solely during dense output completion. */
  private static final double C14 = 1.0 / 10.0;

  /** Weight for yDotK[0] when constructing stage k14. */
  private static final double K14_01 = 13481885573.0 / 240030000000.0 - B_01;

  /** Weight for yDotK[5] when constructing stage k14. */
  private static final double K14_06 = 0.0 - B_06;

  /** Weight for yDotK[6] when constructing stage k14. */
  private static final double K14_07 = 139418837528.0 / 549975234375.0 - B_07;

  /** Weight for yDotK[7] when constructing stage k14. */
  private static final double K14_08 = -11108320068443.0 / 45111937500000.0 - B_08;

  /** Weight for yDotK[8] when constructing stage k14. */
  private static final double K14_09 = -1769651421925959.0 / 14249385146080000.0 - B_09;

  /** Weight for yDotK[9] when constructing stage k14. */
  private static final double K14_10 = 57799439.0 / 377055000.0 - B_10;

  /** Weight for yDotK[10] when constructing stage k14. */
  private static final double K14_11 = 793322643029.0 / 96734250000000.0 - B_11;

  /** Weight for yDotK[11] when constructing stage k14. */
  private static final double K14_12 = 1458939311.0 / 192780000000.0 - B_12;

  /** Weight for yDotK[12] when constructing stage k14. */
  private static final double K14_13 = -4149.0 / 500000.0;

  // k15 for interpolation only
  /** Abscissa for the fifteenth stage used only for dense output reconstruction. */
  private static final double C15 = 1.0 / 5.0;

  /** Weight for yDotK[0] when constructing stage k15. */
  private static final double K15_01 = 1595561272731.0 / 50120273500000.0 - B_01;

  /** Weight for yDotK[5] when constructing stage k15. */
  private static final double K15_06 = 975183916491.0 / 34457688031250.0 - B_06;

  /** Weight for yDotK[6] when constructing stage k15. */
  private static final double K15_07 = 38492013932672.0 / 718912673015625.0 - B_07;

  /** Weight for yDotK[7] when constructing stage k15. */
  private static final double K15_08 = -1114881286517557.0 / 20298710767500000.0 - B_08;

  /** Weight for yDotK[8] when constructing stage k15. */
  private static final double K15_09 = 0.0 - B_09;

  /** Weight for yDotK[9] when constructing stage k15. */
  private static final double K15_10 = 0.0 - B_10;

  /** Weight for yDotK[10] when constructing stage k15. */
  private static final double K15_11 = -2538710946863.0 / 23431227861250000.0 - B_11;

  /** Weight for yDotK[11] when constructing stage k15. */
  private static final double K15_12 = 8824659001.0 / 23066716781250.0 - B_12;

  /** Weight for yDotK[12] when constructing stage k15. */
  private static final double K15_13 = -11518334563.0 / 33831184612500.0;

  /** Weight for yDotKLast[0] when constructing stage k15. */
  private static final double K15_14 = 1912306948.0 / 13532473845.0;

  // k16 for interpolation only
  /** Abscissa for the sixteenth stage, evaluated solely for interpolation support. */
  private static final double C16 = 7.0 / 9.0;

  /** Weight for yDotK[0] when constructing stage k16. */
  private static final double K16_01 = -13613986967.0 / 31741908048.0 - B_01;

  /** Weight for yDotK[5] when constructing stage k16. */
  private static final double K16_06 = -4755612631.0 / 1012344804.0 - B_06;

  /** Weight for yDotK[6] when constructing stage k16. */
  private static final double K16_07 = 42939257944576.0 / 5588559685701.0 - B_07;

  /** Weight for yDotK[7] when constructing stage k16. */
  private static final double K16_08 = 77881972900277.0 / 19140370552944.0 - B_08;

  /** Weight for yDotK[8] when constructing stage k16. */
  private static final double K16_09 = 22719829234375.0 / 63689648654052.0 - B_09;

  /** Weight for yDotK[9] when constructing stage k16. */
  private static final double K16_10 = 0.0 - B_10;

  /** Weight for yDotK[10] when constructing stage k16. */
  private static final double K16_11 = 0.0 - B_11;

  /** Weight for yDotK[11] when constructing stage k16. */
  private static final double K16_12 = 0.0 - B_12;

  /** Weight for yDotK[12] when constructing stage k16. */
  private static final double K16_13 = -1199007803.0 / 857031517296.0;

  /** Weight for yDotKLast[0] when constructing stage k16. */
  private static final double K16_14 = 157882067000.0 / 53564469831.0;

  /** Weight for yDotKLast[1] when constructing stage k16. */
  private static final double K16_15 = -290468882375.0 / 31741908048.0;

  // interpolation weights
  // (beware that only the non-null values are in the table)
  /**
   * Dense-output weight matrix {@code d[k][j]} that combines base and additional stages into the
   * interpolation polynomial coefficients.
   */
  private static final double[][] d = {
    {
      -17751989329.0 / 2106076560.0,
      4272954039.0 / 7539864640.0,
      -118476319744.0 / 38604839385.0,
      755123450731.0 / 316657731600.0,
      3692384461234828125.0 / 1744130441634250432.0,
      -4612609375.0 / 5293382976.0,
      2091772278379.0 / 933644586600.0,
      2136624137.0 / 3382989120.0,
      -126493.0 / 1421424.0,
      98350000.0 / 5419179.0,
      -18878125.0 / 2053168.0,
      -1944542619.0 / 438351368.0
    },
    {
      32941697297.0 / 3159114840.0,
      456696183123.0 / 1884966160.0,
      19132610714624.0 / 115814518155.0,
      -177904688592943.0 / 474986597400.0,
      -4821139941836765625.0 / 218016305204281304.0,
      30702015625.0 / 3970037232.0,
      -85916079474274.0 / 2800933759800.0,
      -5919468007.0 / 634310460.0,
      2479159.0 / 157936.0,
      -18750000.0 / 602131.0,
      -19203125.0 / 2053168.0,
      15700361463.0 / 438351368.0
    },
    {
      12627015655.0 / 631822968.0,
      -72955222965.0 / 188496616.0,
      -13145744952320.0 / 69488710893.0,
      30084216194513.0 / 56998391688.0,
      -296858761006640625.0 / 25648977082856624.0,
      569140625.0 / 82709109.0,
      -18684190637.0 / 18672891732.0,
      69644045.0 / 89549712.0,
      -11847025.0 / 4264272.0,
      -978650000.0 / 16257537.0,
      519371875.0 / 6159504.0,
      5256837225.0 / 438351368.0
    },
    {
      -450944925.0 / 17550638.0,
      -14532122925.0 / 94248308.0,
      -595876966400.0 / 2573655959.0,
      188748653015.0 / 527762886.0,
      2545485458115234375.0 / 27252038150535163.0,
      -1376953125.0 / 36759604.0,
      53995596795.0 / 518691437.0,
      210311225.0 / 7047894.0,
      -1718875.0 / 39484.0,
      58000000.0 / 602131.0,
      -1546875.0 / 39484.0,
      -1262172375.0 / 8429834.0
    }
  };

  /** Serialization identifier preserving stream compatibility across versions. */
  @Serial private static final long serialVersionUID = 4165537490327432186L;
}
