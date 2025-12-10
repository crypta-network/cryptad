package org.spaceroots.mantissa.ode;

/**
 * Implements the 8(5,3) Dormand–Prince explicit Runge–Kutta integrator with FSAL optimization,
 * adaptive steps, and dense output for systems of first-order ordinary differential equations.
 *
 * <p>The integrator combines an eighth-order propagation formula with an embedded fifth-order error
 * estimator and third-order correction, delivering high accuracy while adjusting step sizes to keep
 * the normalized local error below one. It automatically estimates an initial step, enforces
 * user-provided minimum and maximum magnitudes, and reuses the final derivative of each accepted
 * step (the <i>first same as last</i> property) to save one evaluation on the next step. Continuous
 * output is available through a step interpolator so callers can sample intermediate states without
 * retriggering derivative evaluations.
 *
 * <p>Use this class when problems are non-stiff, require tight error control, or benefit from
 * higher-order dense output. Instances are mutable and not thread-safe; confine one integrator to a
 * single integration run at a time. The Butcher tableau is hard-coded to mirror the method
 * described by Hairer, Nørsett, and Wanner (Solving Ordinary Differential Equations I, 2nd ed.).
 *
 * <ul>
 *   <li>Order 8 primary solution with 5th/3rd order error estimation.
 *   <li>Costs 12 function evaluations per accepted step despite 13 stages due to FSAL.
 *   <li>Supports scalar or per-component tolerances and automatic step initialization.
 * </ul>
 *
 * @see RungeKuttaFehlbergIntegrator
 * @see DormandPrince54Integrator
 * @version $Id: DormandPrince853Integrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class DormandPrince853Integrator extends RungeKuttaFehlbergIntegrator {

  private static final String METHOD_NAME = "Dormand-Prince 8 (5, 3)";

  private static final double SQRT_6 = Math.sqrt(6.0);

  private static final double[] C = {
    (12.0 - 2.0 * SQRT_6) / 135.0,
    (6.0 - SQRT_6) / 45.0,
    (6.0 - SQRT_6) / 30.0,
    (6.0 + SQRT_6) / 30.0,
    1.0 / 3.0,
    1.0 / 4.0,
    4.0 / 13.0,
    127.0 / 195.0,
    3.0 / 5.0,
    6.0 / 7.0,
    1.0,
    1.0
  };

  private static final double[][] A = {

    // k2
    {(12.0 - 2.0 * SQRT_6) / 135.0},

    // k3
    {(6.0 - SQRT_6) / 180.0, (6.0 - SQRT_6) / 60.0},

    // k4
    {(6.0 - SQRT_6) / 120.0, 0.0, (6.0 - SQRT_6) / 40.0},

    // k5
    {
      (462.0 + 107.0 * SQRT_6) / 3000.0,
      0.0,
      (-402.0 - 197.0 * SQRT_6) / 1000.0,
      (168.0 + 73.0 * SQRT_6) / 375.0
    },

    // k6
    {1.0 / 27.0, 0.0, 0.0, (16.0 + SQRT_6) / 108.0, (16.0 - SQRT_6) / 108.0},

    // k7
    {
      19.0 / 512.0,
      0.0,
      0.0,
      (118.0 + 23.0 * SQRT_6) / 1024.0,
      (118.0 - 23.0 * SQRT_6) / 1024.0,
      -9.0 / 512.0
    },

    // k8
    {
      13772.0 / 371293.0,
      0.0,
      0.0,
      (51544.0 + 4784.0 * SQRT_6) / 371293.0,
      (51544.0 - 4784.0 * SQRT_6) / 371293.0,
      -5688.0 / 371293.0,
      3072.0 / 371293.0
    },

    // k9
    {
      58656157643.0 / 93983540625.0,
      0.0,
      0.0,
      (-1324889724104.0 - 318801444819.0 * SQRT_6) / 626556937500.0,
      (-1324889724104.0 + 318801444819.0 * SQRT_6) / 626556937500.0,
      96044563816.0 / 3480871875.0,
      5682451879168.0 / 281950621875.0,
      -165125654.0 / 3796875.0
    },

    // k10
    {
      8909899.0 / 18653125.0,
      0.0,
      0.0,
      (-4521408.0 - 1137963.0 * SQRT_6) / 2937500.0,
      (-4521408.0 + 1137963.0 * SQRT_6) / 2937500.0,
      96663078.0 / 4553125.0,
      2107245056.0 / 137915625.0,
      -4913652016.0 / 147609375.0,
      -78894270.0 / 3880452869.0
    },

    // k11
    {
      -20401265806.0 / 21769653311.0,
      0.0,
      0.0,
      (354216.0 + 94326.0 * SQRT_6) / 112847.0,
      (354216.0 - 94326.0 * SQRT_6) / 112847.0,
      -43306765128.0 / 5313852383.0,
      -20866708358144.0 / 1126708119789.0,
      14886003438020.0 / 654632330667.0,
      35290686222309375.0 / 14152473387134411.0,
      -1477884375.0 / 485066827.0
    },

    // k12
    {
      39815761.0 / 17514443.0,
      0.0,
      0.0,
      (-3457480.0 - 960905.0 * SQRT_6) / 551636.0,
      (-3457480.0 + 960905.0 * SQRT_6) / 551636.0,
      -844554132.0 / 47026969.0,
      8444996352.0 / 302158619.0,
      -2509602342.0 / 877790785.0,
      -28388795297996250.0 / 3199510091356783.0,
      226716250.0 / 18341897.0,
      1371316744.0 / 2131383595.0
    },

    // k13 should be for interpolation only, but since it is the same
    // stage as the first evaluation of the next step, we perform it
    // here at no cost by specifying this is a fsal method
    {
      104257.0 / 1920240.0,
      0.0,
      0.0,
      0.0,
      0.0,
      3399327.0 / 763840.0,
      66578432.0 / 35198415.0,
      -1674902723.0 / 288716400.0,
      54980371265625.0 / 176692375811392.0,
      -734375.0 / 4826304.0,
      171414593.0 / 851261400.0,
      137909.0 / 3084480.0
    }
  };

  private static final double[] B = {
    104257.0 / 1920240.0,
    0.0,
    0.0,
    0.0,
    0.0,
    3399327.0 / 763840.0,
    66578432.0 / 35198415.0,
    -1674902723.0 / 288716400.0,
    54980371265625.0 / 176692375811392.0,
    -734375.0 / 4826304.0,
    171414593.0 / 851261400.0,
    137909.0 / 3084480.0,
    0.0
  };

  private static final double E1_01 = 116092271.0 / 8848465920.0;
  private static final double E1_06 = -1871647.0 / 1527680.0;
  private static final double E1_07 = -69799717.0 / 140793660.0;
  private static final double E1_08 = 1230164450203.0 / 739113984000.0;
  private static final double E1_09 = -1980813971228885.0 / 5654156025964544.0;
  private static final double E1_10 = 464500805.0 / 1389975552.0;
  private static final double E1_11 = 1606764981773.0 / 19613062656000.0;
  private static final double E1_12 = -137909.0 / 6168960.0;

  private static final double E2_01 = -364463.0 / 1920240.0;
  private static final double E2_06 = 3399327.0 / 763840.0;
  private static final double E2_07 = 66578432.0 / 35198415.0;
  private static final double E2_08 = -1674902723.0 / 288716400.0;
  private static final double E2_09 = -74684743568175.0 / 176692375811392.0;
  private static final double E2_10 = -734375.0 / 4826304.0;
  private static final double E2_11 = 171414593.0 / 851261400.0;
  private static final double E2_12 = 69869.0 / 3084480.0;

  /**
   * Creates an eighth-order Dormand–Prince integrator with scalar error tolerances and explicit
   * bounds on the adaptive step size.
   *
   * <p>The constructor stores the provided tolerances, prepares a reusable step interpolator, and
   * leaves the instance ready for a single integration run. Step magnitudes are clamped between
   * {@code minStep} and {@code maxStep}; the final step may be shorter to land exactly on the
   * target time or an event. Scalar tolerances apply uniformly to every state component; pass
   * per-component arrays to the vector overload when state magnitudes differ significantly.
   *
   * @param minStep positive lower bound for the absolute step size even during backward integration
   *     runs; values smaller than this may be used only for the final partial step.
   * @param maxStep positive upper bound for the absolute step size used during adaptation; must not
   *     be smaller than {@code minStep} and is honored for both forward and backward directions.
   * @param scalAbsoluteTolerance uniform absolute error threshold applied to each component when
   *     normalizing local error estimates; must be non-negative.
   * @param scalRelativeTolerance uniform relative error threshold scaled by the largest magnitude
   *     of the start and end state values for each component; must be non-negative.
   */
  public DormandPrince853Integrator(
      double minStep, double maxStep, double scalAbsoluteTolerance, double scalRelativeTolerance) {
    super(
        true,
        C,
        A,
        B,
        new DormandPrince853StepInterpolator(),
        minStep,
        maxStep,
        scalAbsoluteTolerance,
        scalRelativeTolerance);
  }

  /**
   * Creates an eighth-order Dormand–Prince integrator with per-component error tolerances and
   * explicit adaptive step bounds.
   *
   * <p>This overload accepts absolute and relative tolerances aligned to each state component,
   * which is useful when state magnitudes differ by several orders. The integrator keeps step
   * magnitudes within {@code minStep} and {@code maxStep}, shrinking the final step if needed to
   * hit the target time exactly. Tolerance arrays are consumed as provided; callers must ensure
   * their length equals the equation dimension and that all entries are non-negative.
   *
   * @param minStep positive lower bound for absolute step size regardless of integration direction;
   *     the last step may still be shorter to finish exactly on the target time.
   * @param maxStep positive upper bound for absolute step size used during growth; must be at least
   *     {@code minStep} and is applied symmetrically to forward and backward integration.
   * @param vecAbsoluteTolerance absolute error thresholds per state component used to scale local
   *     truncation error estimates; array length must match the problem dimension.
   * @param vecRelativeTolerance relative error thresholds per state component multiplied by the
   *     larger magnitude of the start and end values; array length must match the problem
   *     dimension.
   */
  public DormandPrince853Integrator(
      double minStep,
      double maxStep,
      double[] vecAbsoluteTolerance,
      double[] vecRelativeTolerance) {
    super(
        true,
        C,
        A,
        B,
        new DormandPrince853StepInterpolator(),
        minStep,
        maxStep,
        vecAbsoluteTolerance,
        vecRelativeTolerance);
  }

  /**
   * Returns a short human-readable identifier for this integration method.
   *
   * <p>The name reflects the Dormand–Prince 8(5,3) tableau and is suitable for logs, user-facing
   * diagnostics, or selection menus. The value is constant for all instances.
   *
   * @return stable method identifier describing the Dormand–Prince 8(5,3) scheme.
   */
  public String getName() {
    return METHOD_NAME;
  }

  /**
   * Reports the formal order of accuracy of the primary integration formula.
   *
   * <p>The returned value corresponds to the eighth-order solution propagated after each accepted
   * step; embedded lower-order estimates are used internally for error control and are not reported
   * here.
   *
   * @return the integer value {@code 8}, representing the main solution order for this method.
   */
  public int getOrder() {
    return 8;
  }

  /**
   * Computes the normalized local error estimate for the current trial step.
   *
   * <p>The method combines two embedded error estimators (orders five and three) to produce a
   * single scalar error ratio. Each state component is scaled by either scalar or vector
   * tolerances, using the larger magnitude of the start and end values to normalize derivatives. A
   * return value above one signals that the step should be rejected and retried with a smaller
   * size; values at or below one allow the step to be accepted and possibly grown for the next
   * attempt. The computation does not modify the provided arrays.
   *
   * @param yDotK staged derivatives for all computed Runge–Kutta stages; indices align with the
   *     method tableau and contain one entry per state component.
   * @param y0 state estimate at the beginning of the candidate step; length matches the problem
   *     dimension and is used for scaling tolerances.
   * @param y1 state estimate at the end of the candidate step produced by the high-order formula;
   *     length matches {@code y0} and is used for scaling tolerances.
   * @param h signed size of the trial step currently under evaluation; absolute value is used when
   *     computing the returned ratio.
   * @return normalized error ratio; values greater than one trigger step rejection and reduction,
   *     while values at or below one allow acceptance.
   */
  protected double estimateError(double[][] yDotK, double[] y0, double[] y1, double h) {
    double error1 = 0;
    double error2 = 0;

    for (int j = 0; j < y0.length; ++j) {
      double errSum1 =
          E1_01 * yDotK[0][j]
              + E1_06 * yDotK[5][j]
              + E1_07 * yDotK[6][j]
              + E1_08 * yDotK[7][j]
              + E1_09 * yDotK[8][j]
              + E1_10 * yDotK[9][j]
              + E1_11 * yDotK[10][j]
              + E1_12 * yDotK[11][j];
      double errSum2 =
          E2_01 * yDotK[0][j]
              + E2_06 * yDotK[5][j]
              + E2_07 * yDotK[6][j]
              + E2_08 * yDotK[7][j]
              + E2_09 * yDotK[8][j]
              + E2_10 * yDotK[9][j]
              + E2_11 * yDotK[10][j]
              + E2_12 * yDotK[11][j];

      double yScale = Math.max(Math.abs(y0[j]), Math.abs(y1[j]));
      double tol =
          (vecAbsoluteTolerance == null)
              ? (scalAbsoluteTolerance + scalRelativeTolerance * yScale)
              : (vecAbsoluteTolerance[j] + vecRelativeTolerance[j] * yScale);
      double ratio1 = errSum1 / tol;
      error1 += ratio1 * ratio1;
      double ratio2 = errSum2 / tol;
      error2 += ratio2 * ratio2;
    }

    double den = error1 + 0.01 * error2;
    if (den <= 0.0) {
      den = 1.0;
    }

    return Math.abs(h) * error1 / Math.sqrt(y0.length * den);
  }
}
