package org.spaceroots.mantissa.ode;

import java.util.Arrays;

/**
 * Bundles scalar and state inputs used to estimate an initial step size.
 *
 * <p>This value class collects the core inputs that remain stable during the initial step-size
 * heuristic: the derivative provider, integration direction, scaling factors, the start time, and
 * the state and derivative arrays at that time. Integrators typically assemble an instance right
 * before invoking {@link AdaptiveStepsizeIntegrator#initializeStep(StepInitializationContext)} and
 * pair it with a workspace that holds mutable trial buffers used during the Euler probe.
 *
 * <p>The instance is immutable and defensively copies its mutable array fields on construction and
 * access. The class does not validate inputs or enforce invariants, so callers remain responsible
 * for ensuring array lengths match the equation dimension and scaling factors are non-zero.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Providing the derivative provider and direction for the heuristic.
 *   <li>Carrying the state, derivative, and scale arrays used in norm computations.
 *   <li>Supplying the start time that anchors the trial evaluation.
 * </ul>
 *
 * @see StepInitializationContext
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class StepInitializationInputs {
  private final FirstOrderDifferentialEquations equations;
  private final boolean forward;
  private final int order;
  private final double[] scale;
  private final double t0;
  private final double[] y0;
  private final double[] yDot0;

  /**
   * Creates an input bundle for the initial step-size estimate.
   *
   * <p>This constructor copies the provided arrays and does not validate dimensional consistency.
   * Callers must ensure that {@code y0}, {@code yDot0}, and {@code scale} have identical lengths,
   * that each scale entry is non-zero, and that {@code yDot0} reflects the derivative at {@code
   * t0}.
   *
   * @param equations derivative provider used by the initialization heuristic; must not be {@code
   *     null}
   * @param forward {@code true} for forward integration, {@code false} for backward direction
   * @param order integration order used to scale the step estimate; must be positive
   * @param scale per-component scaling factors used in norm calculations; entries must be non-zero
   * @param t0 start time for the trial step, expressed in integrator time units
   * @param y0 state vector at {@code t0}; length must match the equation dimension
   * @param yDot0 derivative vector at {@code t0}; length must match {@code y0}
   */
  public StepInitializationInputs(
      FirstOrderDifferentialEquations equations,
      boolean forward,
      int order,
      double[] scale,
      double t0,
      double[] y0,
      double[] yDot0) {
    this.equations = equations;
    this.forward = forward;
    this.order = order;
    this.scale = copyArray(scale);
    this.t0 = t0;
    this.y0 = copyArray(y0);
    this.yDot0 = copyArray(yDot0);
  }

  /**
   * Returns the derivative provider used during the initial step-size heuristic.
   *
   * <p>The returned instance is the same reference supplied at construction time. It is invoked by
   * the integrator to compute derivatives at {@code t0} and at the Euler trial point. The caller is
   * responsible for ensuring that the provider is consistent with the supplied state arrays and
   * that it can be called safely during initialization.
   *
   * @return derivative provider used for trial derivative evaluations
   */
  public FirstOrderDifferentialEquations equations() {
    return equations;
  }

  /**
   * Returns the integration direction flag.
   *
   * <p>The value determines whether the estimated step size is positive or negative relative to
   * {@code t0}. It is not derived from time values and remains fixed for the lifetime of this
   * instance. Callers should supply a direction consistent with the target time to avoid stepping
   * away from the intended integration goal.
   *
   * @return {@code true} when integration advances toward increasing time, otherwise {@code false}
   */
  public boolean forward() {
    return forward;
  }

  /**
   * Returns the integration order used to scale the step-size estimate.
   *
   * <p>The order is used by the heuristic when converting normalized derivative estimates into a
   * step size. This class does not validate the value, so callers must ensure it is positive and
   * consistent with the integrator implementation. Incorrect values can lead to overly aggressive
   * or overly conservative initial steps.
   *
   * @return integration order used when scaling the initial step-size estimate
   */
  public int order() {
    return order;
  }

  /**
   * Returns the per-component scaling factors used for normalization.
   *
   * <p>The returned array is a defensive copy. Each entry must be non-zero to avoid division by
   * zero, and the array length must match the state vector dimension.
   *
   * @return scale array used to normalize state and derivative components
   */
  public double[] scale() {
    return copyArray(scale);
  }

  /**
   * Returns the start time for the trial step.
   *
   * <p>This value anchors the state and derivative arrays and is used when evaluating derivatives
   * at the Euler trial point. It is stored verbatim without validation and may be any finite value
   * supported by the integrator. Callers should ensure it matches the time at which {@code y0} and
   * {@code yDot0} were computed.
   *
   * @return start time for the trial step, expressed in integrator time units
   */
  public double t0() {
    return t0;
  }

  /**
   * Returns the state vector at the start time.
   *
   * <p>The returned array is a defensive copy. It must have the same length as the equation
   * dimension and the scale array.
   *
   * @return state vector at {@code t0}, shared with the integrator
   */
  public double[] y0() {
    return copyArray(y0);
  }

  /**
   * Returns the derivative vector at the start time.
   *
   * <p>The returned array is a defensive copy. It should contain the derivative at {@code t0} and
   * have the same length as {@code y0}.
   *
   * @return derivative vector at {@code t0}, shared and mutable
   */
  public double[] yDot0() {
    return copyArray(yDot0);
  }

  private static double[] copyArray(double[] input) {
    return input == null ? null : Arrays.copyOf(input, input.length);
  }
}
