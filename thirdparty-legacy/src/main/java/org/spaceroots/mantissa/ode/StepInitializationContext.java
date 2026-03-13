package org.spaceroots.mantissa.ode;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles inputs and work arrays used to estimate an initial step size.
 *
 * <p>This value object packages the values required by {@link
 * AdaptiveStepsizeIntegrator#initializeStep(StepInitializationContext)} so callers can pass a
 * single object instead of a long parameter list. It is typically created by adaptive integrators
 * right before the first step is chosen, using arrays that already exist in the integration
 * workspace. The instance itself is immutable, but it stores references to mutable arrays owned by
 * the caller; no defensive copies are made, and the arrays may be reused across attempts.
 *
 * <p>Use this context as a short-lived description of one initialization attempt. It captures a
 * derivative provider, the integration direction, scaling information, and the working buffers for
 * the Euler probe used by the step-size heuristic. The context does not validate array dimensions
 * or contents; callers are responsible for supplying consistent array lengths and non-zero scaling
 * values. Instances are not thread-safe because the arrays are shared and are expected to be
 * mutated by the integrator during initialization.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Capturing the derivative provider and direction flags needed for the heuristic.
 *   <li>Carrying consistent state and derivative arrays for trial evaluations.
 *   <li>Ensuring scale information is available for normalized error estimates.
 * </ul>
 *
 * @see AdaptiveStepsizeIntegrator#initializeStep(StepInitializationContext)
 */
public final class StepInitializationContext {
  private final FirstOrderDifferentialEquations equations;
  private final boolean forward;
  private final int order;
  private final double[] scale;
  private final double t0;
  private final double[] y0;
  private final double[] yDot0;
  private final double[] y1;
  private final double[] yDot1;

  /**
   * Creates a bundle of inputs and work arrays for the initial step-size estimate.
   *
   * <p>The constructor simply stores references from the provided input and workspace containers.
   * It does not clone or normalize any arrays, and it performs no consistency checks. Callers must
   * ensure that all arrays have compatible lengths, that the scale entries are non-zero, and that
   * the derivative buffer contains the derivative at {@code t0}. The resulting context is intended
   * for immediate use during a single initialization pass and should not be shared across threads
   * because the arrays are expected to be mutated during the Euler probe.
   *
   * @param inputs scalar values and state vectors used by the heuristic; must not be {@code null}
   * @param workspace buffers reused during the Euler probe and derivative evaluation; must not be
   *     {@code null}
   */
  public StepInitializationContext(
      StepInitializationInputs inputs, StepInitializationWorkspace workspace) {
    this.equations = inputs.equations();
    this.forward = inputs.forward();
    this.order = inputs.order();
    this.scale = inputs.scale();
    this.t0 = inputs.t0();
    this.y0 = inputs.y0();
    this.yDot0 = inputs.yDot0();
    this.y1 = workspace.y1();
    this.yDot1 = workspace.yDot1();
  }

  /**
   * Returns the derivative provider for the trial evaluations.
   *
   * <p>The returned instance is the same reference supplied by the caller and is used by the
   * heuristic to compute derivatives during the Euler probe. The context does not wrap or cache the
   * provider, so any side effects or state in the equations implementation are observed directly
   * during initialization. Callers should ensure that the equations implementation is configured
   * consistently with the supplied state arrays and that it can safely be invoked at {@code t0} and
   * the trial time computed by the integrator.
   *
   * @return derivative provider used for trial derivative evaluations during initialization
   */
  public FirstOrderDifferentialEquations equations() {
    return equations;
  }

  /**
   * Reports whether integration proceeds toward increasing time.
   *
   * <p>This flag mirrors the integrator direction used to sign the trial step size. It is not
   * derived from the time values and remains constant for the lifetime of this context. The value
   * is consulted by the initialization heuristic to orient the step toward the target time, and it
   * is also used when clamping the initial step size to configured limits. Callers should provide a
   * value consistent with the target time to avoid an initial step that points away from the goal.
   *
   * @return {@code true} for forward integration, {@code false} for backward integration
   */
  public boolean forward() {
    return forward;
  }

  /**
   * Returns the integration order used by the step-size heuristic.
   *
   * <p>The order controls the power applied when scaling the error estimate. It should match the
   * order of the method used by the integrator, and it is treated as an input parameter rather than
   * recomputed. The context does not validate that the value is positive, so callers must supply a
   * meaningful order and ensure consistency with the integrator implementation. An incorrect order
   * can yield overly aggressive or overly conservative initial step sizes.
   *
   * @return integration order used when scaling the step-size estimate
   */
  public int order() {
    return order;
  }

  /**
   * Returns the per-component scaling factors used to normalize errors.
   *
   * <p>The returned array reference is shared with the caller and is read multiple times during the
   * heuristic. Each entry should be non-zero to avoid division by zero, and the array length must
   * match the state dimension. The context does not enforce these invariants. If the array is
   * modified while initialization is in progress, the computed step size may become inconsistent
   * with the state and derivative values.
   *
   * @return scale array used to normalize state and derivative components
   */
  public double[] scale() {
    return scale;
  }

  /**
   * Returns the start time used for the trial step.
   *
   * <p>This value is the integration time at which the initial state and derivative arrays are
   * defined. The heuristic uses it when evaluating derivatives at the Euler trial point and when
   * clamping the step size relative to the timescale. The value is stored verbatim and may be any
   * finite or NaN value supported by the integrator. Callers should supply the same {@code t0} used
   * to populate {@code y0} and {@code yDot0}.
   *
   * @return starting time for the initial step-size trial, in integrator time units
   */
  public double t0() {
    return t0;
  }

  /**
   * Returns the state vector at the initial time.
   *
   * <p>The returned array is shared with the integrator and should contain the state at {@code t0}.
   * The heuristic reads this array but does not modify it directly. Callers must ensure the array
   * length matches the equation dimension used by the derivative provider and that the contents are
   * consistent with {@code yDot0}. If the array is mutated during initialization, the estimated
   * step size may be based on mixed state values.
   *
   * @return state vector at {@code t0}, shared with the integrator
   */
  public double[] y0() {
    return y0;
  }

  /**
   * Returns the derivative vector at the initial time.
   *
   * <p>The returned array is both an input and a workspace: it initially holds the derivative at
   * {@code t0}, and the integrator may overwrite it when recomputing derivatives. The heuristic
   * reads this array when estimating the first step size, so it must be populated before use. The
   * array length must match {@code y0}, and the values should be derived from the same equations
   * instance returned by {@link #equations()}.
   *
   * @return derivative vector at {@code t0}, shared and mutable
   */
  public double[] yDot0() {
    return yDot0;
  }

  /**
   * Returns the workspace array for the Euler-predicted trial state.
   *
   * <p>The heuristic writes the Euler trial state into this array and then uses it when requesting
   * derivatives at the trial time. The contents are not preserved after initialization, and the
   * array is owned by the caller. Its length must match the state dimension, and it should not
   * alias {@code y0} or {@code yDot0} unless the caller can tolerate in-place overwrites. The
   * initialization logic expects the array to be mutable.
   *
   * @return workspace holding the Euler trial state, reused across attempts
   */
  public double[] y1() {
    return y1;
  }

  /**
   * Returns the workspace array for derivatives at the Euler trial state.
   *
   * <p>The derivative provider writes into this array when evaluating the Euler trial point. The
   * values are used to estimate second derivatives and are not retained after initialization.
   * Callers must ensure that the array length matches the state dimension and that it can be
   * overwritten without affecting another integrator state. This buffer is read immediately after
   * the trial evaluation and then discarded.
   *
   * @return workspace for derivatives at the trial state, reused across attempts
   */
  public double[] yDot1() {
    return yDot1;
  }

  /**
   * Compares this context with another for structural equality.
   *
   * <p>The comparison uses the context fields as the semantic values but treats the array
   * components as ordered value sequences rather than reference identities. The time value is
   * compared using raw bit equality to keep {@code NaN} payloads distinct. This method is
   * deterministic and side-effect free, which makes it suitable for caching keys or assertions in
   * tests. Because content compares arrays, two contexts sharing different array instances can
   * still be considered equal when their values match.
   *
   * @param other candidate object to compare; may be {@code null} or any type instance
   * @return {@code true} when all scalar fields match and each array contains equal values
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof StepInitializationContext context)) {
      return false;
    }
    return forward == context.forward
        && order == context.order
        && Double.doubleToLongBits(t0) == Double.doubleToLongBits(context.t0)
        && Objects.equals(equations, context.equations)
        && Arrays.equals(scale, context.scale)
        && Arrays.equals(y0, context.y0)
        && Arrays.equals(yDot0, context.yDot0)
        && Arrays.equals(y1, context.y1)
        && Arrays.equals(yDot1, context.yDot1);
  }

  /**
   * Computes a hash code consistent with the array-aware equality contract.
   *
   * <p>The hash is composed of the scalar components and the contents of each array. This keeps the
   * result stable for identical value sequences even when the arrays are distinct instances.
   * Callers should remember that changing any referenced array will change the hash, so this
   * context should not be used as a key in mutable array scenarios unless the contents are stable.
   * The method performs no caching and recomputes the hash on every call.
   *
   * @return hash value derived from scalar components and array contents
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(equations, forward, order, t0);
    result = 31 * result + Arrays.hashCode(scale);
    result = 31 * result + Arrays.hashCode(y0);
    result = 31 * result + Arrays.hashCode(yDot0);
    result = 31 * result + Arrays.hashCode(y1);
    result = 31 * result + Arrays.hashCode(yDot1);
    return result;
  }

  /**
   * Renders a descriptive string that includes the contents of each array component.
   *
   * <p>The output mirrors the field order, formatting arrays with {@link Arrays#toString(double[])}
   * so the contents are visible for diagnostics. The returned string is non-null and intended for
   * logging or debugging rather than parsing. Because the arrays are mutable, the returned string
   * reflects the state at the time of the call and may change if the arrays are later modified.
   * This method has no side effects and does not allocate additional arrays beyond formatting.
   *
   * @return human-readable representation containing scalar values and array contents
   */
  @Override
  public @NotNull String toString() {
    return "StepInitializationContext["
        + "equations="
        + equations
        + ", forward="
        + forward
        + ", order="
        + order
        + ", scale="
        + Arrays.toString(scale)
        + ", t0="
        + t0
        + ", y0="
        + Arrays.toString(y0)
        + ", yDot0="
        + Arrays.toString(yDot0)
        + ", y1="
        + Arrays.toString(y1)
        + ", yDot1="
        + Arrays.toString(yDot1)
        + "]";
  }
}
