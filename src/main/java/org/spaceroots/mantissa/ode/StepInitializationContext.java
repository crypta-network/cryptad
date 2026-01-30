package org.spaceroots.mantissa.ode;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles inputs and work arrays used to estimate an initial step size.
 *
 * <p>This record packages the values required by {@link AdaptiveStepsizeIntegrator#initializeStep}
 * so callers can pass a single object instead of a long parameter list. It is typically created by
 * adaptive integrators right before the first step is chosen, using arrays that already exist in
 * the integration workspace. The record itself is immutable, but it stores references to mutable
 * arrays owned by the caller; no defensive copies are made, and the arrays may be reused across
 * attempts. Treat instances as short-lived, single-thread use objects that describe one
 * initialization attempt and provide access to the shared scratch buffers.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Capturing the derivative provider and direction flags needed for the heuristic.
 *   <li>Carrying consistent state and derivative arrays for trial evaluations.
 *   <li>Ensuring scale information is available for normalized error estimates.
 * </ul>
 *
 * @param equations the system that computes derivatives for the trial states; must not be null.
 * @param forward true to integrate toward increasing time, false for the backward direction.
 * @param order integration order used to scale the initial step estimate.
 * @param scale per-component scaling factors; length matches state and contains non-zero values.
 * @param t0 start time for the trial step; expressed in integration time units.
 * @param y0 state values at {@code t0}; array length matches the equations dimension.
 * @param yDot0 derivative values at {@code t0}; used as input and overwritten by callers.
 * @param y1 workspace holding the Euler-predicted trial state; same length as {@code y0}.
 * @param yDot1 workspace for derivatives at the trial state; same length as {@code y0}.
 * @see AdaptiveStepsizeIntegrator#initializeStep(StepInitializationContext)
 */
@SuppressWarnings("ArrayRecordComponent")
public record StepInitializationContext(
    FirstOrderDifferentialEquations equations,
    boolean forward,
    int order,
    double[] scale,
    double t0,
    double[] y0,
    double[] yDot0,
    double[] y1,
    double[] yDot1) {

  /**
   * Compare this context with another for structural equality.
   *
   * <p>The comparison uses the record components as the semantic fields but treats the array
   * components as ordered value sequences rather than reference identities. The time value is
   * compared using raw bit equality to keep {@code NaN} payloads distinct. This method is
   * deterministic and side-effect free, which makes it suitable for caching keys or assertions in
   * tests.
   *
   * @param other candidate object to compare; may be null or any type.
   * @return {@code true} when all scalar fields match and each array contains equal values.
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other
        instanceof
        StepInitializationContext(
            FirstOrderDifferentialEquations otherEquations,
            boolean otherForward,
            int otherOrder,
            double[] otherScale,
            double otherT0,
            double[] otherY0,
            double[] otherYDot0,
            double[] otherY1,
            double[] otherYDot1))) {
      return false;
    }
    return forward == otherForward
        && order == otherOrder
        && Double.doubleToLongBits(t0) == Double.doubleToLongBits(otherT0)
        && Objects.equals(equations, otherEquations)
        && Arrays.equals(scale, otherScale)
        && Arrays.equals(y0, otherY0)
        && Arrays.equals(yDot0, otherYDot0)
        && Arrays.equals(y1, otherY1)
        && Arrays.equals(yDot1, otherYDot1);
  }

  /**
   * Compute a hash code consistent with the array-aware equality contract.
   *
   * <p>The hash is composed of the scalar components and the contents of each array. This keeps the
   * result stable for identical value sequences even when the arrays are distinct instances.
   * Callers should remember that changing any referenced array will change the hash, so this record
   * should not be used as a key in mutable array scenarios unless the contents are stable.
   *
   * @return hash value derived from scalar components and array contents.
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
   * Render a descriptive string that includes the contents of each array component.
   *
   * <p>The output mirrors the record component order, formatting arrays with {@link
   * Arrays#toString(double[])} so the contents are visible for diagnostics. The returned string is
   * non-null and intended for logging or debugging rather than parsing.
   *
   * @return human-readable representation containing scalar values and array contents.
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
