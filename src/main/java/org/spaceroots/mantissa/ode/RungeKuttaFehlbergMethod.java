package org.spaceroots.mantissa.ode;

import java.util.Arrays;
import java.util.Objects;
import org.jetbrains.annotations.NotNull;

/**
 * Bundles the Butcher tableau and interpolation prototype for a Fehlberg integrator.
 *
 * <p>The value object groups the immutable method definition shared across Runge-Kutta-Fehlberg
 * constructors: the FSAL flag, tableau coefficients, and the step interpolator prototype that is
 * cloned during integration. Instances are simple data carriers; they do not copy the coefficient
 * arrays and therefore rely on the caller to treat those arrays as immutable.
 */
public final class RungeKuttaFehlbergMethod {
  private final boolean fsal;
  private final double[] c;
  private final double[][] a;
  private final double[] b;
  private final RungeKuttaStepInterpolator prototype;

  /**
   * Creates a definition for a Runge-Kutta-Fehlberg method.
   *
   * @param fsal whether the method has the first-same-as-last property
   * @param c time steps from the Butcher tableau (excluding the first zero)
   * @param a internal weights from the Butcher tableau (excluding the first empty row)
   * @param b external weights for the high-order method
   * @param prototype prototype interpolator used for dense output
   */
  public RungeKuttaFehlbergMethod(
      boolean fsal, double[] c, double[][] a, double[] b, RungeKuttaStepInterpolator prototype) {
    this.fsal = fsal;
    this.c = c;
    this.a = a;
    this.b = b;
    this.prototype = prototype;
  }

  public boolean fsal() {
    return fsal;
  }

  public double[] c() {
    return c;
  }

  public double[][] a() {
    return a;
  }

  public double[] b() {
    return b;
  }

  public RungeKuttaStepInterpolator prototype() {
    return prototype;
  }

  /**
   * Compare this method definition with another for structural equality.
   *
   * <p>The comparison treats the coefficient arrays as ordered value sequences rather than identity
   * references, ensuring two methods with identical tableau contents are equal even when backed by
   * distinct arrays.
   *
   * @param other candidate object to compare
   * @return {@code true} if all components are equal by value
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof RungeKuttaFehlbergMethod method)) {
      return false;
    }
    return method.fsal == fsal
        && Objects.equals(method.prototype, prototype)
        && Arrays.equals(method.c, c)
        && Arrays.deepEquals(method.a, a)
        && Arrays.equals(method.b, b);
  }

  /**
   * Compute a hash code consistent with the array-aware equality contract.
   *
   * <p>The hash is composed of the scalar fields and the contents of the coefficient arrays so that
   * equal method definitions share the same hash even if their arrays are distinct instances.
   *
   * @return hash code derived from field values and array contents
   */
  @Override
  public int hashCode() {
    int result = Objects.hash(fsal, prototype);
    result = 31 * result + Arrays.hashCode(c);
    result = 31 * result + Arrays.deepHashCode(a);
    result = 31 * result + Arrays.hashCode(b);
    return result;
  }

  /**
   * Render a descriptive string that includes the contents of each coefficient array.
   *
   * <p>The output mirrors the field order and formats arrays with {@link Arrays#toString(double[])}
   * and {@link Arrays#deepToString(Object[])} for easy inspection.
   *
   * @return human-readable representation containing array contents
   */
  @Override
  public @NotNull String toString() {
    return "RungeKuttaFehlbergMethod["
        + "fsal="
        + fsal
        + ", c="
        + Arrays.toString(c)
        + ", a="
        + Arrays.deepToString(a)
        + ", b="
        + Arrays.toString(b)
        + ", prototype="
        + prototype
        + "]";
  }
}
