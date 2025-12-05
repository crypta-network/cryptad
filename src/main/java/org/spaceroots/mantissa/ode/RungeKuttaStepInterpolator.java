package org.spaceroots.mantissa.ode;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;

/**
 * Dense output helper for a single Runge-Kutta integration step.
 *
 * <p>The interpolator rebuilds the continuous state between two grid points after a Runge-Kutta or
 * Runge-Kutta-Fehlberg step has been computed by an integrator. It stores the set of intermediate
 * stage derivatives ({@code yDotK}) produced during the step and exposes a uniform {@link
 * AbstractStepInterpolator} contract so step handlers can query any intermediate time without
 * re-evaluating the differential equations. A new instance is created by integrators, reinitialized
 * with step data, finalized lazily when interpolation is first requested, and then discarded or
 * cloned for later reuse.
 *
 * <p>Instances are mutable and <strong>not</strong> thread-safe; each integration run must use a
 * dedicated interpolator chain. Typical call flow is: construct (or clone a prototype), call {@link
 * #reinitialize(FirstOrderDifferentialEquations, double[], double[][], boolean)}, let the
 * integrator advance the step, and allow step handlers to interrogate interpolated states via the
 * inherited API. Cloning is deep with respect to stored derivatives so callers may safely keep
 * copies beyond the life of the original step.
 *
 * <ul>
 *   <li>Responsibilities: carry Runge-Kutta stage slopes for dense output
 *   <li>Lifecycle: constructed empty, reinitialized per step, optionally cloned
 *   <li>Concurrency: no internal synchronization; use per-thread instances
 * </ul>
 *
 * @see RungeKuttaIntegrator
 * @see RungeKuttaFehlbergIntegrator
 * @version $Id: RungeKuttaStepInterpolator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
abstract class RungeKuttaStepInterpolator extends AbstractStepInterpolator {

  /**
   * Simple constructor.
   *
   * <p>Builds an empty, non-finalized interpolator that must be initialized later with {@link
   * #reinitialize(FirstOrderDifferentialEquations, double[], double[][], boolean)} before any
   * interpolation attempt. Integrators rely on this constructor to create a prototype that can be
   * cloned cheaply for every step, deferring array allocation until real step data is available.
   * The resulting instance holds no references to equations or slopes until reinitialized and is
   * therefore safe to reuse as a lightweight template.
   */
  protected RungeKuttaStepInterpolator() {
    super();
    yDotK = null;
    equations = null;
  }

  /**
   * Copy constructor.
   *
   * <p>The copied interpolator should have been finalized before the copy, otherwise the copy will
   * not be able to perform correctly any interpolation and will throw a {@link
   * NullPointerException} later. Since we don't want this constructor to throw the exceptions
   * finalization may involve and since we don't want this method to modify the state of the copied
   * interpolator, finalization is <strong>not</strong> done automatically, it remains under user
   * control.
   *
   * <p>The copy is a deep copy: its arrays are separated from the original arrays of the instance.
   *
   * <p>Use this constructor when a previously finalized interpolator must be retained independently
   * of future steps (for example when a dense output model is stored). Arrays holding intermediate
   * derivatives are deep-copied so modifications in one instance never leak into the other. The
   * original interpolator state (current state, time, direction) is preserved, while references to
   * the differential equations are intentionally dropped to avoid accidental reuse.
   *
   * @param interpolator interpolator to copy from; must already be finalized for accurate
   *     interpolation results.
   */
  public RungeKuttaStepInterpolator(RungeKuttaStepInterpolator interpolator) {

    super(interpolator);

    if (interpolator.currentState != null) {
      int dimension = currentState.length;

      yDotK = new double[interpolator.yDotK.length][];
      for (int k = 0; k < interpolator.yDotK.length; ++k) {
        yDotK[k] = new double[dimension];
        System.arraycopy(interpolator.yDotK[k], 0, yDotK[k], 0, dimension);
      }

    } else {
      yDotK = null;
    }

    // we cannot keep any reference to the equations in the copy
    // the interpolator should have been finalized before
    equations = null;
  }

  /**
   * Reinitialize the instance for a new Runge-Kutta step.
   *
   * <p>Integrators invoke this hook once per accepted step to supply the terminal state value, the
   * ordered array of stage derivatives, and the integration direction. It resets internal caches
   * inherited from {@link AbstractStepInterpolator} while retaining references to the provided
   * arrays so that interpolation can be finalized lazily on demand. Callers must ensure the
   * provided arrays remain valid and unmodified for the duration of interpolation of that step.
   *
   * <pre>{@code
   * interpolator.reinitialize(equations, yEnd, kSlopes, forward);
   * interpolator.storeTime(stepEnd);
   * }</pre>
   *
   * @param equations set of first-order differential equations; never {@code null} and consistent
   *     with the integrator producing the step.
   * @param y reference to the state values at the end of the current step; contents are reused
   *     until the interpolator is reinitialized again.
   * @param yDotK reference to the intermediate Runge-Kutta slopes ordered by stage index; all inner
   *     arrays must have the same dimension as {@code y}.
   * @param forward {@code true} if integration advances toward increasing time, {@code false}
   *     otherwise; preserved to honor interpolation direction.
   */
  public void reinitialize(
      FirstOrderDifferentialEquations equations, double[] y, double[][] yDotK, boolean forward) {
    reinitialize(y, forward);
    this.yDotK = yDotK;
    this.equations = equations;
  }

  /**
   * Save the state of the instance.
   *
   * <p>Serializes the base interpolator data followed by every stored Runge-Kutta stage derivative
   * for the current step. The referenced differential equations instance is deliberately excluded
   * because it is not serializable and is expected to be supplied again on reinitialization.
   *
   * @param out stream where to save the state; must remain open for the duration of serialization
   *     and is not closed by this method.
   * @throws IOException if any element of the state cannot be written to the provided stream.
   */
  public void writeExternal(ObjectOutput out) throws IOException {

    // save the state of the base class
    writeBaseExternal(out);

    // save the local attributes
    out.writeInt(yDotK.length);
    for (int k = 0; k < yDotK.length; ++k) {
      for (int i = 0; i < currentState.length; ++i) {
        out.writeDouble(yDotK[k][i]);
      }
    }

    // we do not save any reference to the equations

  }

  /**
   * Read the state of the instance.
   *
   * <p>Restores the serialized interpolator content, including all intermediate derivatives, and
   * resets the equations reference to {@code null}. After deserialization the caller must supply an
   * equations instance via {@link #reinitialize(FirstOrderDifferentialEquations, double[],
   * double[][], boolean)} before performing further interpolations.
   *
   * @param in stream where to read the state from; must deliver the data written by {@link
   *     #writeExternal(ObjectOutput)} in the same order.
   * @throws IOException if the serialized form is truncated, malformed, or cannot be processed due
   *     to underlying I/O errors.
   */
  public void readExternal(ObjectInput in) throws IOException {

    // read the base class
    double t = readBaseExternal(in);

    // read the local attributes
    int kMax = in.readInt();
    yDotK = new double[kMax][];
    for (int k = 0; k < kMax; ++k) {
      yDotK[k] = new double[currentState.length];
      for (int i = 0; i < currentState.length; ++i) {
        yDotK[k][i] = in.readDouble();
      }
    }

    equations = null;

    try {
      // we can now set the interpolated time and state
      setInterpolatedTime(t);
    } catch (DerivativeException e) {
      IOException ioe = new IOException();
      ioe.initCause(e);
      throw ioe;
    }
  }

  /**
   * Slopes evaluated at each Runge-Kutta stage for the current step.
   *
   * <p>Each inner array has the same dimension as the state vector and is reused by the integrator
   * across steps. The interpolator keeps a direct reference and assumes callers preserve these
   * values until the next {@link #reinitialize(FirstOrderDifferentialEquations, double[],
   * double[][], boolean)} invocation.
   */
  protected double[][] yDotK;

  /**
   * Reference to the differential equations being integrated during the current step.
   *
   * <p>The reference is transient across serialization and is reset after reading external state.
   * It is provided by {@link #reinitialize(FirstOrderDifferentialEquations, double[], double[][],
   * boolean)} and is not owned by the interpolator.
   */
  protected FirstOrderDifferentialEquations equations;
}
