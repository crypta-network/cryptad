package org.spaceroots.mantissa.ode;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serializable;

/**
 * Base class for dense-output interpolators that reconstruct the ODE state between grid points.
 *
 * <p>An {@code AbstractStepInterpolator} instance is created by an integrator after each accepted
 * step and passed to {@link StepHandler step handlers}. Handlers call {@link #setInterpolatedTime}
 * followed by {@link #getInterpolatedState()} to obtain intermediate states without forcing extra
 * integration steps. The instance maintains the raw step endpoints, the integration direction, and
 * a mutable interpolated state buffer reused across calls.
 *
 * <p>Lifecycle overview:
 *
 * <ul>
 *   <li>{@link #reinitialize(double[], boolean)} prepares arrays and resets time markers.
 *   <li>{@link #storeTime(double)} records the end of a step and snapshots the current state.
 *   <li>{@link #setInterpolatedTime(double)} computes an intermediate state on demand.
 *   <li>{@link #finalizeStep()} ensures any delayed evaluations happen once per step.
 * </ul>
 *
 * Typical usage occurs within a single integration thread; instances are mutable and not thread
 * safe. To keep a snapshot beyond the current handler invocation, call {@link #finalizeStep()},
 * then {@link #copy()} to obtain an independent, deep-cloned interpolator. Copies inherit the
 * integration direction and already-computed data but remain detached from subsequent integrator
 * updates. Integrators are expected to progress monotonically in the {@linkplain #isForward()
 * forward} direction indicated here.
 *
 * @see FirstOrderIntegrator
 * @see SecondOrderIntegrator
 * @see StepHandler
 * @version $Id: AbstractStepInterpolator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public abstract class AbstractStepInterpolator implements Serializable {

  /** Previous grid point time, i.e. the start of the current step, in integration units. */
  protected double previousTime;

  /** Current grid point time recorded after the last accepted step. */
  protected double currentTime;

  /** Current step size, computed as {@code currentTime - previousTime}. */
  protected double h;

  /** State vector at {@link #currentTime}; shared with the owning integrator. */
  protected double[] currentState;

  /** Time at which {@link #interpolatedState} has been computed. */
  protected double interpolatedTime;

  /**
   * Working buffer holding the state corresponding to {@link #interpolatedTime}; reused across
   * interpolations within the same step.
   */
  protected double[] interpolatedState;

  /** Indicates whether {@link #finalizeStep()} has already been executed for this step. */
  private boolean finalized;

  /** Integration direction flag; {@code true} when time increases during integration. */
  private boolean forward;

  /**
   * Simple constructor for deferred initialization.
   *
   * <p>The created instance carries no state arrays until {@link #reinitialize(double[], boolean)}
   * is invoked. Integrators use this path when they need a prototype object to clone later (for
   * example, {@link RungeKuttaFehlbergIntegrator}) or when the step size is unknown during
   * construction. All time markers are initialized to {@link Double#NaN} so accidental use before
   * reinitialization is easy to detect. The constructor performs no allocation, which keeps cloning
   * inexpensive when integrators maintain internal pools of prototype interpolators.
   */
  protected AbstractStepInterpolator() {
    previousTime = Double.NaN;
    currentTime = Double.NaN;
    h = Double.NaN;
    interpolatedTime = Double.NaN;
    currentState = null;
    interpolatedState = null;
    finalized = false;
    this.forward = true;
  }

  /**
   * Simple constructor with immediate state binding.
   *
   * <p>Use this when the integrator already has a state vector available for the end of the step
   * and wants the interpolator to reference it directly. Because the array is not copied, any
   * in-place updates performed by the integrator remain visible to subsequent interpolation
   * requests, reducing memory churn but requiring callers to respect the integrator's ownership.
   *
   * @param y reference to the integrator-managed array holding the state at the end of the step;
   *     the reference is stored, not copied
   * @param forward integration direction indicator; {@code true} when time increases
   */
  protected AbstractStepInterpolator(double[] y, boolean forward) {

    previousTime = Double.NaN;
    currentTime = Double.NaN;
    h = Double.NaN;
    interpolatedTime = Double.NaN;

    currentState = y;
    interpolatedState = new double[y.length];

    finalized = false;
    this.forward = forward;
  }

  /**
   * Copy constructor creating a deep, detached interpolator.
   *
   * <p>The source should already be {@link #finalizeStep() finalized}; otherwise derivative data
   * may be missing and later interpolation attempts can raise a {@link NullPointerException}. To
   * avoid side effects, this constructor never finalizes the source automatically. All array fields
   * are deep-copied so the new instance can evolve independently while preserving the same step
   * bounds, direction, and precomputed interpolated state. Each clone therefore serves as a durable
   * snapshot that can survive beyond the lifetime of the integrator callback while the original
   * continues to mutate with new step data.
   *
   * @param interpolator interpolator to copy from; must describe a finalized step for safe use
   */
  protected AbstractStepInterpolator(AbstractStepInterpolator interpolator) {

    previousTime = interpolator.previousTime;
    currentTime = interpolator.currentTime;
    h = interpolator.h;
    interpolatedTime = interpolator.interpolatedTime;

    if (interpolator.currentState != null) {
      currentState = interpolator.currentState.clone();
      interpolatedState = interpolator.interpolatedState.clone();
    } else {
      currentState = null;
      interpolatedState = null;
    }

    finalized = interpolator.finalized;
    forward = interpolator.forward;
  }

  /**
   * Reinitialize the instance for a new step.
   *
   * <p>The method resets all time markers to {@link Double#NaN}, prepares a fresh {@link
   * #interpolatedState} array sized to the provided state vector, clears the {@link #finalized}
   * flag, and records the integration direction. Integrators invoke it when reusing an interpolator
   * across steps or when cloning a prototype to avoid repeated allocations.
   *
   * @param y reference to the integrator array holding the state at the end of the step; reused as
   *     {@link #currentState}
   * @param forward integration direction indicator; affects {@link #isForward()}
   */
  protected void reinitialize(double[] y, boolean forward) {

    previousTime = Double.NaN;
    currentTime = Double.NaN;
    h = Double.NaN;
    interpolatedTime = Double.NaN;

    currentState = y;
    interpolatedState = new double[y.length];

    finalized = false;
    this.forward = forward;
  }

  /**
   * Create a deep copy of the instance.
   *
   * <p>Callers should invoke {@link #finalizeStep()} before copying so that any delayed derivative
   * evaluations are captured; otherwise later calls that rely on those values may fail. The
   * returned instance owns independent arrays but preserves the same step metadata and computed
   * interpolation state, enabling safe storage of snapshots while the integrator continues. Copies
   * are the only supported mechanism for retaining dense output beyond the duration of a step
   * handler invocation.
   *
   * @return a copy of this interpolator with detached arrays and identical step metadata
   */
  public abstract AbstractStepInterpolator copy();

  /**
   * Shift one step forward.
   *
   * <p>Copies {@link #currentTime} into {@link #previousTime}, preparing the instance for the next
   * call to {@link #storeTime(double)}. This method does not modify state arrays. Integrators call
   * it immediately after accepting a step so that subsequent calls to {@link #storeTime(double)}
   * compute a consistent step size {@link #h}. It should never be used to skip finalization; doing
   * so leaves the current step in an undefined state for dense output.
   */
  public void shift() {
    previousTime = currentTime;
  }

  /**
   * Store the current step time and snapshot the state.
   *
   * @param t current time at the end of the step; may be greater or smaller than {@link
   *     #previousTime} depending on integration direction. The method also recomputes the step size
   *     {@link #h}, resets the interpolated time to the grid point, clones the current state into
   *     {@link #interpolatedState}, and clears the {@link #finalized} flag to allow deferred
   *     evaluations on the new step.
   */
  public void storeTime(double t) {

    currentTime = t;
    h = currentTime - previousTime;
    interpolatedTime = t;
    System.arraycopy(currentState, 0, interpolatedState, 0, currentState.length);

    // the step is not finalized anymore
    finalized = false;
  }

  /**
   * Get the previous grid point time.
   *
   * <p>The value corresponds to the start of the most recently accepted step and is initialized to
   * {@link Double#NaN} until the first call to {@link #shift()}. Client code can use this as the
   * lower bound when checking whether an interpolated time lies within the active step.
   *
   * @return previous grid point time marking the start of the current step
   */
  public double getPreviousTime() {
    return previousTime;
  }

  /**
   * Get the current grid point time.
   *
   * <p>This represents the upper bound of the current step. When combined with {@link
   * #getPreviousTime()}, it defines the domain over which interpolation is expected to be accurate.
   * The value remains {@link Double#NaN} until {@link #storeTime(double)} has been invoked at least
   * once.
   *
   * @return current grid point time stored by the most recent {@link #storeTime(double)} call
   */
  public double getCurrentTime() {
    return currentTime;
  }

  /**
   * Get the time of the interpolated point.
   *
   * <p>If {@link #setInterpolatedTime(double)} has not been called, it returns the current grid
   * point time. Once an interpolated time has been set, this value tracks the timestamp for which
   * {@link #getInterpolatedState()} will return a consistent snapshot, even if the request lies
   * outside the nominal step interval. Callers can compare it with {@link #getPreviousTime()} and
   * {@link #getCurrentTime()} to decide whether the current state represents interpolation or
   * extrapolation.
   *
   * @return interpolation point time associated with the last computed state
   */
  public double getInterpolatedTime() {
    return interpolatedTime;
  }

  /**
   * Set the time of the interpolated point and recompute the state.
   *
   * <p>Calling this method triggers {@link #computeInterpolatedState(double, double)} with the
   * appropriate normalized abscissa. Values outside the current step are permitted to ease
   * implementation of search algorithms near the step endpoints, but accuracy will degrade as the
   * requested time moves away from the stored step. The interpolated state buffer is overwritten in
   * place. The method may implicitly call {@link #finalizeStep()} if the interpolator defers some
   * evaluations.
   *
   * @param time time of the interpolated point, expressed in the same units as the integration
   *     variable; may lie outside the step bounds
   * @throws DerivativeException if evaluating the user-provided derivatives fails during automatic
   *     finalization or interpolation computations
   */
  public void setInterpolatedTime(double time) throws DerivativeException {
    interpolatedTime = time;
    double oneMinusThetaH = currentTime - interpolatedTime;
    computeInterpolatedState((h - oneMinusThetaH) / h, oneMinusThetaH);
  }

  /**
   * Check if the natural integration direction is forward.
   *
   * <p>The flag reflects the integrator's intended direction, protecting clients from anomalies
   * such as zero-length steps that could appear when switching functions or step control logic
   * cancels movement. Consumers of dense output should prefer this accessor over inferring the
   * direction from step endpoints because it is defined even before the first step is stored. The
   * value remains constant for the lifetime of the interpolator instance and is copied verbatim
   * when {@link #copy()} is invoked.
   *
   * @return {@code true} if the integration variable increases during integration; {@code false}
   *     otherwise
   */
  public boolean isForward() {
    return forward;
  }

  /**
   * Compute the state at the interpolated time.
   *
   * <p>Implementations fill {@link #interpolatedState} using the provided normalized abscissa and
   * time offset. They may reuse cached stage derivatives and must leave the buffer fully populated
   * when returning. No side effects outside this instance should be performed. Implementors should
   * avoid allocating temporary arrays for performance reasons and are free to exploit symmetry when
   * handling backward integration ({@code theta} outside the [0, 1] interval).
   *
   * @param theta normalized interpolation abscissa within the step (0 at {@link #previousTime}, 1
   *     at {@link #currentTime}); may fall outside [0, 1] for extrapolation requests
   * @param oneMinusThetaH time gap {@code currentTime - interpolatedTime}; sign matches integration
   *     direction
   * @throws DerivativeException if evaluating user derivatives during interpolation fails
   */
  protected abstract void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException;

  /**
   * Get the state vector of the interpolated point.
   *
   * <p>The returned array is a defensive copy; modifications will not affect the internal buffers.
   * Repeated calls after different {@link #setInterpolatedTime(double)} values will return
   * independent arrays reflecting each query, making it safe for callers to cache results without
   * cloning again.
   *
   * @return cloned state vector corresponding to {@link #getInterpolatedTime()}, leaving the
   *     internal buffer untouched
   */
  public double[] getInterpolatedState() {
    return interpolatedState.clone();
  }

  /**
   * Finalize the step.
   *
   * <p>Some interpolators defer expensive derivative evaluations until an interpolated state is
   * requested. This method ensures such deferred work executes at most once per step by invoking
   * {@link #doFinalize()} when needed and latching the {@link #finalized} flag. Handlers may call
   * it explicitly before introducing side effects in the ODE equations, or rely on implicit calls
   * from {@link #setInterpolatedTime(double)}.
   *
   * <p><strong>Warning:</strong> the interpolator instance provided to {@link
   * StepHandler#handleStep(StepInterpolator, boolean)} is only valid during that invocation. To
   * reuse later, call {@code finalizeStep()}, then {@link #copy()} and store the copy instead of
   * the transient original.
   *
   * @throws DerivativeException if user-supplied derivative computations fail during finalization
   */
  public final void finalizeStep() throws DerivativeException {
    if (!finalized) {
      doFinalize();
      finalized = true;
    }
  }

  /**
   * Perform implementation-specific finalization work.
   *
   * <p>The default implementation does nothing. Subclasses override this to trigger any additional
   * derivative evaluations required by their interpolation formulae. Implementations must remain
   * idempotent because {@link #finalizeStep()} guarantees single execution per step via a guard
   * flag.
   *
   * @throws DerivativeException if user derivative evaluation fails during subclass finalization
   */
  protected void doFinalize() throws DerivativeException {}

  /**
   * Save the base state of the instance.
   *
   * <p>Serializes dimensions, step bounds, direction, raw state, and interpolated time to the
   * provided stream. The interpolated state itself is omitted because it can be recomputed. Invokes
   * {@link #finalizeStep()} beforehand so deferred computations are included. Implementations that
   * extend the serialized form should call this method first, then write subclass fields.
   *
   * @param out stream where to save the state; must remain open for the duration of the write
   * @exception IOException if an I/O error occurs or finalization raises a derivative failure
   */
  protected void writeBaseExternal(ObjectOutput out) throws IOException {

    out.writeInt(currentState.length);
    out.writeDouble(previousTime);
    out.writeDouble(currentTime);
    out.writeDouble(h);
    out.writeBoolean(forward);

    for (double v : currentState) {
      out.writeDouble(v);
    }

    out.writeDouble(interpolatedTime);

    // we do not store the interpolated state,
    // it will be recomputed as needed after reading

    // finalize the step (and don't bother saving the now true flag)
    try {
      finalizeStep();
    } catch (DerivativeException e) {
      throw new IOException(e);
    }
  }

  /**
   * Read the base state of the instance.
   *
   * <p>Restores dimensions, step bounds, direction, and raw state from the stream. The interpolated
   * time and state remain unset; callers must later invoke {@link #setInterpolatedTime(double)}
   * after completing subclass-specific deserialization. The method assumes the serialized format
   * produced by {@link #writeBaseExternal(ObjectOutput)}.
   *
   * @param in stream where to read the state from; must supply data in the expected order
   * @return interpolated time placeholder read from the stream, to be applied by the caller later
   * @exception IOException if a read error occurs while reconstructing the base fields
   */
  protected double readBaseExternal(ObjectInput in) throws IOException {

    int dimension = in.readInt();
    previousTime = in.readDouble();
    currentTime = in.readDouble();
    h = in.readDouble();
    forward = in.readBoolean();

    currentState = new double[dimension];
    for (int i = 0; i < currentState.length; ++i) {
      currentState[i] = in.readDouble();
    }

    // we do NOT handle the interpolated time and state here
    interpolatedTime = Double.NaN;
    interpolatedState = new double[dimension];

    finalized = true;

    return in.readDouble();
  }
}
