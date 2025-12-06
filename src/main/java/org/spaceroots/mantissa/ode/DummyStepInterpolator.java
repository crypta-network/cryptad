package org.spaceroots.mantissa.ode;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.Serial;

/**
 * Step interpolator that returns the end-of-step state without computing a curve.
 *
 * <p>This lightweight implementation exists for callers that register a {@link StepHandler step
 * handler} but never request intermediate evaluations between the solver grid points. The
 * interpolated state is always copied from the already known end-of-step state when {@link
 * AbstractStepInterpolator#setInterpolatedTime(double)} is invoked, so no additional derivative
 * evaluations or polynomial reconstruction are performed. It is therefore useful for performance
 * sensitive integrations, for prototype creation through the cloning pattern, or whenever the
 * consumer is satisfied with fixed-step output.
 *
 * <p>The instance mirrors the lifecycle of {@link AbstractStepInterpolator}: it starts empty, must
 * be {@link AbstractStepInterpolator#reinitialize(double[], boolean) reinitialized} before use, and
 * is reused by the integrator across steps. The class is not thread-safe and relies on the mutable
 * arrays provided by the owning integrator; copies made through {@link #copy()} detach the backing
 * state snapshot at the time of cloning.
 *
 * <ul>
 *   <li>Responsibility: expose the last computed state without interpolation math.
 *   <li>Trade-off: minimal overhead, but no intermediate times can be synthesized.
 *   <li>Serialization: supports externalization of the base interpolator state for checkpointing.
 * </ul>
 *
 * @see StepHandler
 * @version $Id: DummyStepInterpolator.java 1721 2007-10-07 20:21:25Z luc $
 * @author L. Maisonobe
 */
public class DummyStepInterpolator extends AbstractStepInterpolator implements StepInterpolator {

  /**
   * Create an uninitialized interpolator ready for delayed setup.
   *
   * <p>The newly created instance contains no allocated state arrays. Callers are expected to
   * supply step end values via {@link AbstractStepInterpolator#reinitialize(double[], boolean)}
   * before the object participates in an integration loop. Integrators such as {@link
   * RungeKuttaFehlbergIntegrator} typically allocate a single prototype interpolator and clone it
   * for each run to minimize setup costs and to keep the interpolation strategy pluggable.
   */
  public DummyStepInterpolator() {
    super();
  }

  /**
   * Create an initialized interpolator bound to an existing state buffer.
   *
   * <p>This constructor is typically used internally by integrators that manage their own state
   * arrays. The interpolator stores only a reference to {@code y}; callers must ensure the array is
   * populated with end-of-step values before interpolation is attempted and remains valid for the
   * duration of the step processing.
   *
   * @param y reference to the mutable integrator state array holding end-of-step values
   * @param forward {@code true} when integration time increases; {@code false} for backward steps
   */
  protected DummyStepInterpolator(double[] y, boolean forward) {
    super(y, forward);
  }

  /**
   * Create a deep copy of another dummy interpolator.
   *
   * <p>The clone shares no mutable arrays with the source; it captures the current interpolated and
   * current state so that subsequent updates to the original do not leak into the copy. This is
   * used by integrators that follow the prototyping pattern to generate thread-local or step-local
   * interpolators on demand.
   *
   * @param interpolator existing interpolator whose state and direction are replicated
   */
  protected DummyStepInterpolator(DummyStepInterpolator interpolator) {
    super(interpolator);
  }

  /**
   * Create a detached copy suitable for independent interpolation requests.
   *
   * <p>The returned instance preserves the current time, direction, and state snapshot of the
   * source interpolator. Subsequent updates to either instance do not affect the other, making this
   * method appropriate when the same integration step must be examined concurrently at different
   * interpolated times or when caching a snapshot for later analysis.
   *
   * @return new {@code DummyStepInterpolator} containing the same state values and integration
   *     direction as this instance
   */
  @Override
  public DummyStepInterpolator copy() {
    return new DummyStepInterpolator(this);
  }

  /**
   * Copy the end-of-step state into the interpolated slot without recomputation.
   *
   * <p>Unlike rich interpolators, this implementation ignores {@code theta} and {@code
   * oneMinusThetaH}. It simply mirrors the current state into the interpolated buffer so that calls
   * to {@link AbstractStepInterpolator#getInterpolatedState()} yield the same values stored at the
   * end of the step in {@link AbstractStepInterpolator#currentState}. The method preserves {@link
   * AbstractStepInterpolator} invariants and relies on the caller to ensure the current state was
   * freshly computed by the underlying integrator before invocation.
   *
   * @param theta normalized interpolation abscissa; zero is start of step, one is end of step
   * @param oneMinusThetaH signed time gap from interpolated time to current grid point, in seconds
   * @throws DerivativeException propagated if the base class requires derivative evaluation hooks
   *     that fail during copying or validation
   */
  protected void computeInterpolatedState(double theta, double oneMinusThetaH)
      throws DerivativeException {
    System.arraycopy(currentState, 0, interpolatedState, 0, currentState.length);
  }

  /**
   * Write the externalized form of the interpolator state.
   *
   * <p>Only the base class fields are serialized; no additional data is emitted because this
   * implementation performs no interpolation-specific bookkeeping. The output stream is expected to
   * remain open after the call so that callers can chain serialization of other objects.
   *
   * @param out destination stream that receives the normalized base interpolator fields
   * @throws IOException if the underlying stream rejects the serialized form or closes prematurely
   */
  public void writeExternal(ObjectOutput out) throws IOException {
    // save the state of the base class
    writeBaseExternal(out);
  }

  /**
   * Restore the interpolator from an externalized form and resynchronize its timeline.
   *
   * <p>The method delegates deserialization of core state to the base class, then sets the
   * interpolated time so that subsequent {@link AbstractStepInterpolator#getInterpolatedState()}
   * calls are immediately valid. Any {@link DerivativeException} encountered during reattachment is
   * wrapped as an {@link IOException} to comply with the {@link java.io.Externalizable} contract.
   *
   * @param in source stream positioned at a serialized {@code DummyStepInterpolator} payload
   * @throws IOException if the serialized form is corrupt or derivative recomputation fails
   */
  public void readExternal(ObjectInput in) throws IOException {

    // read the base class
    double t = readBaseExternal(in);

    try {
      // we can now set the interpolated time and state
      setInterpolatedTime(t);
    } catch (DerivativeException e) {
      throw new IOException(e);
    }
  }

  @Serial private static final long serialVersionUID = 1708010296707839488L;
}
