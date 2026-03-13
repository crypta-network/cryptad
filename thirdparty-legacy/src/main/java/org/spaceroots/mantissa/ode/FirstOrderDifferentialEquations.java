package org.spaceroots.mantissa.ode;

/**
 * Interface describing a system of first-order ordinary differential equations (ODEs) that can be
 * integrated numerically.
 *
 * <p>Implementations expose the mathematical model {@code dY/dt = f(t, Y)} where {@code Y} is the
 * state vector and {@code f} computes its time derivative. Integrators use this contract to query
 * the system repeatedly while advancing the numerical solution. The interface deliberately focuses
 * on the minimal coupling needed by an integrator: a fixed dimension, an immutable view of the
 * current state, and a writable buffer for derivatives. Model-specific constants or configuration
 * values remain the responsibility of the implementing class.
 *
 * <p>Typical usage follows a pull model: an integration routine calls {@link #getDimension()} once
 * to allocate working arrays, then invokes {@link #computeDerivatives(double, double[], double[])}
 * many times as it explores the trajectory. Implementations should keep {@code getDimension()}
 * stable over the lifetime of an integration step and avoid side effects beyond filling the
 * derivative array. Unless documented otherwise they are not required to be thread-safe, so callers
 * should confine each instance to a single integration thread.
 *
 * <ul>
 *   <li><b>Responsibilities:</b> report a consistent state dimension and provide derivatives on
 *       demand.
 *   <li><b>Notable behaviors:</b> derivative computation must neither mutate the provided state
 *       array nor rely on hidden internal time progression.
 *   <li><b>Failure handling:</b> throw {@link DerivativeException} when the model cannot evaluate
 *       safely (singularities, invalid parameters, or user cancellation).
 * </ul>
 *
 * @see FirstOrderIntegrator
 * @see FirstOrderConverter
 * @see SecondOrderDifferentialEquations
 * @see org.spaceroots.mantissa.utilities.ArraySliceMappable
 * @version $Id: FirstOrderDifferentialEquations.java 1719 2007-09-26 19:46:57Z luc $
 * @author L. Maisonobe
 */
public interface FirstOrderDifferentialEquations {

  /**
   * Return the number of state variables that define this first-order system.
   *
   * <p>The dimension is typically the length of every state vector {@code Y} passed to or produced
   * by the integrator. Implementations should return a strictly positive value and keep it
   * constant; integrators rely on this to size their work arrays, validate inputs, and detect
   * mismatched states early. While most models expose physical units through each component, this
   * method only reports the aggregate size and leaves interpretation to the caller. Implementations
   * are encouraged to document component ordering separately to aid client code.
   *
   * @return size of the state vector, strictly positive and stable during integrator calls
   */
  int getDimension();

  /**
   * Compute the instantaneous time derivative of the supplied state vector.
   *
   * <p>The integrator provides the current time and state and expects this method to populate the
   * {@code yDot} buffer with {@code dY/dt}. Implementations must not reallocate or resize the
   * arrays; instead they should write results directly into {@code yDot} using the same ordering
   * and length reported by {@link #getDimension()}. The input state {@code y} should be treated as
   * read-only. Any persistent model parameters (e.g., masses, forces, or system matrices) should be
   * stored in the instance and consulted here. This method may be called thousands of times per
   * integration step, so it should avoid unnecessary object creation. When evaluation cannot
   * proceed safely (singularity, invalid input range, or external stop request), it should raise a
   * {@link DerivativeException}.
   *
   * <pre>{@code
   * // Example: simple exponential decay dY/dt = -k * Y
   * public void computeDerivatives(double t, double[] y, double[] yDot) {
   *   yDot[0] = -decayConstant * y[0];
   * }
   * }</pre>
   *
   * @param t current integration time, in the units defined by the model; may be increasing or
   *     decreasing depending on integrator direction
   * @param y state vector at time {@code t}; length must equal {@link #getDimension()}; contents
   *     must remain unmodified by the implementation
   * @param yDot destination array for computed derivatives; caller preallocates; length matches
   *     {@code y}; implementation writes each component without allocating new storage
   * @throws DerivativeException if the derivative cannot be evaluated reliably for the supplied
   *     state or if the model detects an unrecoverable condition
   */
  void computeDerivatives(double t, double[] y, double[] yDot) throws DerivativeException;
}
