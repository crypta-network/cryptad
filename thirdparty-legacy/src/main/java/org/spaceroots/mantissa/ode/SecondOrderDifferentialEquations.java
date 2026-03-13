package org.spaceroots.mantissa.ode;

/**
 * Models a system of coupled second order differential equations for numerical integration.
 *
 * <p>Implementations expose the mathematical model required by {@link SecondOrderIntegrator}
 * instances: given a time {@code t}, the current state vector {@code y}, and its first derivative
 * {@code yDot}, they supply the second derivative {@code yDDot}. The interface is deliberately
 * minimal so application code can supply domain-specific state containers, parameter handling, and
 * validation without constraining integrator implementations. Typical use wraps a physics or
 * engineering model whose natural form is {@code d2Y/dt^2 = f(t, Y, dY/dt)}, such as rigid-body
 * motion, oscillator chains, or orbital mechanics.
 *
 * <p>Instances are generally stateless and thread-safe if the underlying model is immutable; an
 * integrator may call the methods repeatedly with new array instances or may reuse arrays for
 * efficiency. Implementors should document any assumptions about array lengths or mutability and
 * avoid retaining references to caller-provided buffers. While parameter sets external to the state
 * vector are allowed, they must remain consistent for the duration of an integration pass to avoid
 * undefined trajectories.
 *
 * <ul>
 *   <li>Defines the dimension of the state space for all subsequent derivative evaluations.
 *   <li>Supplies the second derivative needed by position/velocity based integrators.
 *   <li>Provides a bridge for converting to first order form via {@link FirstOrderConverter}.
 * </ul>
 *
 * @see SecondOrderIntegrator
 * @see FirstOrderConverter
 * @see FirstOrderDifferentialEquations
 * @see org.spaceroots.mantissa.utilities.ArraySliceMappable
 * @version $Id: SecondOrderDifferentialEquations.java 1255 2002-06-20 17:50:50Z luc $
 * @author L. Maisonobe
 */
public interface SecondOrderDifferentialEquations {

  /**
   * Returns the fixed size of the state space described by this system.
   *
   * <p>The dimension is the number of scalar components in the state vector {@code y}. It must
   * remain constant throughout an integration and must match the lengths of the arrays passed to
   * {@link #computeSecondDerivatives(double, double[], double[], double[])}. Implementations are
   * expected to validate array sizes in their derivative computation and may signal mismatches
   * through a {@link DerivativeException}. Integrators typically call this method once during
   * initialization to allocate working buffers, so returning a consistent value is essential for
   * predictable memory usage and performance.
   *
   * @return the number of scalar state components that every argument array must contain
   */
  int getDimension();

  /**
   * Computes the second derivative of the state for the supplied time and first derivative.
   *
   * <p>The implementation must fill {@code yDDot} with {@code d2Y/dt2} values that correspond to
   * the provided time {@code t}, state {@code y}, and first derivative {@code yDot}. All arrays are
   * caller-owned and sized to {@link #getDimension()} elements; implementations should neither
   * resize nor retain them. This method is typically invoked many times per integration step, so it
   * should perform minimal allocation and be deterministic for identical inputs. If the model
   * cannot evaluate the derivative (for example because of invalid state, domain errors, or missing
   * parameters), it should throw a {@link DerivativeException} to abort the current integration
   * pass cleanly.
   *
   * @param t current value of the independent time variable, expressed in the model's time units
   * @param y array containing the current value of the state vector; length must match {@link
   *     #getDimension()}
   * @param yDot array containing the current value of the first derivative of the state vector;
   *     length must equal {@link #getDimension()}
   * @param yDDot preallocated array to receive the computed second derivative; sized to {@link
   *     #getDimension()}
   * @throws DerivativeException if the derivative cannot be computed for the supplied state and
   *     time or if array lengths are inconsistent
   */
  void computeSecondDerivatives(double t, double[] y, double[] yDot, double[] yDDot)
      throws DerivativeException;
}
