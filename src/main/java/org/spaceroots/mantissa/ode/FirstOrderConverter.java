package org.spaceroots.mantissa.ode;

/**
 * Converts a second order differential equations set to a first order one usable by standard
 * integrators.
 *
 * <p>This adapter wraps a {@link SecondOrderDifferentialEquations} instance and exposes it through
 * the {@link FirstOrderDifferentialEquations} interface so callers can reuse first order
 * integrators without rewriting their problem model. The conversion doubles the dimension of the
 * state vector: for an original size <code>n</code>, the first <code>n</code> components carry the
 * position variables and the remaining <code>n</code> components carry their first derivatives. The
 * resulting derivative vector therefore contains both first and second time derivatives, allowing
 * existing first order solvers to advance the state.
 *
 * <p>Each {@link #computeDerivatives(double, double[], double[])} call copies up to <code>4n</code>
 * scalar values to split and reassemble the state, so users should account for the transient memory
 * churn and CPU overhead. The converter is mutable only through the working arrays it owns; it is
 * not thread-safe for concurrent integration steps but may be reused sequentially across multiple
 * runs. Prefer implementing a direct first order formulation when minimizing copying is critical.
 *
 * <ul>
 *   <li>Responsibility: dispatch second order state into position/velocity, forward the model, then
 *       pack combined derivatives.
 *   <li>Trade-off: convenience and API compatibility in exchange for predictable duplication work
 *       per step.
 *   <li>Typical use: wrap a legacy second order model and pass this converter to a {@link
 *       FirstOrderIntegrator}.
 * </ul>
 *
 * @see FirstOrderIntegrator
 * @see FirstOrderDifferentialEquations
 * @see SecondOrderDifferentialEquations
 * @version $Id: FirstOrderConverter.java 1253 2002-06-20 17:47:07Z luc $
 * @author L. Maisonobe
 */
public class FirstOrderConverter implements FirstOrderDifferentialEquations {

  /**
   * Simple constructor. Build a converter around a second order equations set.
   *
   * <p>The created instance keeps references to working arrays sized from the provided model's
   * dimension. Callers should create one converter per problem instance or guard access externally
   * when sharing across threads.
   *
   * @param equations second order equations set to convert; must be non-null and dimensionally
   *     stable during the converter lifetime
   */
  public FirstOrderConverter(SecondOrderDifferentialEquations equations) {
    this.equations = equations;
    dimension = equations.getDimension();
    z = new double[dimension];
    zDot = new double[dimension];
    zDDot = new double[dimension];
  }

  /**
   * Returns the dimension of the converted first order problem.
   *
   * <p>The dimension is exactly twice the underlying second order dimension because the converter
   * concatenates position and velocity components into a single state vector.
   *
   * @return total size of the combined state vector (positions then velocities), always <code>2*n
   *     </code>
   */
  @Override
  public int getDimension() {
    return 2 * dimension;
  }

  /**
   * Computes the first order derivative vector corresponding to the augmented state.
   *
   * <p>This method splits the incoming state <code>y</code> into position and velocity slices,
   * delegates the second derivative computation to the wrapped model, then reassembles the result
   * so the first half of {@code yDot} contains velocities and the second half contains
   * accelerations. Both input arrays must have a length of exactly {@link #getDimension()}. No
   * defensive copies are made; the method writes directly into the provided {@code yDot}.
   *
   * <pre>{@code
   * FirstOrderConverter converter = new FirstOrderConverter(model);
   * double[] state = {...};
   * double[] derivative = new double[state.length];
   * converter.computeDerivatives(t, state, derivative);
   * }</pre>
   *
   * @param t current integration time; passed unchanged to the underlying second order model
   * @param y combined state array containing positions then velocities; length must equal {@link
   *     #getDimension()}
   * @param yDot output array receiving velocities then accelerations; must be preallocated to the
   *     same length as {@code y}
   * @throws DerivativeException if the wrapped {@link SecondOrderDifferentialEquations} signals a
   *     failure while computing second derivatives
   */
  @Override
  public void computeDerivatives(double t, double[] y, double[] yDot) throws DerivativeException {

    // split the state vector in two
    System.arraycopy(y, 0, z, 0, dimension);
    System.arraycopy(y, dimension, zDot, 0, dimension);

    // apply the underlying equations set
    equations.computeSecondDerivatives(t, z, zDot, zDDot);

    // build the result state derivative
    System.arraycopy(zDot, 0, yDot, 0, dimension);
    System.arraycopy(zDDot, 0, yDot, dimension, dimension);
  }

  /** Underlying second order equations set. */
  private final SecondOrderDifferentialEquations equations;

  /** second order problem dimension. */
  private final int dimension;

  /** state vector. */
  private final double[] z;

  /** first time derivative of the state vector. */
  private final double[] zDot;

  /** second time derivative of the state vector. */
  private final double[] zDDot;
}
