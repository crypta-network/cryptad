package org.spaceroots.mantissa.estimation;

import java.io.Serializable;

/**
 * Weighted scalar measurement participating in a least-squares estimation run.
 *
 * <p>This abstract type encapsulates the shared metadata needed by an estimation solver while
 * delegating model-specific details to subclasses. Each measurement carries an immutable weight
 * that scales its contribution to the cost function and a measured value that represents the raw
 * observation. Subclasses provide the link to the model by implementing {@link
 * #getTheoreticalValue()} and {@link #getPartial(EstimatedParameter)}, both of which must evaluate
 * the current parameter estimate maintained by the solver and supplied through {@link
 * EstimationProblem#getAllParameters()} or by direct access when the measurement is an inner class.
 *
 * <p>Instances can be marked as ignored via {@link #setIgnored(boolean)} to temporarily exclude bad
 * or outlying measurements without altering the surrounding problem definition. The ignore flag is
 * mutable, but the weight and measured value are fixed after construction so residuals remain
 * consistent across iterations. This class is deliberately lightweight and thread-hostile:
 * instances are expected to be confined to the solver thread that owns the current parameter vector
 * rather than shared concurrently.
 *
 * <ul>
 *   <li>Responsibilities: store observed value, expose residual and partial derivatives, convey
 *       per-measurement weighting.
 *   <li>Notable behaviors: optional exclusion via an ignore flag; residual computed lazily from
 *       theoretical value.
 * </ul>
 *
 * @see EstimationProblem
 * @version $Id: WeightedMeasurement.java 1679 2005-12-16 11:12:23Z luc $
 * @author L. Maisonobe
 */
public abstract class WeightedMeasurement implements Serializable {

  /**
   * Build a measurement with a fixed weight and observed value, initially considered valid.
   *
   * <p>This constructor is convenient for the common case where all measurements start included in
   * the optimization. The {@code weight} scales the contribution of the residual to the global cost
   * (use 1.0 for uniform influence or the inverse of the expected variance for heteroscedastic
   * data). The {@code measuredValue} is stored verbatim and later compared to the theoretical value
   * returned by {@link #getTheoreticalValue()} to compute residuals. The ignore flag defaults to
   * {@code false} so solvers will consume the measurement unless it is explicitly toggled later.
   *
   * @param weight positive scaling factor for this measurement within the least-squares objective;
   *     values near zero effectively down-weight outliers.
   * @param measuredValue raw observed quantity expressed in the same units as the theoretical
   *     counterpart computed by the model.
   */
  protected WeightedMeasurement(double weight, double measuredValue) {
    this.weight = weight;
    this.measuredValue = measuredValue;
    ignored = false;
  }

  /**
   * Build a measurement with explicit weight, observed value, and initial ignore policy.
   *
   * <p>Use this constructor when some observations should start excluded (for example, points
   * flagged during preprocessing) while still keeping their data available for later inclusion. The
   * {@code weight} and {@code measuredValue} behave identically to the single-argument constructor,
   * but the {@code ignored} flag immediately controls whether the solver should skip the
   * measurement. Downstream code may toggle the flag via {@link #setIgnored(boolean)} to re-enable
   * or suppress the measurement as iterative filters converge.
   *
   * @param weight positive scaling factor that modulates how much this measurement contributes to
   *     the accumulated chi-square error term.
   * @param measuredValue raw observed quantity expressed in the domain expected by the model; it is
   *     never modified after construction.
   * @param ignored whether the measurement is initially excluded from solver computations; {@code
   *     true} keeps it silent until explicitly re-enabled.
   */
  protected WeightedMeasurement(double weight, double measuredValue, boolean ignored) {
    this.weight = weight;
    this.measuredValue = measuredValue;
    this.ignored = ignored;
  }

  /**
   * Return the scalar weight applied to this measurement in the least-squares objective.
   *
   * <p>The weight is immutable after construction. Larger values make the residual associated with
   * this measurement influence parameter updates more strongly, while smaller values down-weight it
   * relative to other observations. Callers typically pick weights consistent with the inverse
   * variance of the measurement noise model.
   *
   * @return immutable weight scaling factor; callers must not assume any specific normalization.
   */
  public double getWeight() {
    return weight;
  }

  /**
   * Return the raw measured value captured for this observation.
   *
   * <p>The value is stored exactly as provided to the constructor and is never normalized or
   * altered by the solver. It should be expressed in the same units and reference frame as the
   * theoretical value computed by {@link #getTheoreticalValue()} to avoid bias in residuals.
   *
   * @return immutable measured value retained for residual computation and reporting.
   */
  public double getMeasuredValue() {
    return measuredValue;
  }

  /**
   * Compute the residual between the observed and theoretical values.
   *
   * <p>The residual equals {@code measuredValue - getTheoreticalValue()}. It is evaluated lazily
   * using the current parameter estimates held by the solver, so repeated calls may produce
   * different values as iterations progress. The method performs no bounds checking; callers should
   * ensure the underlying model remains numerically stable for the current parameter set.
   *
   * @return signed residual in the same units as the measurement; positive values indicate the
   *     observation exceeds the model prediction.
   */
  public double getResidual() {
    return measuredValue - getTheoreticalValue();
  }

  /**
   * Compute the theoretical value predicted by the model for the current parameters.
   *
   * <p>Implementations must read the most recent parameter estimates supplied by the solver so the
   * returned value reflects the solver's current iterate. The method should avoid side effects and
   * be deterministic for a fixed parameter vector because solvers may invoke it repeatedly while
   * assembling residuals and Jacobians. Implementations are responsible for any domain checks
   * needed to keep the model well-defined.
   *
   * @return model-predicted value expressed in the same units as {@link #getMeasuredValue()}, ready
   *     for residual computation.
   */
  public abstract double getTheoreticalValue();

  /**
   * Return the partial derivative of the theoretical value with respect to a parameter.
   *
   * <p>The derivative must be evaluated at the current parameter estimate managed by the solver.
   * Implementations should return zero for parameters that do not influence the measurement and
   * should be careful to keep derivative calculations numerically stable for ill-conditioned
   * models. Solvers typically build a Jacobian matrix by calling this method for each parameter
   * referenced by the measurement.
   *
   * @param parameter parameter whose influence on the theoretical value is being differentiated;
   *     must refer to a parameter known to the surrounding {@link EstimationProblem}.
   * @return partial derivative value; positive numbers indicate the theoretical value increases
   *     when the parameter grows.
   */
  public abstract double getPartial(EstimatedParameter parameter);

  /**
   * Update the ignore flag to include or exclude this measurement from solver computations.
   *
   * <p>Setting {@code ignored} to {@code true} removes the measurement from subsequent residual and
   * Jacobian calculations, which is useful for discarding late-detected outliers without altering
   * the problem structure. The flag can be flipped back to {@code false} if a measurement is
   * rehabilitated after additional validation steps. The method is not synchronized; callers should
   * coordinate access if measurements are shared across threads.
   *
   * @param ignored {@code true} to skip this measurement in solver iterations; {@code false} to
   *     reinstate it.
   */
  public void setIgnored(boolean ignored) {
    this.ignored = ignored;
  }

  /**
   * Indicate whether this measurement is currently excluded from solver processing.
   *
   * <p>The return value reflects the most recent call to {@link #setIgnored(boolean)} or the
   * constructor initialization. Solvers typically inspect this flag before consuming the
   * measurement; callers may also use it for reporting or diagnostics.
   *
   * @return {@code true} when the measurement is flagged as ignored and therefore omitted from cost
   *     and Jacobian assembly; {@code false} otherwise.
   */
  public boolean isIgnored() {
    return ignored;
  }

  /** Immutable weight applied to this measurement in the global least-squares objective. */
  private final double weight;

  /** Observed scalar value against which the model prediction is compared. */
  private final double measuredValue;

  /**
   * Mutable flag controlling whether the measurement participates in solver calculations; toggled
   * through {@link #setIgnored(boolean)}.
   */
  private boolean ignored;
}
