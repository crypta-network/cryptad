package org.spaceroots.mantissa.estimation;

import java.io.Serial;
import java.io.Serializable;

/**
 * Represents a single parameter that participates in an estimation problem.
 *
 * <p>An {@code EstimatedParameter} carries three pieces of state: a stable textual name, the
 * current numeric estimate of its value, and a flag telling solvers whether the value should be
 * kept fixed during optimization. Instances are intentionally lightweight and mutable so that
 * iterative algorithms can update the value in place rather than copying large arrays of parameters
 * on each iteration. The name remains constant for the life of the instance, allowing higher-level
 * code to correlate results with human-readable identifiers.
 *
 * <p>Typical usage is to create one instance per unknown, pass it to an estimation problem
 * implementation, and let a solver adjust unbound parameters until its convergence criteria are
 * met. Bound parameters act like constants supplied to the solver; toggling the bound flag allows
 * callers to switch between “fixed” and “free” behavior without creating a new object.
 *
 * <ul>
 *   <li>Mutable: the estimate and bound flag may change between solver iterations.
 *   <li>Not thread-safe: callers should confine instances to a single thread or provide external
 *       synchronization.
 *   <li>Serializable: parameter sets can be persisted alongside other estimation artifacts.
 * </ul>
 *
 * @version $Id: EstimatedParameter.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class EstimatedParameter implements Serializable {

  /**
   * Builds a parameter with an initial estimate and marks it as unbound.
   *
   * <p>Use this variant when the parameter should be free to change during solver iterations. The
   * provided name is preserved exactly for later reporting; callers should avoid {@code null} or
   * empty strings to keep diagnostics meaningful. The numeric estimate is stored as-is, including
   * {@link Double#NaN} or infinities, so callers should supply values that match downstream solver
   * expectations.
   *
   * @param name descriptive, non-{@code null} identifier used in logs and result summaries.
   * @param firstEstimate initial numeric value supplied to the estimation algorithm; may be any
   *     {@code double} representable value.
   */
  public EstimatedParameter(String name, double firstEstimate) {
    this.name = name;
    estimate = firstEstimate;
    bound = false;
  }

  /**
   * Builds a parameter with an initial estimate and explicit bound state.
   *
   * <p>Choose this overload when the caller already knows whether the parameter should remain fixed
   * or adjustable. A bound parameter communicates to solvers that the value is trusted input and
   * must not be altered, while an unbound parameter participates in optimization. The constructor
   * does not validate the estimate; solvers decide how to treat special values.
   *
   * @param name descriptive, non-{@code null} identifier used in logs and result summaries.
   * @param firstEstimate initial numeric value supplied to the estimation algorithm; may be any
   *     {@code double} representable value.
   * @param bound {@code true} to freeze the parameter during estimation, {@code false} to allow
   *     solver-driven updates.
   */
  public EstimatedParameter(String name, double firstEstimate, boolean bound) {
    this.name = name;
    estimate = firstEstimate;
    this.bound = bound;
  }

  /**
   * Copy constructor that duplicates the current state of another parameter.
   *
   * <p>The new instance receives the same name reference, estimate value, and bound flag as the
   * source. Subsequent changes to either instance do not affect the other, making this suitable for
   * snapshotting solver state or branching hypothetical scenarios without mutating the original
   * parameter.
   *
   * @param parameter existing parameter whose name, estimate, and bound flag are cloned; must not
   *     be {@code null}.
   */
  public EstimatedParameter(EstimatedParameter parameter) {
    name = parameter.name;
    estimate = parameter.estimate;
    bound = parameter.bound;
  }

  /**
   * Replaces the current numeric estimate.
   *
   * <p>The new value is stored verbatim; no validation or normalization is performed. Solvers may
   * call this repeatedly during iterative optimization, and client code can also use it to inject
   * externally computed updates. Supplying {@link Double#NaN} or infinite values is permitted but
   * may cause downstream algorithms to reject the parameter or fail to converge.
   *
   * @param estimate updated numeric value representing the latest guess for this parameter; any
   *     {@code double} value is accepted.
   */
  public void setEstimate(double estimate) {
    this.estimate = estimate;
  }

  /**
   * Returns the current numeric estimate for this parameter.
   *
   * <p>This method is idempotent and threadsafe only to the extent that callers avoid concurrent
   * mutation of the same instance. Returned values are the last ones provided to the constructor or
   * {@link #setEstimate(double)} and may include {@link Double#NaN} or infinities if previously
   * set.
   *
   * @return the stored estimate value; never modified by this accessor and may be {@link
   *     Double#NaN} if set accordingly.
   */
  public double getEstimate() {
    return estimate;
  }

  /**
   * Provides the stable name associated with this parameter.
   *
   * <p>The name is set at construction and never changed, enabling callers to label solver outputs
   * and diagnostics reliably. The returned reference is the original string; callers should avoid
   * mutating it if a mutable implementation is used.
   *
   * @return immutable identifier string that was supplied at construction time.
   */
  public String getName() {
    return name;
  }

  /**
   * Updates the bound flag that signals whether solvers may alter this parameter.
   *
   * <p>Setting the flag to {@code true} indicates the estimate should remain fixed and treated as a
   * trusted input. Setting it to {@code false} allows solvers to modify the estimate during
   * optimization. This method performs no synchronization; callers coordinating multithreaded
   * access must guard the instance externally.
   *
   * @param bound {@code true} to freeze the value for solver runs, {@code false} to mark it
   *     adjustable.
   */
  public void setBound(boolean bound) {
    this.bound = bound;
  }

  /**
   * Indicates whether the parameter is currently marked as bound.
   *
   * <p>A bound parameter communicates to estimation algorithms that its value should be left
   * untouched. The flag can change over the life of the instance via {@link #setBound(boolean)}; no
   * thread-safety guarantees are provided.
   *
   * @return {@code true} when the bound flag is set, meaning the parameter should not be altered by
   *     solvers.
   */
  public boolean isBound() {
    return bound;
  }

  /**
   * Immutable, human-readable name that identifies this parameter within an estimation problem.
   *
   * <p>The value is provided during construction and used in logs, debug output, and result
   * reporting to correlate numeric estimates with domain concepts. It is never changed after
   * creation.
   */
  private final String name;

  /**
   * Mutable numeric value holding the latest estimate for this parameter.
   *
   * <p>This field is protected to support direct access from closely related subclasses that add
   * domain-specific semantics. External callers should prefer {@link #getEstimate()} and {@link
   * #setEstimate(double)} for clarity and future compatibility.
   */
  protected double estimate;

  /**
   * Flag indicating whether this parameter should remain fixed during estimation runs.
   *
   * <p>When {@code true}, solvers are expected to leave {@link #estimate} untouched. The flag is
   * mutable and may be toggled between successive solver invocations.
   */
  private boolean bound;

  @Serial private static final long serialVersionUID = -555440800213416949L;
}
