package org.spaceroots.mantissa.fitting;

import java.io.Serial;
import org.spaceroots.mantissa.estimation.EstimatedParameter;

/**
 * Immutable parameter wrapper that represents a single polynomial coefficient estimated during a
 * curve fit.
 *
 * <p>Each instance binds together the numeric estimate managed by {@link
 * org.spaceroots.mantissa.estimation.Estimator} infrastructure and the monomial degree it applies
 * to. The coefficient name is derived from its degree (for example {@code a0}, {@code a1}, etc.) so
 * that estimators and callers can address parameters deterministically even when the fitter creates
 * them lazily. Objects are small, thread-safe after construction, and intended to be stored in the
 * coefficients array managed by {@link PolynomialFitter}. They do not mutate their identifying
 * degree, but their inherited estimate value changes as the underlying optimizer iterates.
 *
 * <p>Typical usage pairs a {@link PolynomialCoefficient} with each term of a polynomial model prior
 * to invoking the fitting process. Callers pass the instances to a fitter, inspect estimated values
 * after convergence, and may serialize them if needed.
 *
 * @see PolynomialFitter
 * @version $Id: PolynomialCoefficient.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public class PolynomialCoefficient extends EstimatedParameter {

  /**
   * Create a coefficient placeholder for the specified monomial degree.
   *
   * <p>The newly created parameter is named {@code a<degree>} and initialized with an estimate of
   * zero, allowing estimators to refine its value during optimization. The instance is typically
   * placed into the coefficients array of a {@link PolynomialFitter} immediately after creation.
   *
   * @param degree non-negative exponent of the monomial this coefficient multiplies; used to derive
   *     both the parameter name and the associated partial derivative during fitting.
   */
  public PolynomialCoefficient(int degree) {
    super("a" + degree, 0.0);
    this.degree = degree;
  }

  /** Degree of the monomial this coefficient scales; fixed for the lifetime of the instance. */
  private final int degree;

  /**
   * Get the monomial degree that identifies this coefficient.
   *
   * <p>The returned value is the exponent used both for naming (for example {@code a2}) and for
   * computing partial derivatives during polynomial fitting. It never changes after construction
   * and can be safely cached by callers.
   *
   * @return immutable, non-negative degree associated with this coefficient instance.
   */
  public int getDegree() {
    return degree;
  }

  @Serial private static final long serialVersionUID = 5775845068390259552L;
}
