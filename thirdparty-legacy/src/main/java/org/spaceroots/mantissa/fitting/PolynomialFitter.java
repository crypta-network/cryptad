package org.spaceroots.mantissa.fitting;

import java.io.Serial;
import org.spaceroots.mantissa.estimation.EstimatedParameter;
import org.spaceroots.mantissa.estimation.Estimator;

/**
 * This class implements a curve fitting specialized for polynomials.
 *
 * <p>The fitter wires {@link PolynomialCoefficient} instances into an {@link Estimator} so the
 * regression problem can be solved with the same least-squares machinery used by other curve
 * fitters. Each coefficient acts as an {@link org.spaceroots.mantissa.estimation.EstimatedParameter
 * EstimatedParameter}, allowing callers to configure constraints, convergence thresholds, or
 * weighting at the estimator level rather than inside this class. The design therefore keeps the
 * fitter lightweight while still supporting robust solvers such as Gauss-Newton or Levenberg
 * Marquardt.
 *
 * <p>Typical usage builds the fitter with a degree, registers sample points via {@link
 * AbstractCurveFitter#addWeightedPair(double, double, double)}, and delegates the solve phase to
 * the estimator. The fitter stores coefficients in increasing degree order and evaluates
 * polynomials with Horner’s scheme, making the evaluation stable for modest degrees but still
 * sensitive to ill-conditioned data. Instances are mutable and not thread-safe; create one fitter
 * per concurrent regression to avoid parameter interference.
 *
 * <ul>
 *   <li>Supports dense polynomials via the degree-based constructor.
 *   <li>Supports sparse or pre-seeded polynomials by passing an explicit coefficient array.
 *   <li>Exposes coefficients as estimated parameters so advanced estimators can apply bounds or
 *       correlations.
 * </ul>
 *
 * @see PolynomialCoefficient
 * @version $Id: PolynomialFitter.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class PolynomialFitter extends AbstractCurveFitter {

  /**
   * Creates a fitter for a dense polynomial of the given degree.
   *
   * <p>The fitter will own a contiguous coefficient vector sized {@code degree + 1}, one parameter
   * per monomial from constant term to the highest degree. Use this constructor when every degree
   * up to the maximum should be estimated. For sparse polynomials where only select degrees are
   * present, prefer {@link #PolynomialFitter(PolynomialCoefficient[], Estimator)} with an
   * explicitly prepared array.
   *
   * @param degree maximal degree of the polynomial; negative values are not supported
   * @param estimator estimator to use for the fitting; must accept one parameter per coefficient
   */
  public PolynomialFitter(int degree, Estimator estimator) {
    super(degree + 1, estimator);
    for (int i = 0; i < coefficients.length; ++i) {
      coefficients[i] = new PolynomialCoefficient(i);
    }
  }

  /**
   * Creates a fitter backed by an existing array of coefficient parameters.
   *
   * <p>Use this variant to seed the optimizer with prior estimates or to fit sparse polynomials by
   * supplying only the degrees that matter. The fitter keeps a direct reference to the provided
   * array, so subsequent fitting rounds update the same {@link PolynomialCoefficient} instances in
   * place. Callers must ensure the array ordering matches increasing degree, starting at zero, to
   * keep evaluation consistent with {@link #valueAt(double)}.
   *
   * @param coefficients first estimate of the coefficients; array is stored and mutated in place
   * @param estimator estimator to use for the fitting; drives the optimization iterations
   */
  public PolynomialFitter(PolynomialCoefficient[] coefficients, Estimator estimator) {
    super(coefficients, estimator);
  }

  /**
   * Computes the polynomial value at the supplied abscissa using current estimates.
   *
   * <p>The evaluation uses Horner’s rule to reduce numerical error and minimize multiplications.
   * Coefficients are applied from the highest degree down to the constant term, reflecting the
   * current state of the estimator. Because coefficients are mutable during fitting, repeated calls
   * within an iteration reflect incremental optimizer updates. Inputs of large magnitude may still
   * amplify rounding error for high-degree polynomials; rescale data if stability is critical.
   *
   * @param x abscissa at which the theoretical value is requested; any finite double is accepted
   * @return polynomial value at {@code x}; caller owns the primitive result and may reuse it freely
   */
  @Override
  public double valueAt(double x) {
    double y = coefficients[coefficients.length - 1].getEstimate();
    for (int i = coefficients.length - 2; i >= 0; --i) {
      y = y * x + coefficients[i].getEstimate();
    }
    return y;
  }

  /**
   * Computes the partial derivative of the polynomial with respect to a coefficient.
   *
   * <p>Each {@link PolynomialCoefficient} corresponds to the monomial {@code x^degree}; therefore
   * the derivative of the polynomial value with respect to that coefficient is simply {@code
   * x^degree}. This helper exposes that value so estimators can populate Jacobian entries without
   * reconstructing the polynomial. Parameters belonging to other models are rejected to avoid
   * silently mis-shaping the Jacobian.
   *
   * @param x abscissa at which the partial derivative is requested; must be finite for usefulness
   * @param p parameter with respect to which the derivative is requested; must be a known {@link
   *     PolynomialCoefficient}
   * @return partial derivative value {@code x^degree} for the provided coefficient
   * @throws IllegalArgumentException if {@code p} is not a {@link PolynomialCoefficient} managed by
   *     this fitter
   */
  @Override
  public double partial(double x, EstimatedParameter p) {
    if (p instanceof PolynomialCoefficient coefficient) {
      return Math.pow(x, coefficient.getDegree());
    }
    throw new IllegalArgumentException("internal error");
  }

  @Serial private static final long serialVersionUID = -744904084649890769L;
}
