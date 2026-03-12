package org.spaceroots.mantissa.fitting;

import java.io.Serial;
import org.spaceroots.mantissa.estimation.EstimatedParameter;
import org.spaceroots.mantissa.estimation.EstimationException;
import org.spaceroots.mantissa.estimation.Estimator;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Curve fitter for single-frequency harmonic signals.
 *
 * <p>Provides least-squares estimation of amplitude {@code a}, pulsation {@code omega}, and phase
 * {@code phi} for the model {@code f(t) = a cos(omega t + phi)}. Instances manage three {@link
 * EstimatedParameter} coefficients and delegate iterative solving to an injected {@link Estimator}.
 * When constructed without an initial vector, the fitter derives a first guess from sorted sample
 * points using {@link HarmonicCoefficientsGuesser}, which expects at least four measurements with
 * varied abscissae.
 *
 * <p>The class stores measurements in insertion order and performs a defensive sort before
 * computing guesses to stabilize the integral-based heuristic. The fitter mutates the shared
 * coefficient objects during estimation; callers may reuse the instance across runs provided they
 * supply fresh measurements or reset estimates as needed. The implementation is not synchronized
 * and should be confined to a single thread per instance.
 *
 * <ul>
 *   <li>Responsibilities: coefficient priming, delegate setup, and harmonic value/gradient helpers.
 *   <li>Limitations: optimized neither for memory nor for real-time execution.
 * </ul>
 *
 * @see AbstractCurveFitter
 * @see HarmonicCoefficientsGuesser
 * @author L. Maisonobe
 * @version $Id: HarmonicFitter.java 1709 2006-12-03 21:16:50Z luc $
 */
public class HarmonicFitter extends AbstractCurveFitter {

  /**
   * Creates a fitter that will compute its own initial coefficient guess.
   *
   * <p>Constructs a three-parameter harmonic fitter and seeds the parameters with neutral starting
   * values ({@code a=2π}, {@code omega=0}, {@code phi=0}). The instance records that a heuristic
   * first guess is still required; the next call to {@link #fit()} will sort the accumulated
   * measurements, derive an initial estimate via {@link HarmonicCoefficientsGuesser}, and then
   * launch the delegated estimator.
   *
   * @param estimator least-squares estimator driving iterations; must accept three parameters and
   *     produce updated estimates
   */
  public HarmonicFitter(Estimator estimator) {
    super(3, estimator);
    coefficients[0] = new EstimatedParameter("a", 2.0 * Math.PI);
    coefficients[1] = new EstimatedParameter("omega", 0.0);
    coefficients[2] = new EstimatedParameter("phi", 0.0);
    firstGuessNeeded = true;
  }

  /**
   * Creates a fitter using caller-provided coefficient estimates.
   *
   * <p>Use this constructor when the caller already holds an amplitude, pulsation, and phase
   * estimate that should seed the solver. The provided array is retained and mutated directly by
   * the fitter, so subsequent calls to {@link #fit()} will update the same objects. Because an
   * initial vector is present, no heuristic guessing is performed unless the caller resets the
   * {@code firstGuessNeeded} flag manually.
   *
   * @param coefficients mutable parameter array ordered as {@code a}, {@code omega}, {@code phi};
   *     must contain three non-null entries ready for adjustment
   * @param estimator estimator to iterate the least-squares problem; configured for three
   *     parameters
   */
  public HarmonicFitter(EstimatedParameter[] coefficients, Estimator estimator) {
    super(coefficients, estimator);
    firstGuessNeeded = false;
  }

  /**
   * Performs harmonic least-squares estimation using the configured estimator.
   *
   * <p>When a first guess is required, the method validates that at least four measurements are
   * present, sorts them to stabilize the heuristic, and delegates initial value computation to
   * {@link HarmonicCoefficientsGuesser}. It then invokes the superclass implementation, which
   * forwards the prepared parameters and measurements to the injected {@link Estimator}. After a
   * successful call, {@code firstGuessNeeded} is cleared so subsequent invocations reuse the
   * current estimates unless measurements or coefficients are reset by the caller.
   *
   * @return array containing the updated estimates ordered as {@code a}, {@code omega}, {@code
   *     phi}; the array is managed by the fitter
   * @throws EstimationException if fewer than four measurements are available or if guessing or
   *     estimation fails inside the delegate
   */
  @Override
  public double[] fit() throws EstimationException {
    if (firstGuessNeeded) {
      if (measurements.size() < 4) {
        throw new EstimationException(
            "sample must contain at least {0} points", new String[] {Integer.toString(4)});
      }

      sortMeasurements();

      try {
        HarmonicCoefficientsGuesser guesser =
            new HarmonicCoefficientsGuesser((FitMeasurement[]) getMeasurements());
        guesser.guess();

        coefficients[0].setEstimate(guesser.getA());
        coefficients[1].setEstimate(guesser.getOmega());
        coefficients[2].setEstimate(guesser.getPhi());
      } catch (ExhaustedSampleException | FunctionException e) {
        throw new EstimationException(e);
      }

      firstGuessNeeded = false;
    }

    return super.fit();
  }

  /**
   * Get the current amplitude coefficient estimate.
   *
   * <p>Returns the latest in-memory value of {@code a} used by the fitter. Before the first solve
   * it reflects the constructor seed; after {@link #fit()} completes it contains the optimized
   * amplitude corresponding to the most recent measurement set. Callers may read it between
   * iterations to monitor convergence or after solving to persist the result.
   *
   * @return current amplitude estimate as a double; value is mutable and owned by the fitter
   */
  public double getAmplitude() {
    return coefficients[0].getEstimate();
  }

  /**
   * Get the current pulsation coefficient estimate.
   *
   * <p>Exposes the stored {@code omega} value representing angular frequency. Prior to solving it
   * matches the initial seed; after {@link #fit()} the value is whatever the estimator last
   * computed. The returned primitive is a snapshot, while the underlying {@link EstimatedParameter}
   * remains mutable for subsequent runs.
   *
   * @return present pulsation estimate in radians per unit abscissa; snapshot of mutable state
   */
  public double getPulsation() {
    return coefficients[1].getEstimate();
  }

  /**
   * Get the current phase coefficient estimate.
   *
   * <p>Returns the {@code phi} parameter representing phase offset applied to the cosine model. It
   * may be the seed value or an optimized result depending on whether {@link #fit()} has run. The
   * number is not normalized; callers may wrap it to {@code [-π, π]} or another range if desired.
   *
   * @return present phase estimate in radians; snapshot that may change on subsequent fits
   */
  public double getPhase() {
    return coefficients[2].getEstimate();
  }

  /**
   * Get the value of the function at x according to the current parameters value.
   *
   * <p>Evaluates {@code f(x) = a cos(omega x + phi)} using the fitter's current estimates without
   * modifying them. This helper is useful for inspecting residuals, plotting predicted curves, or
   * building custom merit functions prior to solving. It performs no validation of the estimates
   * and assumes they represent a consistent harmonic parameterization.
   *
   * @param x abscissa at which the theoretical value is requested; any real value is accepted
   * @return computed model value at {@code x} based on the latest coefficient estimates
   */
  @Override
  public double valueAt(double x) {
    double a = coefficients[0].getEstimate();
    double omega = coefficients[1].getEstimate();
    double phi = coefficients[2].getEstimate();
    return a * Math.cos(omega * x + phi);
  }

  /**
   * Get the derivative of the function at x with respect to parameter p.
   *
   * <p>Computes the partial derivative of {@code f(x)} with respect to one of the harmonic
   * parameters while holding the others constant. The method relies on identity checks against the
   * internally stored {@link EstimatedParameter} instances; callers should pass the same objects
   * obtained from the fitter rather than newly created parameter instances.
   *
   * @param x abscissa at which the partial derivative is requested; accepts any finite value
   * @param p parameter with respect to which the derivative is requested; must be one of the
   *     fitter's internal coefficient objects
   * @return partial derivative value for the requested parameter at {@code x}; based on current
   *     estimates
   */
  @Override
  public double partial(double x, EstimatedParameter p) {
    double a = coefficients[0].getEstimate();
    double omega = coefficients[1].getEstimate();
    double phi = coefficients[2].getEstimate();
    if (p == coefficients[0]) {
      return Math.cos(omega * x + phi);
    } else {
      double v = Math.sin(omega * x + phi);
      if (p == coefficients[1]) {
        return -a * x * v;
      } else {
        return -a * v;
      }
    }
  }

  /** Indicator of the need to compute a first guess of the coefficients. */
  private boolean firstGuessNeeded;

  @Serial private static final long serialVersionUID = -8722683066277473450L;
}
