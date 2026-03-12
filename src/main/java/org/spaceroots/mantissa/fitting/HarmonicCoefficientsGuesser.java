package org.spaceroots.mantissa.fitting;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.estimation.EstimationException;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;
import org.spaceroots.mantissa.quadrature.vectorial.EnhancedSimpsonIntegratorSampler;

/**
 * Estimates the amplitude, angular frequency, and phase of a harmonic signal from sampled data.
 *
 * <p>This helper builds an initial guess for a sinusoid {@code f(t) = a * cos(omega * t + phi)}
 * using only time-stamped measurements. It integrates the squared signal and the squared numerical
 * derivative, then solves a two-parameter least-squares system that links the two integrals; the
 * resulting coefficients provide the amplitude and pulsation. A second pass averages cosine/sine
 * projections to recover the phase. The entire procedure runs in linear time with a single
 * traversal of the sample stream, avoiding Fourier transforms or windowing choices.
 *
 * <p>Typical workflow:
 *
 * <ul>
 *   <li>Create an instance with chronologically ordered {@link AbstractCurveFitter.FitMeasurement}
 *       values representing the sampled function.
 *   <li>Invoke {@link #guess()} once to populate amplitude, angular frequency, and phase fields.
 *   <li>Read {@link #getA()}, {@link #getOmega()}, and {@link #getPhi()} to seed a non-linear curve
 *       fitter or optimizer.
 * </ul>
 *
 * <p>The instance retains intermediate sums and therefore is not thread-safe. Estimates assume a
 * single dominant harmonic component and may degrade with heavy noise or multiple tones; use a
 * downstream fitter to refine the result. When {@link #guess()} has not been executed, getter
 * methods return {@code Double.NaN} to signal the absence of a computed estimate.
 *
 * @version $Id: HarmonicCoefficientsGuesser.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 * @see AbstractCurveFitter
 */
public class HarmonicCoefficientsGuesser implements Serializable {

  /**
   * Construct a guesser bound to the provided measurements.
   *
   * <p>The array is defensively cloned so subsequent user modifications do not alter the internal
   * state. Measurements are expected to describe the sampled function in chronological order so the
   * Simpson sampler can compute finite differences for the derivative term. All coefficient fields
   * are initialized to {@code Double.NaN}; they remain in that state until {@link #guess()} is
   * executed successfully. Supplying fewer than three points will cause estimation to fail because
   * the derivative approximation requires neighboring values.
   *
   * @param measurements sequentially ordered sample points of the observed harmonic signal; the
   *     array is cloned and must not be {@code null}.
   */
  public HarmonicCoefficientsGuesser(AbstractCurveFitter.FitMeasurement[] measurements) {
    this.measurements = measurements.clone();
    a = Double.NaN;
    omega = Double.NaN;
  }

  /**
   * Compute initial amplitude, angular frequency, and phase estimates from the stored sample set.
   *
   * <p>The method first solves a least-squares system on squared integrals to infer the amplitude
   * and angular frequency, then averages cosine/sine projections to deduce the phase. All results
   * are cached inside this instance and replace any previous estimate, so repeated calls recompute
   * the same values for unchanged input. Callers should invoke this method before reading any
   * getter; otherwise the getters will return {@code Double.NaN} to indicate that no estimate was
   * produced.
   *
   * @throws ExhaustedSampleException if the sampler runs out of points before finishing.
   * @throws FunctionException if the underlying numerical integrator reports an evaluation error.
   * @throws EstimationException if the sample is too short or leads to negative square roots.
   */
  public void guess() throws ExhaustedSampleException, FunctionException, EstimationException {
    guessAOmega();
    guessPhi();
  }

  /**
   * Estimate a first guess of the a and &omega; coefficients.
   *
   * @throws ExhaustedSampleException if the sample is exhausted.
   * @throws FunctionException if the integrator throws one.
   * @throws EstimationException if the sample is too short or if the first guess cannot be computed
   *     (when the elements under the square roots are negative).
   */
  private void guessAOmega()
      throws ExhaustedSampleException, FunctionException, EstimationException {

    // initialize the sums for the linear model between the two integrals
    double sx2 = 0.0;
    double sy2 = 0.0;
    double sxy = 0.0;
    double sxz = 0.0;
    double syz = 0.0;

    // build the integrals sampler
    F2FP2Iterator iter = new F2FP2Iterator(measurements);
    SampledFunctionIterator sampler = new EnhancedSimpsonIntegratorSampler(iter);
    VectorialValuedPair p0 = sampler.nextSamplePoint();
    double p0X = p0.x;
    double[] p0Y = p0.y;

    // get the points for the linear model
    while (sampler.hasNext()) {

      VectorialValuedPair point = sampler.nextSamplePoint();
      double pX = point.x;
      double[] pY = point.y;

      double x = pX - p0X;
      double y = pY[0] - p0Y[0];
      double z = pY[1] - p0Y[1];

      sx2 += x * x;
      sy2 += y * y;
      sxy += x * y;
      sxz += x * z;
      syz += y * z;
    }

    // compute the amplitude and pulsation coefficients
    double c1 = sy2 * sxz - sxy * syz;
    double c2 = sxy * sxz - sx2 * syz;
    double c3 = sx2 * sy2 - sxy * sxy;
    if ((c1 / c2 < 0.0) || (c2 / c3 < 0.0)) {
      throw new EstimationException("unable to guess a first estimate");
    }
    a = Math.sqrt(c1 / c2);
    omega = Math.sqrt(c2 / c3);
  }

  /**
   * Estimate a first guess of the &phi; coefficient.
   *
   * @throws ExhaustedSampleException if the sample is exhausted.
   * @throws FunctionException if the sampler throws one.
   */
  private void guessPhi() throws ExhaustedSampleException, FunctionException {

    SampledFunctionIterator iter = new FFPIterator(measurements);

    // initialize the means
    double fcMean = 0.0;
    double fsMean = 0.0;

    while (iter.hasNext()) {
      VectorialValuedPair point = iter.nextSamplePoint();
      double omegaX = omega * point.x;
      double cosine = Math.cos(omegaX);
      double sine = Math.sin(omegaX);
      fcMean += omega * point.y[0] * cosine - point.y[1] * sine;
      fsMean += omega * point.y[0] * sine + point.y[1] * cosine;
    }

    phi = Math.atan2(-fsMean, fcMean);
  }

  /**
   * Return the estimated angular frequency in the sample time unit.
   *
   * <p>The value is computed during {@link #guess()} from the least-squares relation between the
   * squared signal integral and the squared derivative integral. It is always non-negative and
   * reflects the original time base; rescaling input timestamps scales this number accordingly. If
   * no estimate has been produced because {@link #guess()} failed or has not been invoked, the
   * method yields {@code Double.NaN} to signal the missing value.
   *
   * @return angular frequency estimate in radians per input time unit, or {@code Double.NaN} when
   *     the estimate is unavailable.
   */
  public double getOmega() {
    return omega;
  }

  /**
   * Return the estimated signal amplitude.
   *
   * <p>This value is inferred during {@link #guess()} by combining the linear regression results
   * that link squared integrals of the function and its derivative. The amplitude is computed as a
   * positive magnitude; noise or degenerate samples may still produce {@code Double.NaN} when the
   * estimation path fails. Prior to a successful {@link #guess()} invocation, the amplitude remains
   * unset and therefore returns {@code Double.NaN}.
   *
   * @return positive amplitude estimate consistent with the sampled signal, or {@code Double.NaN}
   *     when no estimate is available.
   */
  public double getA() {
    return a;
  }

  /**
   * Return the estimated phase shift of the signal.
   *
   * <p>The value is produced by averaging cosine and sine projections of the measurements after the
   * angular frequency has been inferred. The result follows the standard {@link Math#atan2(double,
   * double)} range, typically between {@code -Math.PI} and {@code Math.PI}. If {@link #guess()} has
   * not been executed, the method returns {@code Double.NaN} to indicate the absence of a phase
   * estimate.
   *
   * @return phase estimate in radians using the measurement time base, or {@code Double.NaN} when
   *     guessing has not succeeded.
   */
  public double getPhi() {
    return phi;
  }

  /** Immutable copy of the sampled measurements used to derive all coefficients. */
  private final AbstractCurveFitter.FitMeasurement[] measurements;

  /** Latest amplitude estimate; remains {@code Double.NaN} until {@link #guess()} succeeds. */
  private double a;

  /** Latest angular frequency estimate expressed in the input time unit. */
  private double omega;

  /** Latest phase estimate returned by {@link #getPhi()}. */
  private double phi;

  @Serial private static final long serialVersionUID = 2400399048702758814L;
}
