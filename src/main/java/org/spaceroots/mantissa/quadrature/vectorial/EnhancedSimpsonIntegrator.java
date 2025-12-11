package org.spaceroots.mantissa.quadrature.vectorial;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;

/**
 * This class implements an enhanced Simpson-like integrator.
 *
 * <p>It evaluates vector-valued samples delivered by a {@link SampledFunctionIterator} and applies
 * a quadratic Simpson scheme that adapts its coefficients to the actual spacing between consecutive
 * abscissas. When the iterator provides evenly spaced samples the algorithm matches the classical
 * Simpson rule; when the spacing varies, it recomputes the weights so that the local polynomial
 * still interpolates the three-point window before accumulating the contribution into the running
 * integral. The integrator consumes the iterator exactly once and returns the component-wise
 * cumulative integral at the last available sample, using the underlying {@link
 * EnhancedSimpsonIntegratorSampler} to manage state.
 *
 * <p>Typical usage is to create one instance and call {@link #integrate(SampledFunctionIterator)}
 * for each sampled function. No configuration is stored between invocations, so instances are
 * lightweight and best treated as single-use helpers. The implementation is not synchronized; if an
 * application needs concurrent integrations, create distinct instances per thread or guard access
 * externally. The iterator is expected to provide monotonically increasing abscissas and a stable
 * dimensionality so that the returned array aligns with the sampled vector components.
 *
 * <ul>
 *   <li>Supports irregular sampling without degrading to linear interpolation except on a trailing
 *       incomplete step.
 *   <li>Falls back to a trapezoid estimate for the final partial window when fewer than three
 *       points remain.
 *   <li>Returns a fresh array to protect the accumulated sum from external modification.
 * </ul>
 *
 * @see EnhancedSimpsonIntegratorSampler
 * @see SampledFunctionIterator
 * @version $Id: EnhancedSimpsonIntegrator.java 1709 2006-12-03 21:16:50Z luc $
 * @author L. Maisonobe
 */
public class EnhancedSimpsonIntegrator implements SampledFunctionIntegrator {

  /**
   * Creates a new integrator instance with no retained state between integrations.
   *
   * <p>The constructor performs no validation or allocation beyond the object itself. All runtime
   * configuration is supplied by the {@link SampledFunctionIterator} passed to {@link
   * #integrate(SampledFunctionIterator)}. Instances are lightweight; prefer creating one per caller
   * when integrating concurrently instead of sharing a single instance across threads.
   */
  public EnhancedSimpsonIntegrator() {
    // default constructor
  }

  public double[] integrate(SampledFunctionIterator iter)
      throws ExhaustedSampleException, FunctionException {

    EnhancedSimpsonIntegratorSampler sampler = new EnhancedSimpsonIntegratorSampler(iter);
    double[] sum = null;

    while (sampler.hasNext()) {
      sum = sampler.nextSamplePoint().y;
    }

    return sum;
  }
}
