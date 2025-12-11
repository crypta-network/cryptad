package org.spaceroots.mantissa.quadrature.scalar;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.scalar.SampledFunctionIterator;

/**
 * Integrator for scalar functions provided as discrete samples.
 *
 * <p>Implementations consume a {@link SampledFunctionIterator} and compute a definite integral over
 * the iterator's full span using whatever quadrature rule they provide (trapezoidal, Simpson,
 * adaptive rules, and so on). The iterator is expected to deliver abscissa/ordinate pairs in
 * strictly increasing abscissa order; callers are responsible for creating or rewinding the
 * iterator because integrators typically read it exactly once. Implementations are usually
 * stateless, but they may cache intermediate values while streaming the samples; reuse across
 * threads should therefore follow each implementation's thread-safety guidance.
 *
 * <p>Typical usage creates an iterator from a sampled function, passes it to an integrator, and
 * collects the returned primitive double as the integral over the iterator's range. The interface
 * intentionally leaves tolerance handling and step-size assumptions to implementations so callers
 * can select the strategy that best matches their sampling density and error budget.
 *
 * <ul>
 *   <li>Consumes the entire iterator range exactly once.
 *   <li>Reports insufficient data via {@link ExhaustedSampleException}.
 *   <li>Surfaces underlying function errors via {@link FunctionException}.
 * </ul>
 *
 * @see SampledFunctionIterator
 * @see ComputableFunctionIntegrator
 * @version $Id: SampledFunctionIntegrator.java 1231 2002-03-12 20:07:04Z luc $
 * @author L. Maisonobe
 */
public interface SampledFunctionIntegrator {
  /**
   * Integrate a sample over its overall range.
   *
   * <p>The integrator advances the supplied iterator from its current position to exhaustion,
   * accumulating an estimate of the definite integral that spans the iterator's abscissa domain.
   * Callers should create a fresh iterator for each integration attempt; partial consumption is not
   * rewound. Implementations may assume monotonic abscissas and finite spacing but must signal when
   * a scheme cannot proceed because too few points remain. Any exception from the sampled function
   * is propagated unchanged to make error handling explicit.
   *
   * <pre>{@code
   * // Example: integrate a sampled function with the default iterator
   * SampledFunctionIterator iterator = builder.buildIterator();
   * double area = integrator.integrate(iterator);
   * }</pre>
   *
   * @param iter iterator providing ordered scalar samples to integrate; must not be null
   * @return definite integral value over the iterator range using the implementation scheme
   * @exception ExhaustedSampleException if iterator ends before scheme obtains required sample
   *     points
   * @exception FunctionException if sampled function evaluation during iteration signals an error
   */
  double integrate(SampledFunctionIterator iter) throws ExhaustedSampleException, FunctionException;
}
