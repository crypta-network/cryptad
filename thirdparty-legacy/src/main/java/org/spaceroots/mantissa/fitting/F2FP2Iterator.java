package org.spaceroots.mantissa.fitting;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

/**
 * Iterator that exposes sampled values of the function {@code t -> [f(t)^2, f'(t)^2]}.
 *
 * <p>The iterator wraps an {@link FFPIterator} and transforms each sampled pair {@code (f(t),
 * f'(t))} into squared components to aid estimation of harmonic coefficients. It is intended for
 * the preprocessing stage of {@link HarmonicCoefficientsGuesser}, where magnitudes rather than raw
 * signed values simplify energy-based heuristics. The iteration order, sampling cadence, and
 * interpolation strategy are fully delegated to the underlying {@link FFPIterator} instance, so
 * callers should configure that iterator according to their measurement set and desired sampling
 * domain.
 *
 * <p>Instances are stateful and iterate once over the provided measurements; successive calls to
 * {@link #nextSamplePoint()} advance the shared cursor. The class does not perform any defensive
 * copying of measurement metadata; however, per-call results are backed by freshly allocated arrays
 * so downstream consumers can safely retain returned pairs. This implementation is not thread-safe:
 * coordinate all access through a single thread or external synchronization if the surrounding
 * fitter may be shared.
 *
 * <ul>
 *   <li>Produces two-dimensional squared outputs aligned with the original sampling order.
 *   <li>Surfaces exhaustion and function evaluation errors transparently from the wrapped iterator.
 *   <li>Designed for lightweight reuse within fitting pipelines without additional buffering.
 * </ul>
 *
 * @see FFPIterator
 * @see HarmonicCoefficientsGuesser
 */
class F2FP2Iterator implements SampledFunctionIterator, Serializable {

  /**
   * Builds an iterator that squares the values produced by an underlying {@link FFPIterator}.
   *
   * <p>The provided measurements define both the sampling grid and the raw function/derivative
   * pairs obtained during iteration. No copy of the array or its elements is made; callers should
   * therefore avoid mutating the measurements while iteration is in progress. The new iterator is
   * ready for immediate use and starts at the first measurement position.
   *
   * @param measurements ordered measurements that parameterize the wrapped iterator; must be
   *     non-null and contain all points needed for the fitting pass.
   */
  public F2FP2Iterator(AbstractCurveFitter.FitMeasurement[] measurements) {
    ffpIterator = new FFPIterator(measurements);
  }

  /**
   * Returns the fixed dimension of the sampled vectors produced by this iterator.
   *
   * <p>The output at every iteration step contains exactly two components: the squared value of the
   * function and the squared value of its first derivative at the sampled abscissa. Because this
   * dimension never varies with the measurement set, callers can allocate reusable buffers of size
   * two to minimize per-iteration overhead.
   *
   * @return {@code 2}, reflecting the squared function and squared derivative components that are
   *     always emitted together.
   */
  @Override
  public int getDimension() {
    return 2;
  }

  /**
   * Indicates whether additional squared samples remain to be read.
   *
   * <p>This method delegates to the wrapped {@link FFPIterator} and does not advance the iteration
   * cursor. Use it to guard calls to {@link #nextSamplePoint()} when consuming the iterator in a
   * loop. The result mirrors the availability of the underlying measurements; concurrent mutation
   * of that source is unsupported and may lead to inconsistent answers.
   *
   * @return {@code true} when at least one more sample can be produced; {@code false} once the
   *     measurement sequence has been exhausted.
   */
  @Override
  public boolean hasNext() {
    return ffpIterator.hasNext();
  }

  /**
   * Retrieves the next sample with squared function and derivative components.
   *
   * <p>The returned {@link VectorialValuedPair} preserves the abscissa from the underlying iterator
   * and supplies a new array whose elements are {@code f(t)^2} and {@code f'(t)^2}. Each invocation
   * advances the iterator state; calling this method after exhaustion will trigger the underlying
   * exception pathway. The method performs no caching, so repeated calls reflect the current cursor
   * position only.
   *
   * @return a newly allocated pair containing the current abscissa and a two-element array of
   *     squared values; the caller owns the returned array and may modify it safely.
   * @throws ExhaustedSampleException if the underlying iterator has no remaining samples at the
   *     time of invocation.
   * @throws FunctionException if evaluating the function or its derivative for the current sample
   *     fails or produces an inconsistent state.
   */
  @Override
  public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {

    // get the raw values from the underlying FFPIterator
    VectorialValuedPair point = ffpIterator.nextSamplePoint();
    double[] y = point.y;

    // square the values
    return new VectorialValuedPair(point.x, new double[] {y[0] * y[0], y[1] * y[1]});
  }

  private final FFPIterator ffpIterator;

  @Serial private static final long serialVersionUID = -8113110433795298072L;
}
