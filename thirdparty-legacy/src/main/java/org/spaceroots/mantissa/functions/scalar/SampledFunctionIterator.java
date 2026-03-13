package org.spaceroots.mantissa.functions.scalar;

import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;

/**
 * Iterator that exposes successive samples of a scalar-valued function on a predefined support.
 *
 * <p>Implementations present function evaluations one point at a time, usually walking through a
 * regular grid or a supplied collection of abscissae. Clients typically loop with {@link
 * #hasNext()} followed by {@link #nextSamplePoint()} to stream data into downstream consumers
 * without material inspection of the entire sample set. Most implementations are stateful and
 * single-use: once a point has been returned it is considered consumed and will not be served
 * again. Unless stated otherwise, instances are not thread-safe and should be confined to the
 * thread performing the sampling.
 *
 * <p>This iterator is useful when the function values are expensive to compute or need to be
 * generated lazily, such as when sampling numerical integrations, interpolated trajectories, or
 * external data feeds. Clients can stop early based on convergence checks, propagate exceptions
 * raised during function evaluation, or combine results with additional metadata carried by {@link
 * ScalarValuedPair}.
 *
 * <ul>
 *   <li>Provides forward-only access to ordered sample points.
 *   <li>Propagates underlying computation failures through {@link FunctionException}.
 *   <li>Signals depletion via {@link ExhaustedSampleException}.
 * </ul>
 *
 * @see SampledFunction
 * @see ScalarValuedPair
 * @version $Id: SampledFunctionIterator.java 1666 2005-12-15 16:37:55Z luc $
 * @author L. Maisonobe
 */
public interface SampledFunctionIterator {

  /**
   * Check if another sampled point is available without advancing the iterator state.
   *
   * <p>The method performs a non-consuming check: subsequent calls to {@link #nextSamplePoint()}
   * will return the same next item until it is actually consumed. Typical callers use this in a
   * loop to terminate gracefully when the sample stream runs out rather than relying on exception
   * control flow. Implementations should keep this check inexpensive; repeated calls must not
   * modify internal position or trigger new evaluations.
   *
   * @return true if another sample can be delivered on the next call to {@link #nextSamplePoint()}.
   */
  boolean hasNext();

  /**
   * Get the next available point of the sampled function.
   *
   * <p>Calling this method advances the iterator and returns the paired abscissa and ordinate
   * encapsulated in a {@link ScalarValuedPair}. The method is typically invoked within a {@code
   * while (iterator.hasNext())} loop and is expected to return promptly once computation completes.
   * Implementations should document whether the returned pair is immutable; callers should avoid
   * modifying mutable results to prevent surprising interactions with downstream processing.
   *
   * <pre>{@code
   * while (iterator.hasNext()) {
   *   ScalarValuedPair sample = iterator.nextSamplePoint();
   *   process(sample);
   * }
   * }</pre>
   *
   * @return the next sampled abscissa/value pair; never null when the iterator has a next element
   * @throws ExhaustedSampleException if the sample stream has been fully consumed
   * @throws FunctionException if evaluating the underlying function fails for the next point
   */
  ScalarValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException;
}
