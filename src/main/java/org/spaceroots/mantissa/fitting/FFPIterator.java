package org.spaceroots.mantissa.fitting;

import java.io.Serial;
import java.io.Serializable;
import org.spaceroots.mantissa.functions.ExhaustedSampleException;
import org.spaceroots.mantissa.functions.FunctionException;
import org.spaceroots.mantissa.functions.vectorial.SampledFunctionIterator;
import org.spaceroots.mantissa.functions.vectorial.VectorialValuedPair;

/**
 * Iterator that exposes successive samples of a scalar function along with a finite-difference
 * estimate of its first derivative.
 *
 * <p>This helper is used during harmonic coefficient estimation where the fitting routine needs a
 * stream of {@link VectorialValuedPair vector-valued samples}. Each call to {@link
 * #nextSamplePoint()} returns the pair {@code [f(t), f'(t)]} at the current measurement abscissa,
 * computed from adjacent measurements using a simple first-order difference. The iterator advances
 * strictly forward through the provided measurements and never revisits earlier points, which makes
 * it suitable for one-pass fitting or streaming pipelines.
 *
 * <p><strong>Usage notes:</strong>
 *
 * <ul>
 *   <li>Input measurements must be ordered by increasing abscissa so that derivative estimates use
 *       meaningful step sizes.
 *   <li>The iterator is not thread-safe; confine each instance to a single fitting run.
 *   <li>Derivative estimates use a two-sided difference centered on the current point except for
 *       the edges, which are handled implicitly by the initial seeding.
 * </ul>
 *
 * @see F2FP2Iterator
 * @see HarmonicCoefficientsGuesser
 * @version $Id: FFPIterator.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
class FFPIterator implements SampledFunctionIterator, Serializable {

  /**
   * Build an iterator seeded with the first two measurements so derivative estimates can start on
   * the third point.
   *
   * <p>The array must contain at least two consecutive measurements with strictly increasing
   * abscissas because the iterator performs a forward shift on every call. The provided array is
   * not copied; callers should avoid mutating it while iteration is in progress.
   *
   * @param measurements ordered measurement array (length ≥ 2) supplying abscissas and values.
   */
  public FFPIterator(AbstractCurveFitter.FitMeasurement[] measurements) {
    this.measurements = measurements;

    // initialize the points of the raw sample
    current = measurements[0];
    currentY = current.getMeasuredValue();
    next = measurements[1];
    nextY = next.getMeasuredValue();
    nextIndex = 2;
  }

  /**
   * Return the dimensionality of the vector produced for each sample point.
   *
   * <p>The iterator always yields two values per abscissa: the measured function value and the
   * finite-difference derivative estimate.
   *
   * @return {@code 2}, representing {@code f(x)} and {@code f'(x)} components.
   */
  @Override
  public int getDimension() {
    return 2;
  }

  /**
   * Check whether another sample point can be produced.
   *
   * <p>Returns {@code true} while the iterator still holds a pending look-ahead measurement; it
   * becomes {@code false} only after the final stored measurement has been consumed during a call
   * to {@link #nextSamplePoint()}.
   *
   * @return {@code true} when a subsequent call to {@link #nextSamplePoint()} will succeed.
   */
  @Override
  public boolean hasNext() {
    return nextIndex < measurements.length;
  }

  /**
   * Advance to the next measurement and return the value/derivative pair at its abscissa.
   *
   * <p>The derivative is computed as a symmetric first-order difference using the previous and next
   * measurements surrounding the current one: {@code (nextY - previousY) / (nextX - previousX)}.
   * Callers must iterate in order; skipping {@link #hasNext()} checks may lead to an {@link
   * ExhaustedSampleException}. The returned pair reuses no shared buffers, so callers may retain it
   * safely.
   *
   * @return two-element vector where element 0 is {@code f(x)} and element 1 is {@code f'(x)}.
   * @throws ExhaustedSampleException if called after the final measurement has already been
   *     returned.
   * @throws FunctionException if the underlying measurement retrieval signals a functional error.
   */
  @Override
  public VectorialValuedPair nextSamplePoint() throws ExhaustedSampleException, FunctionException {
    if (nextIndex >= measurements.length) {
      throw new ExhaustedSampleException(measurements.length);
    }

    // shift the points
    AbstractCurveFitter.FitMeasurement previous = current;
    double previousY = currentY;
    current = next;
    currentY = nextY;
    next = measurements[nextIndex++];
    nextY = next.getMeasuredValue();

    // return the two dimensions vector [f(x), f'(x)]
    double[] table = new double[2];
    table[0] = currentY;
    table[1] = (nextY - previousY) / (next.x - previous.x);
    return new VectorialValuedPair(current.x, table);
  }

  /** Ordered measurements supplied by the caller; not defensively copied. */
  private final AbstractCurveFitter.FitMeasurement[] measurements;

  /** Index of the measurement that will become the next look-ahead point. */
  private int nextIndex;

  /** Measurement associated with the last value returned by {@link #nextSamplePoint()}. */
  private AbstractCurveFitter.FitMeasurement current;

  /**
   * Raw value of the look-ahead measurement, cached to avoid repeated {@code getMeasuredValue()}.
   */
  private double nextY;

  /** Measurement used as a look-ahead to compute the derivative for the current point. */
  private AbstractCurveFitter.FitMeasurement next;

  /** Raw value associated with {@link #current}, cached alongside the measurement. */
  private double currentY;

  /** Serialization identifier, kept stable to preserve stream compatibility. */
  @Serial private static final long serialVersionUID = -3187229691615380125L;
}
