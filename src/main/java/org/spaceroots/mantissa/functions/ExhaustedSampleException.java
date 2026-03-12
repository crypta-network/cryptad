package org.spaceroots.mantissa.functions;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Exception indicating that a sample iterator has no more data to provide.
 *
 * <p>This exception is raised when a sampling routine exhausts the finite set of elements it
 * exposes, such as while integrating or fitting a function using precomputed sample points. It
 * enables callers to stop iteration cleanly instead of relying on sentinel values or null checks,
 * which keeps sampling loops explicit and deterministic. Typical usage is to catch the exception at
 * the boundary of the sampling algorithm and perform any final aggregation or logging before
 * releasing resources.
 *
 * <p>The exception is immutable and carries the last known sample size to aid diagnostics without
 * exposing mutable state. It is intended for single-threaded use of iterators but can safely be
 * shared across threads as a passive data carrier because its content never changes.
 *
 * <ul>
 *   <li>Signals premature iteration end when a requested sample index is out of bounds.
 *   <li>Encourages explicit control flow for algorithms that depend on fixed-size datasets.
 * </ul>
 *
 * @version $Id: ExhaustedSampleException.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
public class ExhaustedSampleException extends MantissaException {

  /**
   * Builds an exception instance that records the available sample size for diagnostics.
   *
   * <p>Use this constructor when an iterator or sampler detects that the caller asked for an index
   * beyond the available element count. The provided {@code size} is embedded in the message so
   * higher layers can log or surface the limit encountered. Constructing the exception does not
   * perform I/O or extra validation, keeping it safe to create inside tight loops while still
   * preserving clear control flow around exhaustion events.
   *
   * @param size total elements available in the sample when exhaustion occurred; must be
   *     non-negative
   */
  public ExhaustedSampleException(int size) {
    super("sample contains only {0} elements", new String[] {Integer.toString(size)});
  }

  @Serial private static final long serialVersionUID = -1490493298938282440L;
}
