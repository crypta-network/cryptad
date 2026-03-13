package org.spaceroots.mantissa.geometry;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Exception signaling that a matrix failed validation as a proper rotation matrix.
 *
 * <p>This exception is raised by rotation builders that accept raw matrix coefficients when the
 * matrix is not orthogonal, has a determinant different from {@code +1}, or otherwise violates the
 * constraints required to represent a right-handed rotation in three-dimensional Euclidean space.
 * It allows callers to distinguish data-quality errors from numerical issues in downstream
 * computations.
 *
 * <p>Typical usage is inside {@link Rotation#Rotation(double[][], double)} and similar factory
 * methods: the builder performs structural checks and throws this exception before any rotation
 * instance is created, leaving input data unchanged. The type is immutable and thread-safe, so it
 * can be freely shared across threads without external synchronization.
 *
 * <pre>{@code
 * try {
 *   var rotation = new Rotation(matrix, tolerance);
 * } catch (NotARotationMatrixException ex) {
 *   // provide feedback to the caller
 * }
 * }</pre>
 *
 * <ul>
 *   <li>Use it to flag invalid sensor calibration or user-supplied attitude matrices.
 *   <li>Catch it to surface actionable validation feedback to API clients.
 *   <li>Normalize matrices yourself only when accuracy and stability requirements are understood.
 * </ul>
 *
 * @see Rotation
 * @version $Id: NotARotationMatrixException.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
public class NotARotationMatrixException extends MantissaException {

  /**
   * Builds an exception instance with a translated, parameterized message.
   *
   * <p>The constructor delegates to {@link MantissaException} to perform message lookup using the
   * provided {@code specifier} and substitution {@code parts}. It preserves the order of the
   * message arguments so that callers can rely on deterministic formatting when relaying validation
   * errors to logs or user interfaces. No state is derived from the offending matrix, keeping the
   * exception lightweight and safe to reuse across threads.
   *
   * @param specifier resource-bundle key or literal pattern describing the validation failure; must
   *     not be {@code null}.
   * @param parts ordered, non-translated arguments inserted into the format specifier at runtime;
   *     the array itself may be {@code null} when no arguments are needed.
   */
  public NotARotationMatrixException(String specifier, String[] parts) {
    super(specifier, parts);
  }

  @Serial private static final long serialVersionUID = 5647178478658937642L;
}
