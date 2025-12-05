package org.spaceroots.mantissa.geometry;

import java.io.Serial;
import org.spaceroots.mantissa.MantissaException;

/**
 * Exception thrown when Cardan or Euler angles cannot be extracted from a rotation because the
 * decomposition hits a singular configuration.
 *
 * <p>Rotation sequences that rely on three successive axis rotations become ambiguous when the
 * middle rotation reaches a gimbal-lock position. In that state, distinct sets of Cardan or Euler
 * angles map to the same orientation and the loss of one degree of freedom makes the inverse
 * transformation ill-defined. This exception signals that condition to calling code so it can fall
 * back to an alternate representation (for example, using {@link Rotation#getQ0()} quaternions) or
 * choose a different rotation order. Instances are immutable and contain only a descriptive message
 * indicating whether the failure occurred for a Cardan or an Euler sequence; no additional state is
 * retained. The class is thread-safe because it holds no mutable fields beyond the inherited
 * exception state.
 *
 * <ul>
 *   <li>Raised during {@link Rotation} angle decomposition when gimbal lock is detected.
 *   <li>Distinguishes Cardan versus Euler conventions for clearer error reporting.
 *   <li>Encourages callers to retry with a numerically stable representation.
 * </ul>
 *
 * @see Rotation
 * @see RotationOrder
 * @version $Id: CardanEulerSingularityException.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
public class CardanEulerSingularityException extends MantissaException {

  /**
   * Builds an exception with a message describing whether the failing decomposition used Cardan or
   * Euler conventions.
   *
   * <p>This constructor is typically called internally by {@link Rotation#getAngles(RotationOrder)}
   * when a gimbal-lock configuration prevents a unique set of angles from being recovered. The
   * boolean flag shapes the human-readable message so diagnostic logs can expose the rotation
   * convention that failed without leaking additional state. Callers normally catch this exception
   * to switch to a safer representation (quaternion or matrix) or to retry with a different {@link
   * RotationOrder} that avoids the singularity for their specific data set. The instance does not
   * expose mutable fields, making repeated throws safe in concurrent decompositions.
   *
   * @param isCardan true when the attempted decomposition followed a Cardan sequence; false when it
   *     followed an Euler sequence with the same middle-axis singularity risk
   */
  public CardanEulerSingularityException(boolean isCardan) {
    super(isCardan ? "Cardan angles singularity" : "Euler angles singularity");
  }

  @Serial private static final long serialVersionUID = -1360952845582206770L;
}
