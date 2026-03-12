package org.spaceroots.mantissa.geometry;

/**
 * Immutable catalog entry describing a specific Cardan or Euler rotation order.
 *
 * <p>A rotation order defines the three orthogonal axes about which successive intrinsic rotations
 * are applied when converting to or from angle triples. Instances are singletons exposed as the
 * twelve common combinations supported by {@link Rotation}. Client code passes one of these
 * predefined constants to {@link Rotation#Rotation(RotationOrder,double,double,double)} to build a
 * rotation from angles, or to {@link Rotation#getAngles(RotationOrder)} to extract angles from an
 * existing orientation.
 *
 * <p>Each instance stores immutable references to the three {@link Vector3D} axes in application
 * order, ensuring thread-safety and repeatable behavior across all callers. Typical usage selects
 * the order matching upstream conventions (for example aerospace ZYX yaw-pitch-roll or physics XYZ)
 * to avoid gimbal interpretation errors. The class performs no validation on angle magnitudes,
 * leaving range checks to higher-level code that knows the intended domain.
 *
 * <ul>
 *   <li>Responsibilities: enumerate supported orders and expose their axis triplets.
 *   <li>Mutability: fully immutable; safe for reuse across threads without synchronization.
 *   <li>Lifecycle: constants are created at class initialization and reused indefinitely.
 * </ul>
 *
 * @see Rotation
 * @see Vector3D
 * @version $Id: RotationOrder.java 1714 2006-12-13 22:37:12Z luc $
 * @author L. Maisonobe
 */
public final class RotationOrder {

  /**
   * Private constructor used by the predefined constants.
   *
   * @param name name of the rotation order, used as the external identifier; must be non-null
   * @param a1 axis of the first rotation, typically one of the canonical basis vectors
   * @param a2 axis of the second rotation, distinct from the first in Cardan sequences
   * @param a3 axis of the third rotation, matching or differing according to Euler/Cardan style
   */
  private RotationOrder(String name, Vector3D a1, Vector3D a2, Vector3D a3) {
    this.name = name;
    this.a1 = a1;
    this.a2 = a2;
    this.a3 = a3;
  }

  /**
   * Returns the symbolic name of this rotation order.
   *
   * <p>The name corresponds to the three-axis sequence (for example {@code "ZYX"}) and is stable
   * across JVM instances. This method is idempotent and safe to call from debugging, logging, or
   * serialization helpers.
   *
   * @return human-readable identifier for the order, never {@code null} and owned by this instance
   */
  @Override
  public String toString() {
    return name;
  }

  /**
   * Retrieves the axis of the first applied rotation.
   *
   * <p>This vector is one of the canonical unit axes and is shared across the singleton constants.
   * The returned object must be treated as read-only; callers should avoid modifying its state if
   * it is ever made mutable elsewhere.
   *
   * @return axis used for the initial rotation step; identical reference for repeated calls
   */
  public Vector3D getA1() {
    return a1;
  }

  /**
   * Retrieves the axis of the second applied rotation.
   *
   * <p>In Cardan orders this axis differs from the first and third; in Euler orders it matches the
   * first or third. The vector is immutable in practice and may be reused safely by multiple
   * threads without synchronization.
   *
   * @return axis used for the middle rotation step; shared singleton reference
   */
  public Vector3D getA2() {
    return a2;
  }

  /**
   * Retrieves the axis of the third applied rotation.
   *
   * <p>This final axis completes the sequence represented by the order. Callers commonly pair it
   * with {@link #getA1()} and {@link #getA2()} to feed angle triples into {@link
   * Rotation#Rotation(RotationOrder,double,double,double)} or to interpret results from {@link
   * Rotation#getAngles(RotationOrder)}.
   *
   * @return axis used for the final rotation step; reference is stable across invocations
   */
  public Vector3D getA3() {
    return a3;
  }

  /**
   * Cardan order rotating about X, then Y, then Z.
   *
   * <p>Use this when upstream conventions define yaw-pitch-roll as {@code XYZ} in a right-handed
   * frame. Each axis is applied once, avoiding repeated-axis gimbal locking seen in some Euler
   * sequences. The axes correspond to {@link Vector3D#plusI}, {@link Vector3D#plusJ}, and {@link
   * Vector3D#plusK} in that order.
   */
  public static final RotationOrder XYZ =
      new RotationOrder("XYZ", Vector3D.plusI, Vector3D.plusJ, Vector3D.plusK);

  /**
   * Cardan order rotating about X, then Z, then Y.
   *
   * <p>This sequence suits coordinate systems that treat the intermediate rotation as a roll about
   * the Z axis. Each axis is distinct, preserving non-redundant parameterization while keeping the
   * conventional right-handed orientation.
   */
  public static final RotationOrder XZY =
      new RotationOrder("XZY", Vector3D.plusI, Vector3D.plusK, Vector3D.plusJ);

  /**
   * Cardan order rotating about Y, then X, then Z.
   *
   * <p>Often used when Y represents the primary heading axis. The sequence applies distinct axes in
   * succession to maintain a non-singular parameter space except at the usual Cardan singularities.
   */
  public static final RotationOrder YXZ =
      new RotationOrder("YXZ", Vector3D.plusJ, Vector3D.plusI, Vector3D.plusK);

  /**
   * Cardan order rotating about Y, then Z, then X.
   *
   * <p>Choose this when yaw occurs first and roll concludes the sequence. It preserves the property
   * of three distinct axes to prevent redundant angle pairs in normal operating regions.
   */
  public static final RotationOrder YZX =
      new RotationOrder("YZX", Vector3D.plusJ, Vector3D.plusK, Vector3D.plusI);

  /**
   * Cardan order rotating about Z, then X, then Y.
   *
   * <p>Useful for systems where the heading axis is Z and pitch follows about X. The distinct-axis
   * sequence mirrors {@link #XYZ} with a cyclic permutation matching Z-forward conventions.
   */
  public static final RotationOrder ZXY =
      new RotationOrder("ZXY", Vector3D.plusK, Vector3D.plusI, Vector3D.plusJ);

  /**
   * Cardan order rotating about Z, then Y, then X.
   *
   * <p>This is the classic aerospace yaw-pitch-roll sequence. Angles are applied around the forward
   * (Z), lateral (Y), and longitudinal (X) axes, giving intuitive interpretation for vehicles with
   * Z-up conventions.
   */
  public static final RotationOrder ZYX =
      new RotationOrder("ZYX", Vector3D.plusK, Vector3D.plusJ, Vector3D.plusI);

  /**
   * Euler order rotating about X, then Y, then X.
   *
   * <p>The first and last rotations share the X axis, producing the classical {@code XYX} symmetric
   * Euler sequence. It is suitable when attitude must be expressed with a repeated roll axis while
   * still allowing pitch around Y as the intermediate motion.
   */
  public static final RotationOrder XYX =
      new RotationOrder("XYX", Vector3D.plusI, Vector3D.plusJ, Vector3D.plusI);

  /**
   * Euler order rotating about X, then Z, then X.
   *
   * <p>This sequence repeats X for the first and last rotations with a Z-axis yaw in between. It
   * serves use cases needing symmetry around X with an intermediate heading adjustment about Z.
   */
  public static final RotationOrder XZX =
      new RotationOrder("XZX", Vector3D.plusI, Vector3D.plusK, Vector3D.plusI);

  /**
   * Euler order rotating about Y, then X, then Y.
   *
   * <p>Use this sequence when the primary axis is Y and symmetrical end rotations around Y bracket
   * a pitch about X. It appears in mechanical linkages that pivot around a central yaw axis.
   */
  public static final RotationOrder YXY =
      new RotationOrder("YXY", Vector3D.plusJ, Vector3D.plusI, Vector3D.plusJ);

  /**
   * Euler order rotating about Y, then Z, then Y.
   *
   * <p>The sequence repeats Y for the first and last rotations, with a yaw about Z in between. It
   * offers symmetric behavior around Y and is sometimes chosen to minimize coupling with roll.
   */
  public static final RotationOrder YZY =
      new RotationOrder("YZY", Vector3D.plusJ, Vector3D.plusK, Vector3D.plusJ);

  /**
   * Euler order rotating about Z, then X, then Z.
   *
   * <p>This pattern repeats the Z axis and places the roll-like X rotation in the middle. It is
   * aligned with representations where the primary reference axis is vertical and must remain
   * prominent in the final orientation.
   */
  public static final RotationOrder ZXZ =
      new RotationOrder("ZXZ", Vector3D.plusK, Vector3D.plusI, Vector3D.plusK);

  /**
   * Euler order rotating about Z, then Y, then Z.
   *
   * <p>Reusing the Z axis for the first and last rotations, this sequence places a lateral Y motion
   * in between. It is appropriate when vertical orientation dominates the problem space and a
   * single intermediate pitch is needed.
   */
  public static final RotationOrder ZYZ =
      new RotationOrder("ZYZ", Vector3D.plusK, Vector3D.plusJ, Vector3D.plusK);

  /** Name of the rotations order. */
  private final String name;

  /** Axis of the first rotation. */
  private final Vector3D a1;

  /** Axis of the second rotation. */
  private final Vector3D a2;

  /** Axis of the third rotation. */
  private final Vector3D a3;
}
