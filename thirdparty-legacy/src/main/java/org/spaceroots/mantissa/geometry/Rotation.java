package org.spaceroots.mantissa.geometry;

import java.io.Serial;
import java.io.Serializable;

/**
 * Represents an immutable three-dimensional rotation backed by a unit quaternion.
 *
 * <p>Rotations convert coordinates between frames or reorient vectors without changing their norms.
 * Instances can be created from common mathematical forms (axis-angle, rotation matrices,
 * Cardan/Euler angles, or raw quaternion components) and the same instance can emit any of these
 * views when needed. The internal quaternion representation favors numerical stability, supports
 * inexpensive composition, and avoids gimbal singularities present in some angle systems.
 *
 * <p>Typical usage patterns include: building a rotation from sensor- or ephemeris-provided axes,
 * chaining successive rotations to model attitude changes, and applying the result to {@link
 * Vector3D vectors} or to other {@link Rotation rotations}. The class intentionally avoids
 * prescribing frame semantics; callers decide whether vectors are directions, coordinates, or basis
 * axes.
 *
 * <ul>
 *   <li>Immutability: every operation returns a new instance; thread-safe by construction.
 *   <li>Composition: {@link #applyTo(Rotation)} and {@link #applyInverseTo(Rotation)} follow
 *       mathematical function composition.
 *   <li>Interoperability: constructors and getters bridge between quaternion, matrix, and angle
 *       representations.
 * </ul>
 *
 * @version $Id: Rotation.java 1714 2006-12-13 22:37:12Z luc $
 * @author L. Maisonobe
 * @see Vector3D
 * @see RotationOrder
 */
public final class Rotation implements Serializable {

  private static final double ANGLES_SMALL = 1.0e-10;
  private static final double ANGLES_MAX_THRESHOLD = 1.0 - ANGLES_SMALL;
  private static final double ANGLES_MIN_THRESHOLD = -ANGLES_MAX_THRESHOLD;

  /**
   * Build the identity rotation (zero angle, axis undefined).
   *
   * <p>The constructed instance keeps quaternion coordinates (1, 0, 0, 0), so applying it leaves
   * any {@link Vector3D} unchanged. Because the class is immutable, this constructor is cheap and
   * side-effect free and can be reused whenever a neutral element is required in composition
   * chains.
   */
  public Rotation() {
    q0 = 1;
    q1 = 0;
    q2 = 0;
    q3 = 0;
  }

  /**
   * Create a rotation from raw quaternion components.
   *
   * <p>The supplied coordinates are normalized to a unit quaternion before storage, ensuring the
   * resulting rotation preserves vector lengths. Use this overload when upstream code provides
   * approximate quaternion components but does not guarantee unit length.
   *
   * @param q0 scalar part of the quaternion; any finite value is accepted prior to normalization
   * @param q1 first coordinate of the vectorial part, expressed in the same units as {@code q0}
   * @param q2 second coordinate of the vectorial part, expressed in the same units as {@code q0}
   * @param q3 third coordinate of the vectorial part, expressed in the same units as {@code q0}
   */
  @SuppressWarnings("unused")
  public Rotation(double q0, double q1, double q2, double q3) {
    this(q0, q1, q2, q3, true);
  }

  /**
   * Create a rotation from quaternion coordinates with optional preprocessing.
   *
   * <p>A rotation is represented by a normalized quaternion: q0<sup>2</sup> + q1<sup>2</sup> +
   * q2<sup>2</sup> + q3<sup>2</sup> = 1. When {@code needsNormalization} is {@code true}, the
   * constructor renormalizes the inputs defensively to avoid drift from rounding errors. When it is
   * {@code false}, the caller promises the inputs already form a unit quaternion and no extra work
   * is performed.
   *
   * @param q0 scalar part of the quaternion, typically the cosine of half the rotation angle
   * @param q1 first vector component aligned with the x-axis of the rotation representation
   * @param q2 second vector component aligned with the y-axis of the rotation representation
   * @param q3 third vector component aligned with the z-axis of the rotation representation
   * @param needsNormalization set to {@code true} when the components may not form a unit
   *     quaternion and should be normalized before use
   */
  public Rotation(double q0, double q1, double q2, double q3, boolean needsNormalization) {

    if (needsNormalization) {
      // normalization preprocessing
      double inv = 1.0 / Math.sqrt(q0 * q0 + q1 * q1 + q2 * q2 + q3 * q3);
      q0 *= inv;
      q1 *= inv;
      q2 *= inv;
      q3 *= inv;
    }

    this.q0 = q0;
    this.q1 = q1;
    this.q2 = q2;
    this.q3 = q3;
  }

  /**
   * Create a rotation from an axis and an angle.
   *
   * <p>The rotation follows the right-hand rule: with a direct frame (i, j, k), supplying +k as the
   * axis and {@code PI/2} as the angle maps +i onto +j when {@link #applyTo(Vector3D)} is invoked.
   * The axis does not need to be normalized beforehand; its direction is used and its norm scaled
   * away.
   *
   * @param axis axis around which to rotate; zero-length vectors are rejected
   * @param angle rotation angle in radians; positive values produce right-handed rotations
   * @throws ArithmeticException if the axis norm is zero and a direction cannot be established
   */
  public Rotation(Vector3D axis, double angle) {

    double norm = axis.getNorm();
    if (norm == 0) {
      throw new ArithmeticException("null norm");
    }

    double halfAngle = -0.5 * angle;
    double coeff = Math.sin(halfAngle) / norm;

    q0 = Math.cos(halfAngle);
    q1 = coeff * axis.getX();
    q2 = coeff * axis.getY();
    q3 = coeff * axis.getZ();
  }

  /**
   * Create a rotation from a 3x3 matrix, with optional orthogonalization.
   *
   * <p>Rotation matrices are orthogonal with determinant +1. When the provided matrix is affected
   * by truncation or measurement noise, this constructor iteratively projects a copy onto the space
   * of orthogonal matrices. If convergence fails or produces a negative determinant, an exception
   * is raised and no instance is created.
   *
   * @param m rotation matrix; must be 3x3 but need not be perfectly orthogonal on input
   * @param threshold convergence threshold for iterative orthogonality correction using the
   *     Frobenius norm of the update between steps
   * @throws NotARotationMatrixException if the matrix is not 3x3, cannot be orthogonalized within
   *     the threshold, or yields a negative determinant after correction
   */
  public Rotation(double[][] m, double threshold) throws NotARotationMatrixException {

    // dimension check
    if ((m.length != 3) || (m[0].length != 3) || (m[1].length != 3) || (m[2].length != 3)) {
      throw new NotARotationMatrixException(
          "a {0}x{1} matrix" + " cannot be a rotation matrix",
          new String[] {Integer.toString(m.length), Integer.toString(m[0].length)});
    }

    // compute a "close" orthogonal matrix
    double[][] ort = orthogonalizeMatrix(m, threshold);

    // check the sign of the determinant
    double det =
        ort[0][0] * (ort[1][1] * ort[2][2] - ort[2][1] * ort[1][2])
            - ort[1][0] * (ort[0][1] * ort[2][2] - ort[2][1] * ort[0][2])
            + ort[2][0] * (ort[0][1] * ort[1][2] - ort[1][1] * ort[0][2]);
    if (det < 0.0) {
      throw new NotARotationMatrixException(
          "the closest orthogonal matrix" + " has a negative determinant {0}",
          new String[] {Double.toString(det)});
    }

    // There are different ways to compute the quaternions elements
    // from the matrix. They all involve computing one element from
    // the diagonal of the matrix, and computing the three other ones
    // unsing a formula involving a division by the first element,
    // which unfortunately can be null. Since the norm of the
    // quaternion is 1, we know at least one element has an absolute
    // value greater or equal to 0.5, so it is always possible to
    // select the right formula and avoid division by zero and even
    // numerical inaccuracy. Checking the elements in turn and using
    // the first one greater than 0.45 is safe (this leads to a simple
    // test since qi = 0.45 implies 4 qi^2 - 1 = -0.19)
    double s = ort[0][0] + ort[1][1] + ort[2][2];
    if (s > -0.19) {
      // compute q0 and deduce q1, q2 and q3
      q0 = 0.5 * Math.sqrt(s + 1.0);
      double inv = 0.25 / q0;
      q1 = inv * (ort[1][2] - ort[2][1]);
      q2 = inv * (ort[2][0] - ort[0][2]);
      q3 = inv * (ort[0][1] - ort[1][0]);
    } else {
      s = ort[0][0] - ort[1][1] - ort[2][2];
      if (s > -0.19) {
        // compute q1 and deduce q0, q2 and q3
        q1 = 0.5 * Math.sqrt(s + 1.0);
        double inv = 0.25 / q1;
        q0 = inv * (ort[1][2] - ort[2][1]);
        q2 = inv * (ort[0][1] + ort[1][0]);
        q3 = inv * (ort[0][2] + ort[2][0]);
      } else {
        s = ort[1][1] - ort[0][0] - ort[2][2];
        if (s > -0.19) {
          // compute q2 and deduce q0, q1 and q3
          q2 = 0.5 * Math.sqrt(s + 1.0);
          double inv = 0.25 / q2;
          q0 = inv * (ort[2][0] - ort[0][2]);
          q1 = inv * (ort[0][1] + ort[1][0]);
          q3 = inv * (ort[2][1] + ort[1][2]);
        } else {
          // compute q3 and deduce q0, q1 and q2
          s = ort[2][2] - ort[0][0] - ort[1][1];
          q3 = 0.5 * Math.sqrt(s + 1.0);
          double inv = 0.25 / q3;
          q0 = inv * (ort[0][1] - ort[1][0]);
          q1 = inv * (ort[0][2] + ort[2][0]);
          q2 = inv * (ort[2][1] + ort[1][2]);
        }
      }
    }
  }

  /**
   * Build the rotation that transforms a pair of vector into another pair.
   *
   * <p>Applying the resulting instance to the pair (u1, u2) produces the pair (v1, v2) up to scale
   * factors. If the angular separation of the source vectors differs from that of the target
   * vectors, the constructor computes an adjusted v2′ that lies in the (v1, v2) plane while
   * preserving the original inner products. This makes it suitable for frame alignment where input
   * data may be noisy but a smooth best-fit rotation is desired.
   *
   * @param u1 first vector of the origin pair; must have non-zero norm for orientation to be valid
   * @param u2 second vector of the origin pair; independent from {@code u1} to define a plane
   * @param v1 desired image of {@code u1} after rotation, rescaled internally to match its norm
   * @param v2 desired image of {@code u2}; may be adjusted in-plane to equalize angular separations
   */
  public Rotation(Vector3D u1, Vector3D u2, Vector3D v1, Vector3D v2) {

    // norms computation
    double u1u1 = Vector3D.dotProduct(u1, u1);
    double u2u2 = Vector3D.dotProduct(u2, u2);
    double v1v1 = Vector3D.dotProduct(v1, v1);
    double v2v2 = Vector3D.dotProduct(v2, v2);
    if ((u1u1 < 1.0e-15) || (u2u2 < 1.0e-15) || (v1v1 < 1.0e-15) || (v2v2 < 1.0e-15))
      throw new ArithmeticException("null norm");

    double u1x = u1.getX();
    double u1y = u1.getY();
    double u1z = u1.getZ();

    double u2x = u2.getX();
    double u2y = u2.getY();
    double u2z = u2.getZ();

    // renormalize v1 in order to have (v1'|v1') = (u1|u1)
    double coeff = Math.sqrt(u1u1 / v1v1);
    double v1x = coeff * v1.getX();
    double v1y = coeff * v1.getY();
    double v1z = coeff * v1.getZ();
    v1 = new Vector3D(v1x, v1y, v1z);

    // adjust v2 in order to have (u1|u2) = (v1|v2) and (v2'|v2') = (u2|u2)
    double u1u2 = Vector3D.dotProduct(u1, u2);
    double v1v2 = Vector3D.dotProduct(v1, v2);
    double coeffU = u1u2 / u1u1;
    double coeffV = v1v2 / u1u1;
    double beta = Math.sqrt((u2u2 - u1u2 * coeffU) / (v2v2 - v1v2 * coeffV));
    double alpha = coeffU - beta * coeffV;
    double v2x = alpha * v1x + beta * v2.getX();
    double v2y = alpha * v1y + beta * v2.getY();
    double v2z = alpha * v1z + beta * v2.getZ();
    v2 = new Vector3D(v2x, v2y, v2z);

    // preliminary computation (we use explicit formulation instead
    // of relying on the Vector3D class in order to avoid building lots
    // of temporary objects)
    Vector3D uRef = u1;
    Vector3D vRef = v1;
    double dx1 = v1x - u1.getX();
    double dy1 = v1y - u1.getY();
    double dz1 = v1z - u1.getZ();
    double dx2 = v2x - u2.getX();
    double dy2 = v2y - u2.getY();
    double dz2 = v2z - u2.getZ();
    Vector3D k = new Vector3D(dy1 * dz2 - dz1 * dy2, dz1 * dx2 - dx1 * dz2, dx1 * dy2 - dy1 * dx2);
    double c =
        k.getX() * (u1y * u2z - u1z * u2y)
            + k.getY() * (u1z * u2x - u1x * u2z)
            + k.getZ() * (u1x * u2y - u1y * u2x);

    if (c < (1.0e-10 * u1u1 * u2u2)) {
      // the (q1, q2, q3) vector is in the (u1, u2) plane
      // we try other vectors
      Vector3D u3 = Vector3D.crossProduct(u1, u2);
      Vector3D v3 = Vector3D.crossProduct(v1, v2);
      double u3x = u3.getX();
      double u3y = u3.getY();
      double u3z = u3.getZ();
      double v3x = v3.getX();
      double v3y = v3.getY();
      double v3z = v3.getZ();
      double u3u3 = u1u1 * u2u2 - u1u2 * u1u2;

      double dx3 = v3x - u3x;
      double dy3 = v3y - u3y;
      double dz3 = v3z - u3z;
      k = new Vector3D(dy1 * dz3 - dz1 * dy3, dz1 * dx3 - dx1 * dz3, dx1 * dy3 - dy1 * dx3);
      c =
          k.getX() * (u1y * u3z - u1z * u3y)
              + k.getY() * (u1z * u3x - u1x * u3z)
              + k.getZ() * (u1x * u3y - u1y * u3x);

      if (c < (1.0e-10 * u1u1 * u3u3)) {
        // the (q1, q2, q3) vector is aligned with u1:
        // we try (u2, u3) and (v2, v3)
        k = new Vector3D(dy2 * dz3 - dz2 * dy3, dz2 * dx3 - dx2 * dz3, dx2 * dy3 - dy2 * dx3);
        c =
            k.getX() * (u2y * u3z - u2z * u3y)
                + k.getY() * (u2z * u3x - u2x * u3z)
                + k.getZ() * (u2x * u3y - u2y * u3x);

        if (c < (1.0e-10 * u2u2 * u3u3)) {
          // the (q1, q2, q3) vector is aligned with everything
          // this is really the identity rotation
          q0 = 1.0;
          q1 = 0.0;
          q2 = 0.0;
          q3 = 0.0;
          return;
        }

        // we will have to use u2 and v2 to compute the scalar part
        uRef = u2;
        vRef = v2;
      }
    }

    // compute the vectorial part
    c = Math.sqrt(c);
    double inv = 1.0 / (c + c);
    q1 = inv * k.getX();
    q2 = inv * k.getY();
    q3 = inv * k.getZ();

    // compute the scalar part
    k =
        new Vector3D(
            uRef.getY() * q3 - uRef.getZ() * q2,
            uRef.getZ() * q1 - uRef.getX() * q3,
            uRef.getX() * q2 - uRef.getY() * q1);
    c = Vector3D.dotProduct(k, k);
    q0 = Vector3D.dotProduct(vRef, k) / (c + c);
  }

  /**
   * Build one of the rotations that transform one vector into another one.
   *
   * <p>Except for a possible scale factor, applying the rotation to {@code u} yields {@code v}.
   * Among the infinitely many solutions, this constructor selects the rotation with the smallest
   * angle, whose axis is orthogonal to the ({@code u}, {@code v}) plane. If the vectors are
   * colinear, it falls back to a half-turn around an arbitrary orthogonal axis.
   *
   * @param u origin vector; must have non-zero norm to define an input direction
   * @param v desired image of {@code u}; must have non-zero norm to define an output direction
   * @throws ArithmeticException if either vector has zero norm and a direction cannot be derived
   */
  public Rotation(Vector3D u, Vector3D v) {

    double normProduct = u.getNorm() * v.getNorm();
    if (normProduct < 1.0e-15) {
      throw new ArithmeticException("null norm");
    }

    double dot = Vector3D.dotProduct(u, v);

    if (dot < ((2.0e-15 - 1.0) * normProduct)) {
      // special case u = -v: we select a PI angle rotation around
      // an arbitrary vector orthogonal to u
      Vector3D w = u.orthogonal();
      q0 = 0.0;
      q1 = -w.getX();
      q2 = -w.getY();
      q3 = -w.getZ();
    } else {
      // general case: (u, v) defines a plane, we select
      // the shortest possible rotation: axis orthogonal to this plane
      q0 = Math.sqrt(0.5 * (1.0 + dot / normProduct));
      double coeff = 1.0 / (2.0 * q0 * normProduct);
      q1 = coeff * (v.getY() * u.getZ() - v.getZ() * u.getY());
      q2 = coeff * (v.getZ() * u.getX() - v.getX() * u.getZ());
      q3 = coeff * (v.getX() * u.getY() - v.getY() * u.getX());
    }
  }

  /**
   * Build a rotation from three Cardan or Euler elementary rotations.
   *
   * <p>Cardan rotations use each canonical axis (X, Y, Z) once; Euler rotations repeat the first
   * axis on the third step. Both families offer six valid orders. This constructor applies the
   * supplied elementary rotations in the chosen order and composes the result into a single
   * quaternion-based rotation.
   *
   * @param order order of elementary rotations; must match one of the supported {@link
   *     RotationOrder} constants
   * @param alpha1 angle of the first elementary rotation in radians; positive uses right-hand rule
   * @param alpha2 angle of the second elementary rotation in radians; may encounter singularities
   *     depending on {@code order}
   * @param alpha3 angle of the third elementary rotation in radians; direction follows {@code
   *     order}
   */
  public Rotation(RotationOrder order, double alpha1, double alpha2, double alpha3) {
    Rotation r1 = new Rotation(order.getA1(), alpha1);
    Rotation r2 = new Rotation(order.getA2(), alpha2);
    Rotation r3 = new Rotation(order.getA3(), alpha3);
    Rotation composed = r1.applyTo(r2.applyTo(r3));
    q0 = composed.q0;
    q1 = composed.q1;
    q2 = composed.q2;
    q3 = composed.q3;
  }

  /**
   * Return a rotation that reverses the effect of this instance.
   *
   * <p>If {@code r(u) = v}, then {@code r.revert().applyTo(v)} yields {@code u}. The current
   * instance remains unchanged; the returned rotation is its mathematical inverse and can be used
   * safely in composition chains.
   *
   * @return a new rotation that is the exact inverse of this rotation while leaving this instance
   *     untouched
   */
  public Rotation revert() {
    return new Rotation(-q0, q1, q2, q3, false);
  }

  /**
   * Get the scalar (real) coordinate of the underlying unit quaternion.
   *
   * @return scalar component {@code q0}; value remains in [-1, 1] for normalized rotations
   */
  public double getQ0() {
    return q0;
  }

  /**
   * Get the first coordinate of the quaternion vector part.
   *
   * @return component {@code q1}, representing the x-axis contribution to the rotation vector
   */
  public double getQ1() {
    return q1;
  }

  /**
   * Get the second coordinate of the quaternion vector part.
   *
   * @return component {@code q2}, representing the y-axis contribution to the rotation vector
   */
  public double getQ2() {
    return q2;
  }

  /**
   * Get the third coordinate of the quaternion vector part.
   *
   * @return component {@code q3}, representing the z-axis contribution to the rotation vector
   */
  public double getQ3() {
    return q3;
  }

  /**
   * Get the normalized axis of the rotation.
   *
   * <p>For angles near zero, the direction defaults to the positive x-axis because all axes are
   * equivalent in that limit. For non-zero angles, the axis is oriented so that {@link #getAngle()}
   * remains within [0, {@code PI}] while respecting the quaternion sign convention.
   *
   * @return unit {@link Vector3D} pointing along the rotation axis; may default to +X for tiny
   *     angles
   */
  public Vector3D getAxis() {
    double squaredSine = q1 * q1 + q2 * q2 + q3 * q3;
    if (squaredSine < 1.0e-12) {
      return new Vector3D(1, 0, 0);
    } else if (q0 < 0) {
      double inverse = 1 / Math.sqrt(squaredSine);
      return new Vector3D(q1 * inverse, q2 * inverse, q3 * inverse);
    } else {
      double inverse = -1 / Math.sqrt(squaredSine);
      return new Vector3D(q1 * inverse, q2 * inverse, q3 * inverse);
    }
  }

  /**
   * Get the unsigned rotation angle in radians.
   *
   * <p>The value is always between 0 and {@code PI}. For very small angles, the implementation
   * selects numerically stable formulations to avoid loss of precision caused by limited floating
   * point resolution.
   *
   * @return rotation angle in radians, constrained to the principal interval [0, {@code PI}]
   */
  public double getAngle() {
    if ((q0 < -0.1) || (q0 > 0.1)) {
      return 2 * Math.asin(Math.sqrt(q1 * q1 + q2 * q2 + q3 * q3));
    } else if (q0 < 0) {
      return 2 * Math.acos(-q0);
    } else {
      return 2 * Math.acos(q0);
    }
  }

  /**
   * Get the Cardan or Euler angles corresponding to the instance.
   *
   * <p>Every rotation maps to two equivalent angle triplets; this method chooses the convention
   * where the middle angle has a positive cosine for Cardan orders and a positive sine for Euler
   * orders. The output is therefore unique and stable except near the representation’s intrinsic
   * singularities.
   *
   * <p>Cardan and Euler decompositions suffer from gimbal lock: when the second angle approaches
   * ±{@code PI/2} for Cardan or 0/ {@code PI} for Euler, the mapping is not invertible and the
   * method raises an exception rather than returning unreliable values.
   *
   * @param order rotation order to use; determines axis sequence and singularity locations
   * @return array of three angles in radians, ordered according to {@code order}, representing this
   *     rotation under the selected convention
   * @throws CardanEulerSingularityException if the rotation lies within the singular zone of the
   *     requested order and the angles would be undefined
   */
  public double[] getAngles(RotationOrder order) throws CardanEulerSingularityException {

    if (order == RotationOrder.XYZ) {
      return getAnglesXYZ();
    }
    if (order == RotationOrder.XZY) {
      return getAnglesXZY();
    }
    if (order == RotationOrder.YXZ) {
      return getAnglesYXZ();
    }
    if (order == RotationOrder.YZX) {
      return getAnglesYZX();
    }
    if (order == RotationOrder.ZXY) {
      return getAnglesZXY();
    }
    if (order == RotationOrder.ZYX) {
      return getAnglesZYX();
    }
    if (order == RotationOrder.XYX) {
      return getAnglesXYX();
    }
    if (order == RotationOrder.XZX) {
      return getAnglesXZX();
    }
    if (order == RotationOrder.YXY) {
      return getAnglesYXY();
    }
    if (order == RotationOrder.YZY) {
      return getAnglesYZY();
    }
    if (order == RotationOrder.ZXZ) {
      return getAnglesZXZ();
    }
    if (order == RotationOrder.ZYZ) {
      return getAnglesZYZ();
    }
    throw new IllegalStateException("Unknown rotation order: " + order);
  }

  private double[] getAnglesXYZ() throws CardanEulerSingularityException {

    // r (Vector3D.plusK) coordinates are :
    //  sin (theta), -cos (theta) sin (phi), cos (theta) cos (phi)
    // (-r) (Vector3D.plusI) coordinates are :
    // cos (psi) cos (theta), -sin (psi) cos (theta), sin (theta)
    // and we can choose to have theta in the interval [-PI/2 ; +PI/2]
    Vector3D v1 = applyTo(Vector3D.plusK);
    Vector3D v2 = applyInverseTo(Vector3D.plusI);
    checkAngleBounds(v2.getZ(), true);
    return new double[] {
      Math.atan2(-v1.getY(), v1.getZ()), Math.asin(v2.getZ()), Math.atan2(-v2.getY(), v2.getX())
    };
  }

  private double[] getAnglesXZY() throws CardanEulerSingularityException {

    // r (Vector3D.plusJ) coordinates are :
    // -sin (psi), cos (psi) cos (phi), cos (psi) sin (phi)
    // (-r) (Vector3D.plusI) coordinates are :
    // cos (theta) cos (psi), -sin (psi), sin (theta) cos (psi)
    // and we can choose to have psi in the interval [-PI/2 ; +PI/2]
    Vector3D v1 = applyTo(Vector3D.plusJ);
    Vector3D v2 = applyInverseTo(Vector3D.plusI);
    checkAngleBounds(v2.getY(), true);
    return new double[] {
      Math.atan2(v1.getZ(), v1.getY()), -Math.asin(v2.getY()), Math.atan2(v2.getZ(), v2.getX())
    };
  }

  private double[] getAnglesYXZ() throws CardanEulerSingularityException {

    // r (Vector3D.plusK) coordinates are :
    //  cos (phi) sin (theta), -sin (phi), cos (phi) cos (theta)
    // (-r) (Vector3D.plusJ) coordinates are :
    // sin (psi) cos (phi), cos (psi) cos (phi), -sin (phi)
    // and we can choose to have phi in the interval [-PI/2 ; +PI/2]
    Vector3D v1 = applyTo(Vector3D.plusK);
    Vector3D v2 = applyInverseTo(Vector3D.plusJ);
    checkAngleBounds(v2.getZ(), true);
    return new double[] {
      Math.atan2(v1.getX(), v1.getZ()), -Math.asin(v2.getZ()), Math.atan2(v2.getX(), v2.getY())
    };
  }

  private double[] getAnglesYZX() throws CardanEulerSingularityException {

    // r (Vector3D.plusI) coordinates are :
    // cos (psi) cos (theta), sin (psi), -cos (psi) sin (theta)
    // (-r) (Vector3D.plusJ) coordinates are :
    // sin (psi), cos (phi) cos (psi), -sin (phi) cos (psi)
    // and we can choose to have psi in the interval [-PI/2 ; +PI/2]
    Vector3D v1 = applyTo(Vector3D.plusI);
    Vector3D v2 = applyInverseTo(Vector3D.plusJ);
    checkAngleBounds(v2.getX(), true);
    return new double[] {
      Math.atan2(-v1.getZ(), v1.getX()), Math.asin(v2.getX()), Math.atan2(-v2.getZ(), v2.getY())
    };
  }

  private double[] getAnglesZXY() throws CardanEulerSingularityException {

    // r (Vector3D.plusJ) coordinates are :
    // -cos (phi) sin (psi), cos (phi) cos (psi), sin (phi)
    // (-r) (Vector3D.plusK) coordinates are :
    // -sin (theta) cos (phi), sin (phi), cos (theta) cos (phi)
    // and we can choose to have phi in the interval [-PI/2 ; +PI/2]
    Vector3D v1 = applyTo(Vector3D.plusJ);
    Vector3D v2 = applyInverseTo(Vector3D.plusK);
    checkAngleBounds(v2.getY(), true);
    return new double[] {
      Math.atan2(-v1.getX(), v1.getY()), Math.asin(v2.getY()), Math.atan2(-v2.getX(), v2.getZ())
    };
  }

  private double[] getAnglesZYX() throws CardanEulerSingularityException {

    // r (Vector3D.plusI) coordinates are :
    //  cos (theta) cos (psi), cos (theta) sin (psi), -sin (theta)
    // (-r) (Vector3D.plusK) coordinates are :
    // -sin (theta), sin (phi) cos (theta), cos (phi) cos (theta)
    // and we can choose to have theta in the interval [-PI/2 ; +PI/2]
    Vector3D v1 = applyTo(Vector3D.plusI);
    Vector3D v2 = applyInverseTo(Vector3D.plusK);
    checkAngleBounds(v2.getX(), true);
    return new double[] {
      Math.atan2(v1.getY(), v1.getX()), -Math.asin(v2.getX()), Math.atan2(v2.getY(), v2.getZ())
    };
  }

  private double[] getAnglesXYX() throws CardanEulerSingularityException {

    // r (Vector3D.plusI) coordinates are :
    //  cos (theta), sin (phi1) sin (theta), -cos (phi1) sin (theta)
    // (-r) (Vector3D.plusI) coordinates are :
    // cos (theta), sin (theta) sin (phi2), sin (theta) cos (phi2)
    // and we can choose to have theta in the interval [0 ; PI]
    Vector3D v1 = applyTo(Vector3D.plusI);
    Vector3D v2 = applyInverseTo(Vector3D.plusI);
    checkAngleBounds(v2.getX(), false);
    return new double[] {
      Math.atan2(v1.getY(), -v1.getZ()), Math.acos(v2.getX()), Math.atan2(v2.getY(), v2.getZ())
    };
  }

  private double[] getAnglesXZX() throws CardanEulerSingularityException {

    // r (Vector3D.plusI) coordinates are :
    //  cos (psi), cos (phi1) sin (psi), sin (phi1) sin (psi)
    // (-r) (Vector3D.plusI) coordinates are :
    // cos (psi), -sin (psi) cos (phi2), sin (psi) sin (phi2)
    // and we can choose to have psi in the interval [0 ; PI]
    Vector3D v1 = applyTo(Vector3D.plusI);
    Vector3D v2 = applyInverseTo(Vector3D.plusI);
    checkAngleBounds(v2.getX(), false);
    return new double[] {
      Math.atan2(v1.getZ(), v1.getY()), Math.acos(v2.getX()), Math.atan2(v2.getZ(), -v2.getY())
    };
  }

  private double[] getAnglesYXY() throws CardanEulerSingularityException {

    // r (Vector3D.plusJ) coordinates are :
    //  sin (theta1) sin (phi), cos (phi), cos (theta1) sin (phi)
    // (-r) (Vector3D.plusJ) coordinates are :
    // sin (phi) sin (theta2), cos (phi), -sin (phi) cos (theta2)
    // and we can choose to have phi in the interval [0 ; PI]
    Vector3D v1 = applyTo(Vector3D.plusJ);
    Vector3D v2 = applyInverseTo(Vector3D.plusJ);
    checkAngleBounds(v2.getY(), false);
    return new double[] {
      Math.atan2(v1.getX(), v1.getZ()), Math.acos(v2.getY()), Math.atan2(v2.getX(), -v2.getZ())
    };
  }

  private double[] getAnglesYZY() throws CardanEulerSingularityException {

    // r (Vector3D.plusJ) coordinates are :
    //  -cos (theta1) sin (psi), cos (psi), sin (theta1) sin (psi)
    // (-r) (Vector3D.plusJ) coordinates are :
    // sin (psi) cos (theta2), cos (psi), sin (psi) sin (theta2)
    // and we can choose to have psi in the interval [0 ; PI]
    Vector3D v1 = applyTo(Vector3D.plusJ);
    Vector3D v2 = applyInverseTo(Vector3D.plusJ);
    checkAngleBounds(v2.getY(), false);
    return new double[] {
      Math.atan2(v1.getZ(), -v1.getX()), Math.acos(v2.getY()), Math.atan2(v2.getZ(), v2.getX())
    };
  }

  private double[] getAnglesZXZ() throws CardanEulerSingularityException {

    // r (Vector3D.plusK) coordinates are :
    //  sin (psi1) sin (phi), -cos (psi1) sin (phi), cos (phi)
    // (-r) (Vector3D.plusK) coordinates are :
    // sin (phi) sin (psi2), sin (phi) cos (psi2), cos (phi)
    // and we can choose to have phi in the interval [0 ; PI]
    Vector3D v1 = applyTo(Vector3D.plusK);
    Vector3D v2 = applyInverseTo(Vector3D.plusK);
    checkAngleBounds(v2.getZ(), false);
    return new double[] {
      Math.atan2(v1.getX(), -v1.getY()), Math.acos(v2.getZ()), Math.atan2(v2.getX(), v2.getY())
    };
  }

  private double[] getAnglesZYZ() throws CardanEulerSingularityException {

    // r (Vector3D.plusK) coordinates are :
    //  cos (psi1) sin (theta), sin (psi1) sin (theta), cos (theta)
    // (-r) (Vector3D.plusK) coordinates are :
    // -sin (theta) cos (psi2), sin (theta) sin (psi2), cos (theta)
    // and we can choose to have theta in the interval [0 ; PI]
    Vector3D v1 = applyTo(Vector3D.plusK);
    Vector3D v2 = applyInverseTo(Vector3D.plusK);
    checkAngleBounds(v2.getZ(), false);
    return new double[] {
      Math.atan2(v1.getY(), v1.getX()), Math.acos(v2.getZ()), Math.atan2(v2.getY(), -v2.getX())
    };
  }

  private void checkAngleBounds(double value, boolean isCardan)
      throws CardanEulerSingularityException {
    if ((value < ANGLES_MIN_THRESHOLD) || (value > ANGLES_MAX_THRESHOLD)) {
      throw new CardanEulerSingularityException(isCardan);
    }
  }

  /**
   * Get the 3x3 matrix corresponding to this rotation.
   *
   * <p>The returned matrix is guaranteed to be orthogonal with determinant +1, consistent with the
   * quaternion stored in this instance. A fresh array is created on each call so callers can modify
   * the matrix safely without affecting the rotation.
   *
   * @return new 3x3 double array representing the rotation in row-major order
   */
  public double[][] getMatrix() {

    // products
    double q0q0 = q0 * q0;
    double q0q1 = q0 * q1;
    double q0q2 = q0 * q2;
    double q0q3 = q0 * q3;
    double q1q1 = q1 * q1;
    double q1q2 = q1 * q2;
    double q1q3 = q1 * q3;
    double q2q2 = q2 * q2;
    double q2q3 = q2 * q3;
    double q3q3 = q3 * q3;

    // create the matrix
    double[][] m = new double[3][];
    m[0] = new double[3];
    m[1] = new double[3];
    m[2] = new double[3];

    m[0][0] = 2.0 * (q0q0 + q1q1) - 1.0;
    m[1][0] = 2.0 * (q1q2 - q0q3);
    m[2][0] = 2.0 * (q1q3 + q0q2);

    m[0][1] = 2.0 * (q1q2 + q0q3);
    m[1][1] = 2.0 * (q0q0 + q2q2) - 1.0;
    m[2][1] = 2.0 * (q2q3 - q0q1);

    m[0][2] = 2.0 * (q1q3 - q0q2);
    m[1][2] = 2.0 * (q2q3 + q0q1);
    m[2][2] = 2.0 * (q0q0 + q3q3) - 1.0;

    return m;
  }

  /**
   * Apply the rotation to a vector.
   *
   * <p>The input vector is not modified; a new {@link Vector3D} containing the rotated coordinates
   * is returned. The operation preserves norms and is equivalent to multiplying by the 3x3 rotation
   * matrix that {@link #getMatrix()} would produce.
   *
   * @param u vector to apply the rotation to; accepted even if not normalized, but must be finite
   * @return a new vector equal to {@code u} expressed in the rotated frame defined by this instance
   */
  public Vector3D applyTo(Vector3D u) {

    double x = u.getX();
    double y = u.getY();
    double z = u.getZ();

    double s = q1 * x + q2 * y + q3 * z;

    return new Vector3D(
        2 * (q0 * (x * q0 - (q2 * z - q3 * y)) + s * q1) - x,
        2 * (q0 * (y * q0 - (q3 * x - q1 * z)) + s * q2) - y,
        2 * (q0 * (z * q0 - (q1 * y - q2 * x)) + s * q3) - z);
  }

  /**
   * Apply the inverse of the rotation to a vector.
   *
   * <p>This is equivalent to applying {@link #revert()} then {@link #applyTo(Vector3D)}, but avoids
   * creating an intermediate rotation. Use it when you need to express a vector from the rotated
   * frame back into the original frame.
   *
   * @param u vector to transform by the inverse rotation; components must be finite
   * @return a new vector that, when this rotation is applied, yields the original {@code u}
   */
  public Vector3D applyInverseTo(Vector3D u) {

    double x = u.getX();
    double y = u.getY();
    double z = u.getZ();

    double s = q1 * x + q2 * y + q3 * z;
    double m0 = -q0;

    return new Vector3D(
        2 * (m0 * (x * m0 - (q2 * z - q3 * y)) + s * q1) - x,
        2 * (m0 * (y * m0 - (q3 * x - q1 * z)) + s * q2) - y,
        2 * (m0 * (z * m0 - (q1 * y - q2 * x)) + s * q3) - z);
  }

  /**
   * Apply this rotation to another rotation.
   *
   * <p>The result follows function composition: if {@code v = r.applyTo(u)} and {@code w =
   * applyTo(v)}, then {@code w} also equals {@code comp.applyTo(u)} where {@code comp} is the
   * rotation returned by this method. This is the standard way to chain two rotations while
   * preserving numerical stability.
   *
   * @param r rotation to be applied first in the composition; treated as immutable input
   * @return a new rotation equivalent to {@code this ∘ r} (apply {@code r}, then this rotation)
   */
  public Rotation applyTo(Rotation r) {
    return new Rotation(
        r.q0 * q0 - (r.q1 * q1 + r.q2 * q2 + r.q3 * q3),
        r.q1 * q0 + r.q0 * q1 + (r.q2 * q3 - r.q3 * q2),
        r.q2 * q0 + r.q0 * q2 + (r.q3 * q1 - r.q1 * q3),
        r.q3 * q0 + r.q0 * q3 + (r.q1 * q2 - r.q2 * q1),
        false);
  }

  /**
   * Apply the inverse of this rotation to another rotation.
   *
   * <p>The returned rotation satisfies {@code applyInverseTo(r).applyTo(u) = applyInverseTo(r
   * applyTo(u))} for any vector {@code u}. Use it to undo a rotation in a composition chain without
   * explicitly creating the inverse rotation instance.
   *
   * @param r rotation to be adjusted by the inverse of this rotation; remains unchanged itself
   * @return a new rotation equivalent to {@code this^{-1} ∘ r} (apply {@code r}, then undo {@code
   *     this})
   */
  @SuppressWarnings("unused")
  public Rotation applyInverseTo(Rotation r) {
    return new Rotation(
        -r.q0 * q0 - (r.q1 * q1 + r.q2 * q2 + r.q3 * q3),
        -r.q1 * q0 + r.q0 * q1 + (r.q2 * q3 - r.q3 * q2),
        -r.q2 * q0 + r.q0 * q2 + (r.q3 * q1 - r.q1 * q3),
        -r.q3 * q0 + r.q0 * q3 + (r.q1 * q2 - r.q2 * q1),
        false);
  }

  /**
   * Perfect orthogonality on a 3X3 matrix.
   *
   * @param m initial matrix (not exactly orthogonal)
   * @param threshold convergence threshold for the iterative orthogonality correction (convergence
   *     is reached when the difference between two steps of the Frobenius norm of the correction is
   *     below this threshold)
   * @return an orthogonal matrix close to m
   * @exception NotARotationMatrixException if the matrix cannot be orthogonalized with the given
   *     threshold after 10 iterations
   */
  private double[][] orthogonalizeMatrix(double[][] m, double threshold)
      throws NotARotationMatrixException {
    double x00 = m[0][0];
    double x01 = m[0][1];
    double x02 = m[0][2];
    double x10 = m[1][0];
    double x11 = m[1][1];
    double x12 = m[1][2];
    double x20 = m[2][0];
    double x21 = m[2][1];
    double x22 = m[2][2];
    double fn = 0;
    double fn1;

    double[][] o = new double[3][];
    o[0] = new double[3];
    o[1] = new double[3];
    o[2] = new double[3];

    // iterative correction: Xn+1 = Xn - 0.5 * (Xn.Mt.Xn - M)
    int i = 0;
    while (++i < 11) {

      // Mt.Xn
      double mx00 = m[0][0] * x00 + m[1][0] * x10 + m[2][0] * x20;
      double mx10 = m[0][1] * x00 + m[1][1] * x10 + m[2][1] * x20;
      double mx20 = m[0][2] * x00 + m[1][2] * x10 + m[2][2] * x20;
      double mx01 = m[0][0] * x01 + m[1][0] * x11 + m[2][0] * x21;
      double mx11 = m[0][1] * x01 + m[1][1] * x11 + m[2][1] * x21;
      double mx21 = m[0][2] * x01 + m[1][2] * x11 + m[2][2] * x21;
      double mx02 = m[0][0] * x02 + m[1][0] * x12 + m[2][0] * x22;
      double mx12 = m[0][1] * x02 + m[1][1] * x12 + m[2][1] * x22;
      double mx22 = m[0][2] * x02 + m[1][2] * x12 + m[2][2] * x22;

      // Xn+1
      o[0][0] = x00 - 0.5 * (x00 * mx00 + x01 * mx10 + x02 * mx20 - m[0][0]);
      o[0][1] = x01 - 0.5 * (x00 * mx01 + x01 * mx11 + x02 * mx21 - m[0][1]);
      o[0][2] = x02 - 0.5 * (x00 * mx02 + x01 * mx12 + x02 * mx22 - m[0][2]);
      o[1][0] = x10 - 0.5 * (x10 * mx00 + x11 * mx10 + x12 * mx20 - m[1][0]);
      o[1][1] = x11 - 0.5 * (x10 * mx01 + x11 * mx11 + x12 * mx21 - m[1][1]);
      o[1][2] = x12 - 0.5 * (x10 * mx02 + x11 * mx12 + x12 * mx22 - m[1][2]);
      o[2][0] = x20 - 0.5 * (x20 * mx00 + x21 * mx10 + x22 * mx20 - m[2][0]);
      o[2][1] = x21 - 0.5 * (x20 * mx01 + x21 * mx11 + x22 * mx21 - m[2][1]);
      o[2][2] = x22 - 0.5 * (x20 * mx02 + x21 * mx12 + x22 * mx22 - m[2][2]);

      // correction on each element
      double corr00 = o[0][0] - m[0][0];
      double corr01 = o[0][1] - m[0][1];
      double corr02 = o[0][2] - m[0][2];
      double corr10 = o[1][0] - m[1][0];
      double corr11 = o[1][1] - m[1][1];
      double corr12 = o[1][2] - m[1][2];
      double corr20 = o[2][0] - m[2][0];
      double corr21 = o[2][1] - m[2][1];
      double corr22 = o[2][2] - m[2][2];

      // Frobenius norm of the correction
      fn1 =
          corr00 * corr00
              + corr01 * corr01
              + corr02 * corr02
              + corr10 * corr10
              + corr11 * corr11
              + corr12 * corr12
              + corr20 * corr20
              + corr21 * corr21
              + corr22 * corr22;

      // convergence test
      if (Math.abs(fn1 - fn) <= threshold) return o;

      // prepare next iteration
      x00 = o[0][0];
      x01 = o[0][1];
      x02 = o[0][2];
      x10 = o[1][0];
      x11 = o[1][1];
      x12 = o[1][2];
      x20 = o[2][0];
      x21 = o[2][1];
      x22 = o[2][2];
      fn = fn1;
    }

    // the algorithm did not converge after 10 iterations
    throw new NotARotationMatrixException(
        "unable to orthogonalize matrix" + " in {0} iterations",
        new String[] {Integer.toString(i - 1)});
  }

  /** Scalar coordinate of the quaternion. */
  private final double q0;

  /** First coordinate of the vectorial part of the quaternion. */
  private final double q1;

  /** Second coordinate of the vectorial part of the quaternion. */
  private final double q2;

  /** Third coordinate of the vectorial part of the quaternion. */
  private final double q3;

  @Serial private static final long serialVersionUID = -2112458726544145775L;
}
