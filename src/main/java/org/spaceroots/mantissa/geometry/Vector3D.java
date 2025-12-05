package org.spaceroots.mantissa.geometry;

import java.io.Serial;
import java.io.Serializable;

/**
 * Represents an immutable vector in three-dimensional Euclidean space.
 *
 * <p>This class stores a vector by its Cartesian coordinates and exposes helper constructors to
 * build vectors from azimuth/elevation angles or from linear combinations of other vectors. All
 * instances are immutable: every operation such as addition, scaling, or normalization returns a
 * new {@code Vector3D} without modifying the source operands. This makes the class inherently
 * thread-safe and well suited for sharing between computations or caching as constants.
 *
 * <p>Typical usage patterns include building basis vectors, translating between spherical and
 * Cartesian coordinates, computing angles and projections, and generating orthogonal reference
 * frames for geometric algorithms. Consumers should prefer reusing the provided canonical vectors
 * when possible to avoid redundant allocations.
 *
 * <p><strong>Notable behaviors:</strong>
 *
 * <ul>
 *   <li>All accessors and operations avoid side effects; null norms trigger {@link
 *       ArithmeticException} when normalization or angular separation is undefined.
 *   <li>Methods that combine vectors attempt to preserve numerical stability by selecting formulas
 *       appropriate to the input orientation.
 *   <li>Serialization is supported via {@link Serializable}, enabling safe reuse in persisted
 *       state.
 * </ul>
 *
 * @see #crossProduct(Vector3D, Vector3D)
 * @see #dotProduct(Vector3D, Vector3D)
 * @see #orthogonal()
 * @version $Id: Vector3D.java 1716 2006-12-13 22:56:35Z luc $
 * @author L. Maisonobe
 */
public class Vector3D implements Serializable {

  /**
   * Unit vector pointing along the positive X axis (coordinates: 1, 0, 0).
   *
   * <p>This constant is reused to avoid repeated allocations when callers need a right-directed
   * basis vector of length one. The instance is immutable and can be safely shared across threads
   * without synchronization.
   */
  public static final Vector3D plusI = new Vector3D(1, 0, 0);

  /**
   * Unit vector pointing along the negative X axis (coordinates: -1, 0, 0).
   *
   * <p>Useful as a ready-made left-directed axis when constructing orthogonal frames or applying
   * reflections. The vector length is exactly one and the instance is immutable.
   */
  public static final Vector3D minusI = new Vector3D(-1, 0, 0);

  /**
   * Unit vector pointing along the positive Y axis (coordinates: 0, 1, 0).
   *
   * <p>Use this constant to represent the canonical forward/up axis in planar computations or as
   * part of an orthonormal basis without additional object creation.
   */
  public static final Vector3D plusJ = new Vector3D(0, 1, 0);

  /**
   * Unit vector pointing along the negative Y axis (coordinates: 0, -1, 0).
   *
   * <p>This shared constant helps express down/backward directions and supports geometric
   * operations that expect a unit vector with a negative Y component.
   */
  public static final Vector3D minusJ = new Vector3D(0, -1, 0);

  /**
   * Unit vector pointing along the positive Z axis (coordinates: 0, 0, 1).
   *
   * <p>Frequently used as a vertical axis in right-handed coordinate systems. The immutable
   * instance can be reused wherever a normalized Z basis vector is required.
   */
  public static final Vector3D plusK = new Vector3D(0, 0, 1);

  /**
   * Unit vector pointing along the negative Z axis (coordinates: 0, 0, -1).
   *
   * <p>Provides a prebuilt downward-facing axis with unit length. Sharing this constant avoids
   * repeated construction in transformations or cross-product calculations.
   */
  public static final Vector3D minusK = new Vector3D(0, 0, -1);

  /**
   * Creates a null vector with all coordinates set to zero.
   *
   * <p>The zero vector is often used as an origin reference or as a neutral element when summing
   * multiple vectors. Because instances are immutable, the returned object can be reused safely
   * wherever a shared zero vector is appropriate.
   */
  public Vector3D() {
    x = 0;
    y = 0;
    z = 0;
  }

  /**
   * Builds a vector from explicit Cartesian coordinates.
   *
   * <p>This constructor is the most direct way to represent a point or displacement in space.
   * Values are stored as provided without range checks; callers remain responsible for supplying
   * coordinates in the desired units.
   *
   * @param x abscissa value along the X axis; any finite double is accepted
   * @param y ordinate value along the Y axis; any finite double is accepted
   * @param z height value along the Z axis; any finite double is accepted
   * @see #getX()
   * @see #getY()
   * @see #getZ()
   */
  public Vector3D(double x, double y, double z) {
    this.x = x;
    this.y = y;
    this.z = z;
  }

  /**
   * Builds a unit-length vector from azimuth and elevation angles.
   *
   * <p>The azimuth {@code alpha} is measured in radians around the Z axis where 0 corresponds to
   * the positive X direction and {@code Math.PI / 2} points to the positive Y direction. The
   * elevation {@code delta} is measured in radians above the XY plane in the range -{@code
   * Math.PI}/2 to +{@code Math.PI}/2. The resulting vector has a norm of 1 unless the inputs
   * contain infinities or NaN.
   *
   * @param alpha azimuth around the Z axis in radians; 0 is +X, {@code PI/2} is +Y
   * @param delta elevation above the XY plane in radians; range [-{@code PI}/2, {@code PI}/2]
   * @see #getAlpha()
   * @see #getDelta()
   */
  public Vector3D(double alpha, double delta) {
    double cosDelta = Math.cos(delta);
    this.x = Math.cos(alpha) * cosDelta;
    this.y = Math.sin(alpha) * cosDelta;
    this.z = Math.sin(delta);
  }

  /**
   * Builds a vector by scaling another vector with a scalar factor.
   *
   * <p>The resulting vector equals {@code a * u}. Neither the input vector nor the factor is
   * modified. Use this constructor when creating intermediate scaled values inside composite
   * operations without exposing temporary setters.
   *
   * @param a scale factor applied multiplicatively to all coordinates of {@code u}
   * @param u base vector to scale; must not be {@code null} and is left unchanged
   */
  public Vector3D(double a, Vector3D u) {
    this.x = a * u.x;
    this.y = a * u.y;
    this.z = a * u.z;
  }

  /**
   * Builds a vector as a linear combination of two input vectors.
   *
   * <p>The constructed vector equals {@code a1 * u1 + a2 * u2}. This is a convenience for
   * expressing affine transforms or barycentric coordinates without mutating intermediate data.
   *
   * @param a1 scale factor applied to {@code u1}; finite double recommended
   * @param u1 first base vector; treated as immutable input and not copied defensively
   * @param a2 scale factor applied to {@code u2}; finite double recommended
   * @param u2 second base vector; treated as immutable input and not copied defensively
   */
  public Vector3D(double a1, Vector3D u1, double a2, Vector3D u2) {
    this.x = a1 * u1.x + a2 * u2.x;
    this.y = a1 * u1.y + a2 * u2.y;
    this.z = a1 * u1.z + a2 * u2.z;
  }

  /**
   * Builds a vector as a linear combination of three input vectors.
   *
   * <p>The resulting coordinates follow {@code a1 * u1 + a2 * u2 + a3 * u3} and are computed
   * directly from the supplied factors. Inputs are assumed valid and are not normalized
   * automatically.
   *
   * @param a1 scale factor applied to {@code u1}; finite double recommended
   * @param u1 first base vector contributing to the linear combination
   * @param a2 scale factor applied to {@code u2}; finite double recommended
   * @param u2 second base vector contributing to the linear combination
   * @param a3 scale factor applied to {@code u3}; finite double recommended
   * @param u3 third base vector contributing to the linear combination
   */
  public Vector3D(double a1, Vector3D u1, double a2, Vector3D u2, double a3, Vector3D u3) {
    this.x = a1 * u1.x + a2 * u2.x + a3 * u3.x;
    this.y = a1 * u1.y + a2 * u2.y + a3 * u3.y;
    this.z = a1 * u1.z + a2 * u2.z + a3 * u3.z;
  }

  /**
   * Builds a vector as a linear combination of four input vectors.
   *
   * <p>The coordinates are computed as {@code a1 * u1 + a2 * u2 + a3 * u3 + a4 * u4}. No
   * normalization or overflow guarding is performed; callers should ensure the provided
   * coefficients match their numeric expectations.
   *
   * @param a1 scale factor applied to {@code u1}; finite double recommended
   * @param u1 first base vector contributing to the linear combination
   * @param a2 scale factor applied to {@code u2}; finite double recommended
   * @param u2 second base vector contributing to the linear combination
   * @param a3 scale factor applied to {@code u3}; finite double recommended
   * @param u3 third base vector contributing to the linear combination
   * @param a4 scale factor applied to {@code u4}; finite double recommended
   * @param u4 fourth base vector contributing to the linear combination
   */
  public Vector3D(
      double a1,
      Vector3D u1,
      double a2,
      Vector3D u2,
      double a3,
      Vector3D u3,
      double a4,
      Vector3D u4) {
    this.x = a1 * u1.x + a2 * u2.x + a3 * u3.x + a4 * u4.x;
    this.y = a1 * u1.y + a2 * u2.y + a3 * u3.y + a4 * u4.y;
    this.z = a1 * u1.z + a2 * u2.z + a3 * u3.z + a4 * u4.z;
  }

  /**
   * Returns the abscissa component of the vector.
   *
   * <p>The X coordinate is returned exactly as stored. No unit conversion or bounds checking is
   * applied, making it safe for high-performance numeric routines.
   *
   * @return immutable X component value represented as a double
   * @see #Vector3D(double, double, double)
   */
  public double getX() {
    return x;
  }

  /**
   * Returns the ordinate component of the vector.
   *
   * <p>The Y coordinate is provided without additional processing. Use this when projecting onto
   * the XY plane or when computing planar distances.
   *
   * @return immutable Y component value represented as a double
   * @see #Vector3D(double, double, double)
   */
  public double getY() {
    return y;
  }

  /**
   * Returns the height component of the vector.
   *
   * <p>The Z coordinate is delivered verbatim. This is typically used for vertical distances,
   * elevation calculations, or cross-product inputs.
   *
   * @return immutable Z component value represented as a double
   * @see #Vector3D(double, double, double)
   */
  public double getZ() {
    return z;
  }

  /**
   * Computes the Euclidean norm of the vector.
   *
   * <p>The norm is calculated as {@code sqrt(x^2 + y^2 + z^2)}. Results may be sensitive to
   * floating-point overflow or underflow for extremely large or small coordinates, mirroring
   * standard {@link Math#sqrt(double)} behavior.
   *
   * @return non-negative double representing the vector length; zero for the null vector
   */
  public double getNorm() {
    return Math.sqrt(x * x + y * y + z * z);
  }

  /**
   * Returns the azimuth angle of the vector around the Z axis.
   *
   * <p>The azimuth {@code alpha} is produced via {@link Math#atan2(double, double)} and lies in the
   * range -{@code Math.PI} to +{@code Math.PI}. When both X and Y are zero, the result is platform
   * dependent but follows {@code atan2(0, 0)} semantics.
   *
   * @return azimuth in radians measured from +X toward +Y; range [-{@code PI}, {@code PI}]
   * @see #Vector3D(double, double)
   */
  public double getAlpha() {
    return Math.atan2(y, x);
  }

  /**
   * Returns the elevation angle of the vector above the XY plane.
   *
   * <p>The elevation {@code delta} is computed as {@code asin(z / norm)} and therefore requires a
   * non-zero norm. Values range from -{@code Math.PI}/2 to +{@code Math.PI}/2. For zero-length
   * vectors, callers should handle the resulting {@link ArithmeticException} if the norm is checked
   * before invocation.
   *
   * @return elevation in radians above the XY plane; range [-{@code PI}/2, {@code PI}/2]
   * @see #Vector3D(double, double)
   */
  public double getDelta() {
    return Math.asin(z / getNorm());
  }

  /**
   * Produces a new vector equal to this vector plus the given vector.
   *
   * <p>Neither operand is modified. This method is convenient for chaining translations while
   * preserving the immutability of the original vectors.
   *
   * @param v vector to add; expected non-null and interpreted in the same units
   * @return new {@code Vector3D} representing the coordinate-wise sum
   */
  public Vector3D add(Vector3D v) {
    return new Vector3D(x + v.x, y + v.y, z + v.z);
  }

  /**
   * Produces a new vector equal to this vector plus a scaled vector.
   *
   * <p>The supplied {@code factor} is applied to {@code v} before addition, enabling affine
   * combinations without separate scaling calls.
   *
   * @param factor scale applied to {@code v} prior to addition; any finite double
   * @param v vector to add after scaling; must use the same coordinate system
   * @return new {@code Vector3D} containing the scaled sum
   */
  public Vector3D add(double factor, Vector3D v) {
    return new Vector3D(x + factor * v.x, y + factor * v.y, z + factor * v.z);
  }

  /**
   * Produces a new vector equal to this vector minus the given vector.
   *
   * <p>Use this for computing displacements between positions or reversing a prior addition. The
   * original vectors remain unchanged.
   *
   * @param v vector to subtract; must not be {@code null} and shares units with this vector
   * @return new {@code Vector3D} representing the coordinate-wise difference
   */
  public Vector3D subtract(Vector3D v) {
    return new Vector3D(x - v.x, y - v.y, z - v.z);
  }

  /**
   * Produces a new vector equal to this vector minus a scaled vector.
   *
   * <p>The {@code factor} scales {@code v} before subtraction, allowing weighted differences
   * without temporary intermediate objects.
   *
   * @param factor scale applied to {@code v} prior to subtraction; any finite double
   * @param v vector to subtract after scaling; must use the same coordinate system
   * @return new {@code Vector3D} representing the scaled difference
   */
  public Vector3D subtract(double factor, Vector3D v) {
    return new Vector3D(x - factor * v.x, y - factor * v.y, z - factor * v.z);
  }

  /**
   * Returns a normalized version of this vector.
   *
   * <p>The result has a norm of 1 while preserving direction. If the norm is zero, an {@link
   * ArithmeticException} is thrown to signal the undefined operation. Because a new instance is
   * created, the original vector remains unchanged and safe to reuse.
   *
   * @return normalized vector with unit length and identical direction
   * @throws ArithmeticException if this vector has a zero norm and cannot be normalized
   */
  public Vector3D normalize() {
    double s = getNorm();
    if (s == 0) {
      throw new ArithmeticException("null norm");
    }
    return multiply(1 / s);
  }

  /**
   * Returns a normalized vector orthogonal to this vector.
   *
   * <p>Because infinitely many orthogonal vectors exist, the implementation selects one
   * deterministically based on the largest coordinate magnitude to maintain numerical stability.
   * The returned vector always has unit length and is suitable for building local coordinate
   * frames.
   *
   * <pre>{@code
   * Vector3D k = u.normalize();
   * Vector3D i = k.orthogonal();
   * Vector3D j = Vector3D.crossProduct(k, i);
   * }</pre>
   *
   * @return normalized vector orthogonal to this vector and suitable for basis construction
   * @throws ArithmeticException if this vector has a zero norm and no direction exists
   */
  public Vector3D orthogonal() {

    double threshold = 0.6 * getNorm();
    if (threshold == 0) {
      throw new ArithmeticException("null norm");
    }

    if ((x >= -threshold) && (x <= threshold)) {
      double inverse = 1 / Math.sqrt(y * y + z * z);
      return new Vector3D(0, inverse * z, -inverse * y);
    } else if ((y >= -threshold) && (y <= threshold)) {
      double inverse = 1 / Math.sqrt(x * x + z * z);
      return new Vector3D(-inverse * z, 0, inverse * x);
    } else {
      double inverse = 1 / Math.sqrt(x * x + y * y);
      return new Vector3D(inverse * y, -inverse * x, 0);
    }
  }

  /**
   * Computes the angular separation between two vectors in radians.
   *
   * <p>The method uses the dot product for well-separated vectors and switches to a sine-based
   * calculation for nearly aligned vectors to maintain numeric accuracy. Inputs must both have
   * non-zero norms; otherwise an {@link ArithmeticException} is raised.
   *
   * @param v1 first vector; must be non-null and have non-zero norm
   * @param v2 second vector; must be non-null and have non-zero norm
   * @return angle in radians between {@code v1} and {@code v2}; range [0, {@code PI}]
   * @throws ArithmeticException if either vector has a zero norm and the angle is undefined
   */
  public static double angle(Vector3D v1, Vector3D v2) {

    double normProduct = v1.getNorm() * v2.getNorm();
    if (normProduct == 0) {
      throw new ArithmeticException("null norm");
    }

    double dot = dotProduct(v1, v2);
    double threshold = normProduct * 0.9999;
    if ((dot < -threshold) || (dot > threshold)) {
      // the vectors are almost aligned, compute using the sine
      Vector3D v3 = crossProduct(v1, v2);
      if (dot >= 0) {
        return Math.asin(v3.getNorm() / normProduct);
      }
      return Math.PI - Math.asin(v3.getNorm() / normProduct);
    }

    // the vectors are sufficiently separated to use the cosine
    return Math.acos(dot / normProduct);
  }

  /**
   * Returns a vector that is the additive inverse of this vector.
   *
   * <p>Each coordinate is negated, producing a vector pointing in the exact opposite direction with
   * identical magnitude.
   *
   * @return new {@code Vector3D} representing the opposite of this vector
   */
  public Vector3D negate() {
    return new Vector3D(-x, -y, -z);
  }

  /**
   * Returns a vector scaled by the provided scalar.
   *
   * <p>The scaling applies uniformly to all coordinates. The original vector is left unchanged,
   * preserving immutability and allowing safe reuse.
   *
   * @param a scalar multiplier applied to each coordinate; any finite double
   * @return new {@code Vector3D} scaled version of this vector
   */
  public Vector3D multiply(double a) {
    return new Vector3D(a * x, a * y, a * z);
  }

  /**
   * Computes the dot product of two vectors.
   *
   * <p>The dot product equals {@code v1.x * v2.x + v1.y * v2.y + v1.z * v2.z}. It is positive for
   * acute angles, negative for obtuse angles, and zero for orthogonal vectors.
   *
   * @param v1 first operand; expected non-null and expressed in the same units as {@code v2}
   * @param v2 second operand; expected non-null and expressed in the same units as {@code v1}
   * @return scalar dot product value capturing directional similarity
   */
  public static double dotProduct(Vector3D v1, Vector3D v2) {
    return v1.x * v2.x + v1.y * v2.y + v1.z * v2.z;
  }

  /**
   * Computes the cross product of two vectors.
   *
   * <p>The cross product yields a vector perpendicular to both inputs following the right-hand
   * rule. Its magnitude equals the area of the parallelogram spanned by the operands.
   *
   * @param v1 first operand; expected non-null and expressed in the same units as {@code v2}
   * @param v2 second operand; expected non-null and expressed in the same units as {@code v1}
   * @return new {@code Vector3D} orthogonal to both inputs following the right-hand rule
   */
  public static Vector3D crossProduct(Vector3D v1, Vector3D v2) {
    return new Vector3D(
        v1.y * v2.z - v1.z * v2.y, v1.z * v2.x - v1.x * v2.z, v1.x * v2.y - v1.y * v2.x);
  }

  /** Abscissa. */
  private final double x;

  /** Ordinate. */
  private final double y;

  /** Height. */
  private final double z;

  @Serial private static final long serialVersionUID = 7318440192750283659L;
}
