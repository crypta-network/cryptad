package network.crypta.node;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility for working with node positions in a circular keyspace of length {@code 1.0}.
 *
 * <p>The valid range for a location is {@code [0.0, 1.0]} (both endpoints are treated as valid
 * values). Distances are computed on the unit circle and represent the minimal arc length between
 * two points. Methods in this class are stateless and thread-safe.
 *
 * @author amphibian
 */
public class Location {
  private static final Logger LOG = LoggerFactory.getLogger(Location.class);

  public static final double LOCATION_INVALID = -1.0;

  private Location() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Parse a location from text.
   *
   * <p>Accepts any decimal representation of a {@code double}. Values must lie within {@code [0.0,
   * 1.0]} to be considered valid.
   *
   * @param init the textual representation of a location; {@code null} is treated as invalid
   * @return the parsed value when valid; otherwise {@link #LOCATION_INVALID}
   */
  public static double getLocation(String init) {
    try {
      if (init == null) {
        return LOCATION_INVALID;
      }
      double d = Double.parseDouble(init);
      if (!isValid(d)) {
        return LOCATION_INVALID;
      }
      return d;
    } catch (NumberFormatException _) {
      return LOCATION_INVALID;
    }
  }

  /**
   * Compute the absolute circular distance between a peer and a location.
   *
   * @param p a peer with a valid location
   * @param loc a valid location
   * @return the minimal arc length in {@code [0.0, 0.5]} between the peer and {@code loc}
   * @throws IllegalArgumentException if either input location is invalid
   */
  public static double distance(PeerNode p, double loc) {
    return distance(p.getLocation(), loc);
  }

  /**
   * Compute the absolute circular distance between two locations.
   *
   * @param a a valid location
   * @param b a valid location
   * @return the minimal arc length in {@code [0.0, 0.5]}
   * @throws IllegalArgumentException if either {@code a} or {@code b} is invalid
   */
  public static double distance(double a, double b) {
    if (!isValid(a) || !isValid(b)) {
      String errMsg =
          "Invalid location values: a=" + a + " b=" + b + " (expected within [0.0, 1.0]).";
      LOG.error(errMsg);
      throw new IllegalArgumentException(errMsg);
    }
    return simpleDistance(a, b);
  }

  /**
   * Compute the absolute circular distance, tolerating invalid inputs.
   *
   * <p>Invalid locations are treated as being at {@code 2.0}. When both inputs are invalid, the
   * distance is {@code 0.0}.
   *
   * @param a any location
   * @param b any location
   * @return the minimal arc length, or a value derived from the invalid-input rule above
   */
  public static double distanceAllowInvalid(double a, double b) {
    if (!isValid(a) && !isValid(b)) {
      return 0.0; // Both invalid: treat as equal.
    }
    if (!isValid(a)) {
      return 2.0 - b;
    }
    if (!isValid(b)) {
      return 2.0 - a;
    }
    // Both values are valid; compute minimal arc length.
    return simpleDistance(a, b);
  }

  /**
   * Compute absolute distance without validating inputs.
   *
   * <p>Behavior is undefined for invalid locations.
   *
   * @param a a valid location
   * @param b a valid location
   * @return the minimal arc length in {@code [0.0, 0.5]}
   */
  private static double simpleDistance(double a, double b) {
    return Math.abs(change(a, b));
  }

  /**
   * Compute the signed circular delta from {@code from} to {@code to}.
   *
   * <p>The result lies in {@code (-0.5, 0.5]} after accounting for wrap-around. For points exactly
   * opposite on the unit circle, the method returns {@code +0.5}. Behavior is undefined for invalid
   * locations.
   *
   * @param from a valid starting location
   * @param to a valid end location
   * @return the signed delta on the unit circle
   */
  public static double change(double from, double to) {
    double change = to - from;
    if (change > 0.5) {
      return change - 1.0;
    }
    if (change <= -0.5) {
      return change + 1.0;
    }
    return change;
  }

  /**
   * Normalize an arbitrary value into the canonical range.
   *
   * <p>Maps any {@code double} to {@code [0.0, 1.0)} using modulo arithmetic, preserving the value
   * modulo {@code 1.0}. For example, {@code normalize(0.3 + 1.0) == 0.3} and {@code normalize(0.3 -
   * 1.0) == 0.3}.
   *
   * <p>Note: very large magnitudes may lose precision due to IEEE&nbsp;754 rounding.
   *
   * @param rough any location
   * @return the normalized location in {@code [0.0, 1.0)}
   */
  public static double normalize(double rough) {
    double normal = rough % 1.0;
    if (normal < 0) {
      return 1.0 + normal;
    }
    return normal;
  }

  /**
   * Test whether two locations are effectively equal.
   *
   * <p>Returns {@code true} when the circular distance is below a tiny tolerance ({@code 2 *
   * Double.MIN_VALUE})—for example, {@code equals(0.0, 1.0)}—or when both locations are invalid.
   *
   * @param a any location
   * @param b any location
   * @return {@code true} if considered equal; otherwise {@code false}
   */
  public static boolean equals(double a, double b) {
    return distanceAllowInvalid(a, b) < Double.MIN_VALUE * 2;
  }

  /**
   * Test whether a location lies within {@code [0.0, 1.0]}.
   *
   * @param loc any location
   * @return {@code true} if valid; otherwise {@code false}
   */
  public static boolean isValid(double loc) {
    return loc >= 0.0 && loc <= 1.0;
  }
}
