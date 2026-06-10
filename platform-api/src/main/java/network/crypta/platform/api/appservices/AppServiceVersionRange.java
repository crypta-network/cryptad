package network.crypta.platform.api.appservices;

import java.util.LinkedHashMap;
import network.crypta.platform.api.PlatformApiException;

/**
 * Bounded service-version range declared by a consumer app dependency.
 *
 * <p>The range is parsed from signed dependency metadata and used only for provider compatibility
 * review. It lets a consumer app say which provider service versions it was tested against without
 * granting access or selecting a provider by itself. A descriptor still has to match provider app
 * id, service id, scopes, contexts, kind, adapter, and an active grant before invocation can
 * proceed.
 *
 * <p>Bounds are normalized as manifest tokens. Numeric dotted versions are compared by numeric
 * component without converting to {@code int}, so large bounded version components remain safe to
 * review. Non-numeric tokens use stable lexicographic ordering. Provider display versions that do
 * not normalize as tokens are treated as outside the range rather than causing dependency graph or
 * bundle routes to fail.
 *
 * @param min optional inclusive minimum service version token
 * @param max optional inclusive maximum service version token
 */
public record AppServiceVersionRange(String min, String max) {
  /**
   * Creates a normalized version range.
   *
   * <p>At least one bound should be non-null when callers construct a meaningful range, although
   * the record also tolerates a fully open range. When both bounds are present, the minimum must
   * compare less than or equal to the maximum after normalization.
   *
   * @throws IllegalArgumentException when a bound is malformed or the range is inverted
   */
  public AppServiceVersionRange {
    min = normalizeVersion(min);
    max = normalizeVersion(max);
    if (min != null && max != null && compareVersions(min, max) > 0) {
      throw new IllegalArgumentException("minimum service version must not exceed maximum");
    }
  }

  /**
   * Returns {@code null} when both bounds are absent, otherwise a normalized range.
   *
   * <p>The manifest parser uses this helper so legacy requests without version metadata do not
   * allocate unnecessary range objects. A single-sided bound is valid and means all versions on the
   * open side are acceptable.
   *
   * @param min raw optional minimum version from dependency metadata
   * @param max raw optional maximum version from dependency metadata
   * @return normalized range, or {@code null} when neither bound is declared
   */
  static AppServiceVersionRange optional(String min, String max) {
    if ((min == null || min.isBlank()) && (max == null || max.isBlank())) {
      return null;
    }
    return new AppServiceVersionRange(min, max);
  }

  /**
   * Returns true when the supplied provider service version satisfies this range.
   *
   * <p>Provider versions are normalized independently of manifest bounds. If a provider advertises
   * a display-style value that cannot be represented as a token, the method returns {@code false}
   * instead of throwing. Dependency graph callers can then report {@code version-mismatch} without
   * failing the entire route.
   *
   * @param version provider service version from the current descriptor
   * @return {@code true} when the provider version is inside all declared bounds
   */
  boolean contains(String version) {
    String normalized = normalizeProviderVersion(version);
    return normalized != null
        && (min == null || compareVersions(normalized, min) >= 0)
        && (max == null || compareVersions(normalized, max) <= 0);
  }

  /**
   * Returns deterministic JSON for contract, SDK, and Web Shell callers.
   *
   * <p>The map preserves the inclusive bounds exactly as normalized by the constructor. Missing
   * bounds are serialized as {@code null} so callers can distinguish an open side from a concrete
   * version token.
   *
   * @return ordered JSON-compatible map containing inclusive {@code min} and {@code max} bounds
   */
  public java.util.Map<String, Object> toJson() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("min", min);
    json.put("max", max);
    return json;
  }

  /**
   * Normalizes a manifest-declared service version bound.
   *
   * <p>Bounds are stricter than provider display values because they are signed dependency metadata
   * and participate in deterministic compatibility review.
   *
   * @param value raw manifest version bound, or {@code null} for an open side
   * @return normalized version token, or {@code null} when no bound is declared
   */
  private static String normalizeVersion(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    return AppServiceManifestParser.requiredToken("serviceVersion", value, 40);
  }

  /**
   * Normalizes a provider descriptor version for range comparison.
   *
   * <p>Provider descriptors historically allowed display-style version strings. Treating malformed
   * display values as absent lets dependency graph routes report {@code version-mismatch} instead
   * of failing the whole review response.
   *
   * @param value raw provider service version from the current descriptor
   * @return normalized comparable token, or {@code null} when the descriptor version is not
   *     comparable
   */
  private static String normalizeProviderVersion(String value) {
    try {
      return normalizeVersion(value);
    } catch (PlatformApiException _) {
      return null;
    }
  }

  /**
   * Compares two normalized version tokens using stable dependency-review ordering.
   *
   * <p>Pure dotted numeric versions use component-wise numeric comparison without parsing into
   * fixed width integers. Other valid tokens use lexicographic ordering, which keeps nonnumeric
   * release labels deterministic across JVMs.
   *
   * @param first normalized version token
   * @param second normalized version token
   * @return negative, zero, or positive when {@code first} sorts before, equal to, or after {@code
   *     second}
   */
  private static int compareVersions(String first, String second) {
    if (isNumericVersion(first) && isNumericVersion(second)) {
      String[] left = numericParts(first);
      String[] right = numericParts(second);
      int length = Math.max(left.length, right.length);
      for (int index = 0; index < length; index++) {
        String leftPart = index < left.length ? left[index] : "0";
        String rightPart = index < right.length ? right[index] : "0";
        int compared = compareNumericPart(leftPart, rightPart);
        if (compared != 0) {
          return compared;
        }
      }
      return 0;
    }
    return first.compareTo(second);
  }

  /**
   * Returns whether a normalized version token is made only of dotted decimal components.
   *
   * @param value normalized version token
   * @return {@code true} when numeric component comparison should be used
   */
  private static boolean isNumericVersion(String value) {
    boolean expectingDigit = true;
    for (int index = 0; index < value.length(); index++) {
      char current = value.charAt(index);
      if (isAsciiDigit(current)) {
        expectingDigit = false;
      } else if (current == '.') {
        if (expectingDigit) {
          return false;
        }
        expectingDigit = true;
      } else {
        return false;
      }
    }
    return !expectingDigit;
  }

  /**
   * Splits a numeric dotted version into comparison components.
   *
   * @param value numeric dotted version token
   * @return decimal components in declaration order
   */
  private static String[] numericParts(String value) {
    return value.split("\\.");
  }

  /**
   * Compares two decimal version components without integer conversion.
   *
   * <p>This avoids overflow for bounded but very large numeric components while preserving ordinary
   * numeric ordering after leading zeroes are removed.
   *
   * @param first first decimal component
   * @param second second decimal component
   * @return negative, zero, or positive according to numeric component order
   */
  private static int compareNumericPart(String first, String second) {
    String normalizedFirst = stripLeadingZeroes(first);
    String normalizedSecond = stripLeadingZeroes(second);
    int lengthComparison = Integer.compare(normalizedFirst.length(), normalizedSecond.length());
    if (lengthComparison != 0) {
      return lengthComparison;
    }
    return normalizedFirst.compareTo(normalizedSecond);
  }

  /**
   * Removes insignificant leading zeroes from a decimal component.
   *
   * @param value decimal component from a numeric dotted version
   * @return component with leading zeroes removed, leaving one zero for an all-zero component
   */
  private static String stripLeadingZeroes(String value) {
    int index = 0;
    while (index < value.length() - 1 && value.charAt(index) == '0') {
      index++;
    }
    return value.substring(index);
  }

  private static boolean isAsciiDigit(char value) {
    return value >= '0' && value <= '9';
  }
}
