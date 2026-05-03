package network.crypta.platform.appdist;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Advisory Platform API contract metadata declared by an app bundle or catalog entry.
 *
 * <p>The metadata describes the Platform API compatibility range an app author tested against. It
 * does not grant permissions and does not change install behavior for older manifests that omit the
 * fields. The authoritative grant request remains {@code app.permissions}; optional capabilities
 * are review hints for developer tooling, catalogs, and release certification.
 *
 * <p>The version values refer to the Platform API compatibility contract version, not the URL API
 * version and not the Cryptad build number. A missing minimum or maximum-tested value means the app
 * has not declared that side of its compatibility range. Runtime install/update paths can therefore
 * report {@code unknown} or advisory warnings for old bundles without rejecting them by default.
 *
 * <p>Instances are immutable. Optional capability names are trimmed, lower-cased, validated with
 * the same conservative token syntax used for manifest capabilities, and de-duplicated while
 * preserving declaration order.
 *
 * @param minimumVersion minimum Platform API contract version required by the app, or {@code null}
 * @param maximumTestedVersion highest Platform API contract version tested by the app, or {@code
 *     null}
 * @param optionalCapabilities normalized advisory capability names the app can use when present
 * @param experimentalCapabilitiesAccepted whether the author explicitly accepts experimental
 *     Platform API capabilities
 */
public record AppApiCompatibilityMetadata(
    Integer minimumVersion,
    Integer maximumTestedVersion,
    List<String> optionalCapabilities,
    boolean experimentalCapabilitiesAccepted) {
  private static final Pattern CAPABILITY_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");

  /**
   * Empty metadata used for manifests and catalogs that do not declare any {@code api.*} keys.
   *
   * <p>This shared value preserves backward compatibility for existing app bundles. It represents
   * an undeclared compatibility range, no optional capabilities, and no experimental capability
   * opt-in.
   */
  public static final AppApiCompatibilityMetadata EMPTY =
      new AppApiCompatibilityMetadata(null, null, List.of(), false);

  /**
   * Creates normalized advisory API compatibility metadata.
   *
   * <p>Contract versions are positive integers when present. Optional capabilities use the same
   * syntax as manifest permissions and are normalized to lower case with duplicates removed in
   * declaration order. When both version bounds are present, the maximum-tested contract must be at
   * least the minimum required contract.
   *
   * <p>The constructor performs syntax and range validation only. It does not compare the metadata
   * against a target node contract, and it does not decide whether a catalog or bundle should be
   * installable; those decisions belong to Platform API compatibility verification and review UI.
   *
   * @throws IllegalArgumentException if a version is not positive or a capability name is malformed
   * @throws NullPointerException if {@code optionalCapabilities} or one of its entries is {@code
   *     null}
   */
  public AppApiCompatibilityMetadata {
    minimumVersion = normalizeVersion(minimumVersion, "api.minimumVersion");
    maximumTestedVersion = normalizeVersion(maximumTestedVersion, "api.maximumTestedVersion");
    if (minimumVersion != null
        && maximumTestedVersion != null
        && maximumTestedVersion < minimumVersion) {
      throw new IllegalArgumentException("api.maximumTestedVersion must be >= api.minimumVersion");
    }
    optionalCapabilities = normalizeCapabilities(optionalCapabilities);
  }

  /**
   * Returns whether any compatibility field was explicitly declared.
   *
   * <p>This distinguishes old manifests that simply lack compatibility metadata from manifests that
   * intentionally declare a range, optional capability list, or experimental opt-in. Platform API
   * summaries use this to report {@code unknown} for undeclared metadata without treating the app
   * as incompatible.
   *
   * @return {@code true} when this metadata carries at least one non-default value
   */
  public boolean declared() {
    return minimumVersion != null
        || maximumTestedVersion != null
        || !optionalCapabilities.isEmpty()
        || experimentalCapabilitiesAccepted;
  }

  /**
   * Returns metadata for manifests and catalogs that do not declare compatibility fields.
   *
   * <p>The returned object is immutable and may be reused wherever a parser or caller needs to
   * represent missing {@code api.*} fields. Use this factory when the source artifact is valid but
   * has no explicit Platform API compatibility declaration.
   *
   * @return shared backward-compatible metadata for an undeclared compatibility range
   */
  public static AppApiCompatibilityMetadata undeclared() {
    return EMPTY;
  }

  private static Integer normalizeVersion(Integer version, String fieldName) {
    if (version == null) {
      return null;
    }
    if (version <= 0) {
      throw new IllegalArgumentException(fieldName + " must be a positive integer");
    }
    return version;
  }

  private static List<String> normalizeCapabilities(List<String> capabilities) {
    Objects.requireNonNull(capabilities, "optionalCapabilities");
    Set<String> normalized = new LinkedHashSet<>();
    for (String capability : capabilities) {
      String value =
          Objects.requireNonNull(capability, "optionalCapabilities value")
              .trim()
              .toLowerCase(Locale.ROOT);
      if (value.isEmpty()) {
        throw new IllegalArgumentException(
            "api.optionalCapabilities must not contain blank entries");
      }
      if (!CAPABILITY_PATTERN.matcher(value).matches()) {
        throw new IllegalArgumentException("invalid api.optionalCapabilities value: " + capability);
      }
      normalized.add(value);
    }
    return List.copyOf(normalized);
  }
}
