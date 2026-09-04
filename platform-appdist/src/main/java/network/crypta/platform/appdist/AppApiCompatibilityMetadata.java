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
 * has not declared that side of its compatibility range. Missing {@code api.targetStability}
 * remains readable for old bundles and defaults to {@code experimental} for compatibility review,
 * while {@link #targetStabilityDeclared()} tells tooling whether the manifest explicitly made that
 * choice. Runtime install/update paths can therefore report {@code unknown} or advisory warnings
 * for old bundles without rejecting them by default.
 *
 * <p>Instances are immutable. Optional capability names are trimmed, lower-cased, validated with
 * the same conservative token syntax used for manifest capabilities, and de-duplicated while
 * preserving declaration order.
 *
 * @param minimumVersion minimum Platform API contract version required by the app, or {@code null}
 * @param maximumTestedVersion highest Platform API contract version tested by the app, or {@code
 *     null}
 * @param optionalCapabilities normalized advisory capability names the app can use when present
 * @param targetStability effective target stability for the app; missing legacy declarations become
 *     {@code experimental}
 * @param targetStabilityDeclared whether {@code api.targetStability} was explicitly present
 * @param targetBaseline effective named stable baseline targeted by the app, or {@code null}
 * @param targetBaselineDeclared whether {@code api.targetBaseline} was explicitly present
 * @param experimentalCapabilitiesAccepted whether the author explicitly accepts experimental
 *     Platform API capabilities
 * @param experimentalCapabilitiesAcceptedDeclared whether {@code
 *     api.experimentalCapabilitiesAccepted} was explicitly present
 */
public record AppApiCompatibilityMetadata(
    Integer minimumVersion,
    Integer maximumTestedVersion,
    List<String> optionalCapabilities,
    TargetStability targetStability,
    boolean targetStabilityDeclared,
    String targetBaseline,
    boolean targetBaselineDeclared,
    boolean experimentalCapabilitiesAccepted,
    boolean experimentalCapabilitiesAcceptedDeclared) {
  private static final Pattern CAPABILITY_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final Pattern TARGET_BASELINE_PATTERN = Pattern.compile("1\\.(?:0|[1-9]\\d*)");

  /** Immutable Platform API baseline selected by legacy explicit stable declarations. */
  public static final String DEFAULT_STABLE_TARGET_BASELINE = "1.0";

  /**
   * Empty metadata used for manifests and catalogs that do not declare any {@code api.*} keys.
   *
   * <p>This shared value preserves backward compatibility for existing app bundles. It represents
   * an undeclared compatibility range, no optional capabilities, and no experimental capability
   * opt-in.
   */
  public static final AppApiCompatibilityMetadata EMPTY =
      new AppApiCompatibilityMetadata(
          null, null, List.of(), null, false, null, false, false, false);

  /**
   * Creates normalized advisory API compatibility metadata.
   *
   * <p>Contract versions are positive integers when present. Optional capabilities use the same
   * syntax as manifest permissions and are normalized to lower case with duplicates removed in
   * declaration order. Missing target stability is normalized to {@code experimental} but keeps
   * {@code targetStabilityDeclared=false} so compatibility tools can surface the legacy default.
   * When both version bounds are present, the maximum-tested contract must be at least the minimum
   * required contract.
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
    if (targetStability == null) {
      targetStability = TargetStability.EXPERIMENTAL;
      targetStabilityDeclared = false;
    }
    if (targetBaseline == null) {
      if (targetBaselineDeclared) {
        throw new IllegalArgumentException(
            "api.targetBaseline cannot be declared without a baseline value");
      }
      if (targetStability == TargetStability.STABLE) {
        targetBaseline = DEFAULT_STABLE_TARGET_BASELINE;
      }
    } else {
      validateTargetBaseline(targetBaseline);
    }
    if (experimentalCapabilitiesAccepted) {
      experimentalCapabilitiesAcceptedDeclared = true;
    }
  }

  /**
   * Creates metadata using the pre-stable-freeze constructor shape.
   *
   * <p>Callers compiled against the older API did not have a target-stability field. Those
   * instances keep the documented legacy default of {@code experimental} and mark the target as not
   * explicitly declared.
   *
   * @param minimumVersion minimum Platform API contract version required by the app, or {@code
   *     null}
   * @param maximumTestedVersion highest Platform API contract version tested by the app, or {@code
   *     null}
   * @param optionalCapabilities normalized advisory capability names the app can use when present
   * @param experimentalCapabilitiesAccepted whether the author explicitly accepts experimental
   *     Platform API capabilities
   */
  public AppApiCompatibilityMetadata(
      Integer minimumVersion,
      Integer maximumTestedVersion,
      List<String> optionalCapabilities,
      boolean experimentalCapabilitiesAccepted) {
    this(
        minimumVersion,
        maximumTestedVersion,
        optionalCapabilities,
        null,
        false,
        null,
        false,
        experimentalCapabilitiesAccepted,
        experimentalCapabilitiesAccepted);
  }

  /**
   * Creates metadata with an explicit {@code api.targetStability} value.
   *
   * @param minimumVersion minimum Platform API contract version required by the app, or {@code
   *     null}
   * @param maximumTestedVersion highest Platform API contract version tested by the app, or {@code
   *     null}
   * @param optionalCapabilities normalized advisory capability names the app can use when present
   * @param targetStability explicit manifest or catalog target stability
   * @param experimentalCapabilitiesAccepted whether the author explicitly accepts experimental
   *     Platform API capabilities
   */
  public AppApiCompatibilityMetadata(
      Integer minimumVersion,
      Integer maximumTestedVersion,
      List<String> optionalCapabilities,
      TargetStability targetStability,
      boolean experimentalCapabilitiesAccepted) {
    this(
        minimumVersion,
        maximumTestedVersion,
        optionalCapabilities,
        targetStability,
        true,
        null,
        false,
        experimentalCapabilitiesAccepted,
        true);
  }

  /**
   * Creates metadata with caller-supplied target-stability declaration state.
   *
   * <p>This constructor preserves the shape used by the first Platform API 1.0 freeze work before
   * catalog tooling needed to distinguish an omitted experimental opt-in from an explicit {@code
   * false}. A {@code true} experimental acceptance value is necessarily treated as declared; an
   * explicit {@code false} should use the canonical constructor when the declaration state matters.
   *
   * @param minimumVersion minimum Platform API contract version required by the app, or {@code
   *     null}
   * @param maximumTestedVersion highest Platform API contract version tested by the app, or {@code
   *     null}
   * @param optionalCapabilities normalized advisory capability names the app can use when present
   * @param targetStability effective target stability for the app; {@code null} uses the legacy
   *     experimental default
   * @param targetStabilityDeclared whether {@code api.targetStability} was explicitly present
   * @param experimentalCapabilitiesAccepted whether the author explicitly accepts experimental
   *     Platform API capabilities
   */
  public AppApiCompatibilityMetadata(
      Integer minimumVersion,
      Integer maximumTestedVersion,
      List<String> optionalCapabilities,
      TargetStability targetStability,
      boolean targetStabilityDeclared,
      boolean experimentalCapabilitiesAccepted) {
    this(
        minimumVersion,
        maximumTestedVersion,
        optionalCapabilities,
        targetStability,
        targetStabilityDeclared,
        null,
        false,
        experimentalCapabilitiesAccepted,
        experimentalCapabilitiesAccepted);
  }

  /**
   * Creates metadata using the pre-target-baseline canonical constructor shape.
   *
   * <p>An explicit stable target without a named baseline keeps the Platform API 1.0 compatibility
   * default. Undeclared legacy metadata remains experimental and has no effective target baseline.
   *
   * @param minimumVersion minimum Platform API contract version required by the app, or {@code
   *     null}
   * @param maximumTestedVersion highest Platform API contract version tested by the app, or {@code
   *     null}
   * @param optionalCapabilities normalized advisory capability names the app can use when present
   * @param targetStability effective target stability for the app
   * @param targetStabilityDeclared whether {@code api.targetStability} was explicitly present
   * @param experimentalCapabilitiesAccepted whether experimental capabilities are accepted
   * @param experimentalCapabilitiesAcceptedDeclared whether the acceptance field was declared
   */
  public AppApiCompatibilityMetadata(
      Integer minimumVersion,
      Integer maximumTestedVersion,
      List<String> optionalCapabilities,
      TargetStability targetStability,
      boolean targetStabilityDeclared,
      boolean experimentalCapabilitiesAccepted,
      boolean experimentalCapabilitiesAcceptedDeclared) {
    this(
        minimumVersion,
        maximumTestedVersion,
        optionalCapabilities,
        targetStability,
        targetStabilityDeclared,
        null,
        false,
        experimentalCapabilitiesAccepted,
        experimentalCapabilitiesAcceptedDeclared);
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
        || targetStabilityDeclared
        || targetBaselineDeclared
        || experimentalCapabilitiesAcceptedDeclared;
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

  private static void validateTargetBaseline(String targetBaseline) {
    String value = Objects.requireNonNull(targetBaseline, "api.targetBaseline");
    if (!TARGET_BASELINE_PATTERN.matcher(value).matches()) {
      throw new IllegalArgumentException("unsupported api.targetBaseline: " + targetBaseline);
    }
  }

  /**
   * App-declared stability target for Platform API compatibility verification.
   *
   * <p>The manifest spelling is intentionally narrower than the contract descriptor stability
   * vocabulary. Third-party apps can target the stable baseline or explicitly opt into experimental
   * app-facing APIs. Internal and operator-only surfaces are never valid app targets.
   */
  public enum TargetStability {
    /** Stable Platform API 1.0 app-facing baseline. */
    STABLE("stable"),

    /** App-facing experimental APIs outside the stable compatibility guarantee. */
    EXPERIMENTAL("experimental");

    private final String manifestValue;

    TargetStability(String manifestValue) {
      this.manifestValue = manifestValue;
    }

    /**
     * Returns the manifest/catalog spelling for this target.
     *
     * @return lower-case compatibility metadata value
     */
    public String manifestValue() {
      return manifestValue;
    }

    /**
     * Parses {@code api.targetStability}.
     *
     * @param value manifest or catalog value
     * @return matching target stability
     * @throws IllegalArgumentException if the value is not {@code stable} or {@code experimental}
     */
    public static TargetStability parse(String value) {
      String normalized = Objects.requireNonNull(value, "api.targetStability").trim();
      for (TargetStability target : values()) {
        if (target.manifestValue.equals(normalized.toLowerCase(Locale.ROOT))) {
          return target;
        }
      }
      throw new IllegalArgumentException("unsupported api.targetStability: " + value);
    }
  }
}
