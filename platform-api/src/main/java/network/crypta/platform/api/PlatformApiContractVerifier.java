package network.crypta.platform.api;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;

/**
 * Offline verifier for app-declared Platform API compatibility metadata.
 *
 * <p>The verifier is shared by developer tooling, Platform API summaries, and release
 * certification. It checks manifest permissions and advisory {@code api.*} metadata against a
 * deterministic target contract without contacting a running node.
 *
 * <p>Verification has two modes. Non-strict mode is intended for operator-facing install/update
 * review and local development feedback; most compatibility risks become warnings. Strict mode is
 * intended for release gates and explicit CLI verification; future minimum-contract requirements,
 * unknown capabilities, and newer-than-tested targets become errors. Internal capabilities are
 * always errors because app manifests must never request them.
 *
 * <p>The verifier does not mutate manifests, catalogs, or app installation state. It only compares
 * declared metadata and permission names with a supplied contract snapshot, which keeps it usable
 * in offline tooling and repeatable release-certification self-tests.
 */
public final class PlatformApiContractVerifier {
  private static final String STATUS_COMPATIBLE = "compatible";
  private static final String STATUS_BELOW_MINIMUM = "below_minimum";
  private static final String STATUS_NEWER_THAN_TESTED = "newer_than_tested";
  private static final String STATUS_UNKNOWN = "unknown";
  private static final String STATUS_INCOMPATIBLE = "incompatible";

  private PlatformApiContractVerifier() {}

  /**
   * Verifies one app manifest or catalog compatibility declaration.
   *
   * <p>The supplied manifest permissions remain the authoritative capability request. Optional
   * capabilities from {@code apiCompatibility} are checked as advisory metadata only; they do not
   * grant access, and they do not replace {@code app.permissions}. Inputs are sorted before
   * capability checks so repeated runs produce stable finding order.
   *
   * @param apiCompatibility app-declared API compatibility metadata, or {@code null} for old
   *     manifests without {@code api.*} fields
   * @param manifestPermissions authoritative manifest permission request from {@code
   *     app.permissions}
   * @param contract target Platform API contract used for offline comparison
   * @param strict whether compatibility risks that are warnings in review mode should become errors
   * @return deterministic verification result containing all findings in stable order
   */
  public static CompatibilityVerificationResult verify(
      AppApiCompatibilityMetadata apiCompatibility,
      Collection<String> manifestPermissions,
      PlatformApiContract contract,
      boolean strict) {
    AppApiCompatibilityMetadata metadata =
        Objects.requireNonNullElse(apiCompatibility, AppApiCompatibilityMetadata.undeclared());
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, "contract");
    List<String> permissions = sorted(manifestPermissions);
    Map<String, PlatformApiCapabilityDescriptor> descriptors = checkedContract.capabilitiesByName();
    List<CompatibilityFinding> findings = new ArrayList<>();
    checkContractRange(metadata, checkedContract.contractVersion(), strict, findings);
    checkCapabilities(
        permissions,
        "manifest permission",
        "unknown_manifest_permission",
        descriptors,
        metadata.experimentalCapabilitiesAccepted(),
        strict,
        findings);
    checkCapabilities(
        metadata.optionalCapabilities(),
        "optional capability",
        "unknown_optional_capability",
        descriptors,
        metadata.experimentalCapabilitiesAccepted(),
        strict,
        findings);
    return new CompatibilityVerificationResult(List.copyOf(findings));
  }

  /**
   * Builds the concise API compatibility summary used by Platform API responses.
   *
   * <p>The summary is intentionally smaller than the full verifier output. It exposes the declared
   * version range, the target contract version, optional capabilities, experimental opt-in state, a
   * coarse status, and human-readable warnings. Old apps without compatibility metadata report
   * {@code unknown} rather than failing install or update review.
   *
   * @param apiCompatibility app-declared API compatibility metadata, or {@code null} for legacy
   *     manifests
   * @param manifestPermissions authoritative manifest permission request used for warnings
   * @param contract current or target Platform API contract used for status calculation
   * @return deterministic JSON-compatible summary object for Platform API responses
   */
  public static Map<String, Object> summarize(
      AppApiCompatibilityMetadata apiCompatibility,
      Collection<String> manifestPermissions,
      PlatformApiContract contract) {
    AppApiCompatibilityMetadata metadata =
        Objects.requireNonNullElse(apiCompatibility, AppApiCompatibilityMetadata.undeclared());
    PlatformApiContract checkedContract = Objects.requireNonNull(contract, "contract");
    CompatibilityVerificationResult result =
        verify(metadata, manifestPermissions, checkedContract, false);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("minimumVersion", metadata.minimumVersion());
    json.put("maximumTestedVersion", metadata.maximumTestedVersion());
    json.put("currentVersion", checkedContract.contractVersion());
    json.put("optionalCapabilities", metadata.optionalCapabilities());
    json.put("experimentalCapabilitiesAccepted", metadata.experimentalCapabilitiesAccepted());
    json.put("declared", metadata.declared());
    json.put("status", status(metadata, checkedContract.contractVersion(), result));
    json.put("warnings", result.messages());
    return json;
  }

  private static void checkContractRange(
      AppApiCompatibilityMetadata metadata,
      int targetContractVersion,
      boolean strict,
      List<CompatibilityFinding> findings) {
    Integer minimumVersion = metadata.minimumVersion();
    if (minimumVersion != null && minimumVersion > targetContractVersion) {
      findings.add(
          finding(
              "minimum_version_above_target",
              releaseRiskSeverity(strict),
              "App requires Platform API contract "
                  + minimumVersion
                  + " but target contract is "
                  + targetContractVersion
                  + "."));
    }
    Integer maximumTestedVersion = metadata.maximumTestedVersion();
    if (maximumTestedVersion != null && maximumTestedVersion < targetContractVersion) {
      findings.add(
          finding(
              "target_newer_than_tested",
              releaseRiskSeverity(strict),
              "Target Platform API contract "
                  + targetContractVersion
                  + " is newer than the app's maximum tested contract "
                  + maximumTestedVersion
                  + "."));
    }
  }

  private static void checkCapabilities(
      List<String> capabilities,
      String label,
      String unknownCode,
      Map<String, PlatformApiCapabilityDescriptor> descriptors,
      boolean experimentalAccepted,
      boolean strict,
      List<CompatibilityFinding> findings) {
    for (String capability : capabilities) {
      PlatformApiCapabilityDescriptor descriptor = descriptors.get(capability);
      if (descriptor == null) {
        findings.add(
            finding(
                unknownCode,
                releaseRiskSeverity(strict),
                "Unknown " + label + ": " + capability + "."));
        continue;
      }
      checkCapabilityStability(descriptor, experimentalAccepted, strict, findings);
    }
  }

  private static void checkCapabilityStability(
      PlatformApiCapabilityDescriptor descriptor,
      boolean experimentalAccepted,
      boolean strict,
      List<CompatibilityFinding> findings) {
    switch (descriptor.stability()) {
      case PlatformApiStabilityLevel stability
          when stability == PlatformApiStabilityLevel.EXPERIMENTAL && !experimentalAccepted ->
          findings.add(
              finding(
                  "experimental_capability",
                  releaseRiskSeverity(strict),
                  "Experimental capability requires api.experimentalCapabilitiesAccepted=true: "
                      + descriptor.name()
                      + "."));
      case STABLE, EXPERIMENTAL -> {
        // Stable and explicitly accepted experimental capabilities require no verifier finding.
      }
      case DEPRECATED ->
          findings.add(
              finding(
                  "deprecated_capability",
                  releaseRiskSeverity(strict),
                  "Deprecated capability is declared: " + descriptor.name() + "."));
      case SCHEDULED_FOR_REMOVAL ->
          findings.add(
              finding(
                  "scheduled_for_removal_capability",
                  releaseRiskSeverity(strict),
                  "Capability is scheduled for removal: " + descriptor.name() + "."));
      case INTERNAL ->
          findings.add(
              finding(
                  "internal_capability",
                  CompatibilityFindingSeverity.ERROR,
                  "Internal capability must not be declared by apps: " + descriptor.name() + "."));
    }
  }

  private static String status(
      AppApiCompatibilityMetadata metadata,
      int targetContractVersion,
      CompatibilityVerificationResult result) {
    if (!metadata.declared()) {
      return STATUS_UNKNOWN;
    }
    Integer minimumVersion = metadata.minimumVersion();
    if (minimumVersion != null && minimumVersion > targetContractVersion) {
      return STATUS_BELOW_MINIMUM;
    }
    Integer maximumTestedVersion = metadata.maximumTestedVersion();
    if (maximumTestedVersion != null && maximumTestedVersion < targetContractVersion) {
      return STATUS_NEWER_THAN_TESTED;
    }
    if (result.hasErrors()) {
      return STATUS_INCOMPATIBLE;
    }
    return STATUS_COMPATIBLE;
  }

  private static CompatibilityFindingSeverity releaseRiskSeverity(boolean strict) {
    return strict ? CompatibilityFindingSeverity.ERROR : CompatibilityFindingSeverity.WARNING;
  }

  private static CompatibilityFinding finding(
      String code, CompatibilityFindingSeverity severity, String message) {
    return new CompatibilityFinding(code, severity, message);
  }

  private static List<String> sorted(Collection<String> values) {
    Set<String> sorted = new TreeSet<>();
    for (String value : Objects.requireNonNull(values, "values")) {
      sorted.add(Objects.requireNonNull(value, "values item"));
    }
    return List.copyOf(sorted);
  }

  /**
   * Severity attached to one compatibility verifier finding.
   *
   * <p>The enum values are converted to lowercase JSON strings for CLI output, Platform API review
   * summaries, and release-certification evidence. Callers should use the enum value for control
   * flow and {@link #jsonValue()} only when producing user-visible or machine-readable reports.
   */
  public enum CompatibilityFindingSeverity {
    /**
     * Finding should be reviewed but does not fail non-strict verification.
     *
     * <p>Warnings are used for advisory risks such as deprecated capability use or a target
     * contract newer than the app has declared as tested when the verifier is not running in strict
     * mode.
     */
    WARNING("warning"),

    /**
     * Finding fails strict or release-mode verification.
     *
     * <p>Errors represent malformed or unacceptable compatibility state for the selected mode.
     * Release certification treats these as blockers unless a higher-level workflow explicitly
     * records a waiver.
     */
    ERROR("error");

    private final String jsonValue;

    CompatibilityFindingSeverity(String jsonValue) {
      this.jsonValue = jsonValue;
    }

    /**
     * Returns the stable JSON/CLI severity label.
     *
     * @return lowercase severity value
     */
    public String jsonValue() {
      return jsonValue;
    }
  }

  /**
   * One compatibility verifier finding.
   *
   * <p>A finding is both human-readable and machine-readable. The {@code code} field is stable for
   * tests, CLI filtering, and release evidence, while {@code message} is phrased for app authors
   * and operators. Findings are immutable and trim their text fields during construction.
   *
   * @param code stable machine-readable finding code such as {@code unknown_manifest_permission}
   * @param severity warning or error severity selected for the verifier mode
   * @param message human-readable diagnostic text suitable for CLI and review UI display
   */
  public record CompatibilityFinding(
      String code, CompatibilityFindingSeverity severity, String message) {
    /**
     * Creates a normalized finding.
     *
     * <p>Blank codes and messages are rejected so downstream JSON reports are useful without extra
     * validation. The constructor does not reinterpret severity; callers choose warning or error
     * before creating the finding.
     */
    public CompatibilityFinding {
      code = Objects.requireNonNull(code, "code").trim();
      if (code.isEmpty()) {
        throw new IllegalArgumentException("code must not be blank");
      }
      Objects.requireNonNull(severity, "severity");
      message = Objects.requireNonNull(message, "message").trim();
      if (message.isEmpty()) {
        throw new IllegalArgumentException("message must not be blank");
      }
    }

    /**
     * Converts this finding to a JSON-compatible map.
     *
     * <p>The map uses stable field names and insertion order. It is suitable for direct use with
     * the Platform API JSON writer and for embedding in release-certification evidence.
     *
     * @return deterministic finding map containing code, severity, and message
     */
    public Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put("code", code);
      json.put("severity", severity.jsonValue());
      json.put("message", message);
      return json;
    }
  }

  /**
   * Aggregate compatibility verification result.
   *
   * <p>The result keeps every finding rather than stopping at the first error. Developer tooling
   * can therefore show all obvious compatibility problems in one run, and release certification can
   * record the complete evidence set for first-party apps.
   *
   * @param findings deterministic verifier findings produced by one verification pass
   */
  public record CompatibilityVerificationResult(List<CompatibilityFinding> findings) {
    /**
     * Creates an immutable verification result.
     *
     * <p>The supplied list is copied in its current order. Callers should pass
     * already-deterministic findings when stable JSON output matters.
     */
    public CompatibilityVerificationResult {
      findings = List.copyOf(Objects.requireNonNull(findings, "findings"));
    }

    /**
     * Returns whether verification produced any error findings.
     *
     * <p>Warnings never make this method return {@code true}. That distinction lets non-strict
     * install/update review surface compatibility risks without forcing the caller into failure
     * behavior.
     *
     * @return {@code true} when at least one error finding exists
     */
    public boolean hasErrors() {
      return findings.stream()
          .anyMatch(finding -> finding.severity() == CompatibilityFindingSeverity.ERROR);
    }

    /**
     * Returns all finding messages in deterministic order.
     *
     * <p>This convenience projection is used by concise Platform API summaries where the full code
     * and severity structure would be too large for install-review panels.
     *
     * @return immutable diagnostic messages in the same order as {@link #findings()}
     */
    public List<String> messages() {
      return findings.stream().map(CompatibilityFinding::message).toList();
    }

    /**
     * Converts this result to a JSON-compatible object.
     *
     * <p>The object contains an {@code ok} boolean, an error count, and the complete finding list.
     * That shape is compact enough for CLI output while preserving the information release tooling
     * needs for blocking decisions.
     *
     * @return deterministic verification result map suitable for CLI and release evidence
     */
    public Map<String, Object> toJsonValue() {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put("ok", !hasErrors());
      json.put(
          "errors",
          findings.stream()
              .filter(finding -> finding.severity() == CompatibilityFindingSeverity.ERROR)
              .count());
      json.put("findings", findings.stream().map(CompatibilityFinding::toJsonValue).toList());
      return json;
    }
  }
}
