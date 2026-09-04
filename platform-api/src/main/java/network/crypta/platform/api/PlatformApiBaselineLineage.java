package network.crypta.platform.api;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Records one append-only lifecycle transition for an immutable baseline definition.
 *
 * <p>Membership never changes through this record. Instead, each transition binds the definition
 * digest, a closed lifecycle state, evidence provenance, and the preceding transition digest. A
 * registry validates the resulting gap-free chain and legal state progression. Activation and
 * support coordinates are carried only when the lifecycle state and evidence kind permit them.
 *
 * <p>Fixture evidence cannot establish runtime support. The imported-frozen evidence kind is
 * reserved for the existing {@code 1.0} bootstrap, while a future operational activation requires
 * protected release, build, and support-start coordinates. Instances are immutable and safe to
 * retain as authenticated contract history subjects.
 *
 * @param baselineId the baseline whose immutable definition advances state
 * @param definitionDigest the exact definition digest bound by this transition
 * @param status the closed lifecycle state established by the evidence
 * @param evidenceKind the provenance boundary for the transition evidence
 * @param evidenceDigest the lowercase SHA-256 digest of the exact evidence
 * @param activationRelease the activating daemon release, when operationally active
 * @param activationBuild the positive activating daemon build, when operationally active
 * @param supportStartedRelease the release where the support promise began
 * @param supportEndedRelease the release where support ended, only at end-of-support
 * @param previousLineageDigest the prior transition digest, or {@code null} for genesis
 * @param lineageDigest the canonical self-digest of this complete transition
 */
public record PlatformApiBaselineLineage(
    PlatformApiBaselineId baselineId,
    String definitionDigest,
    PlatformApiBaselineStatus status,
    PlatformApiBaselineEvidenceKind evidenceKind,
    String evidenceDigest,
    String activationRelease,
    Integer activationBuild,
    String supportStartedRelease,
    String supportEndedRelease,
    String previousLineageDigest,
    String lineageDigest) {
  private static final Pattern RELEASE_ID_PATTERN =
      Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");

  /**
   * Creates and verifies one lifecycle record.
   *
   * <p>The canonical constructor is intended for persisted input because it checks the supplied
   * self-digest. Producers should normally call {@link #create}. Validation also enforces canonical
   * release identifiers, positive activation builds, lifecycle-specific coordinate presence, and
   * the restricted frozen-import evidence shape. Digest validation establishes internal binding; it
   * does not authenticate the evidence bytes or protected workflow receipt.
   *
   * @throws NullPointerException if a required identity, state, kind, or digest is {@code null}
   * @throws IllegalArgumentException if evidence, support coordinates, or the self-digest are
   *     inconsistent
   */
  public PlatformApiBaselineLineage {
    Objects.requireNonNull(baselineId, "baselineId");
    definitionDigest =
        PlatformApiBaselineDigest.requireSha256(definitionDigest, "definitionDigest");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(evidenceKind, "evidenceKind");
    evidenceDigest = PlatformApiBaselineDigest.requireSha256(evidenceDigest, "evidenceDigest");
    activationRelease = optionalReleaseId(activationRelease, "activationRelease");
    supportStartedRelease = optionalReleaseId(supportStartedRelease, "supportStartedRelease");
    supportEndedRelease = optionalReleaseId(supportEndedRelease, "supportEndedRelease");
    previousLineageDigest = optionalPreviousLineageDigest(previousLineageDigest);
    if (activationBuild != null && activationBuild <= 0) {
      throw new IllegalArgumentException("activationBuild must be positive when present");
    }
    requireEvidenceBoundary(
        baselineId,
        definitionDigest,
        status,
        evidenceKind,
        evidenceDigest,
        activationRelease,
        activationBuild,
        supportStartedRelease,
        supportEndedRelease);
    lineageDigest = PlatformApiBaselineDigest.requireSha256(lineageDigest, "lineageDigest");
    String expected =
        computeDigest(
            baselineId,
            definitionDigest,
            status,
            evidenceKind,
            evidenceDigest,
            activationRelease,
            activationBuild,
            supportStartedRelease,
            supportEndedRelease,
            previousLineageDigest);
    if (!lineageDigest.equals(expected)) {
      throw new IllegalArgumentException("lineageDigest does not match lifecycle record");
    }
  }

  /**
   * Creates a lifecycle record and computes its canonical self-digest.
   *
   * <p>This method enforces the evidence boundary for the requested state, but the enclosing
   * registry remains responsible for validating predecessor links and legal state transitions.
   * Callers must supply the exact preceding lineage digest when appending to an existing baseline.
   * Release certification remains responsible for authenticating protected evidence coordinates;
   * this factory only canonicalizes and binds their declared values.
   *
   * @param baselineId the baseline whose lifecycle is changing
   * @param definitionDigest the exact immutable definition digest
   * @param status the lifecycle state established by this evidence
   * @param evidenceKind the closed provenance classification
   * @param evidenceDigest the exact evidence's lowercase SHA-256 digest
   * @param activationRelease the activating release ID, or {@code null} before activation
   * @param activationBuild the activating positive build, or {@code null} before activation
   * @param supportStartedRelease the release starting support, or {@code null} before support
   * @param supportEndedRelease the ending release, only for end-of-support
   * @param previousLineageDigest the preceding transition digest, or {@code null} at genesis
   * @return a verified immutable transition with its canonical self-digest
   * @throws IllegalArgumentException if the requested evidence and state are inconsistent
   */
  public static PlatformApiBaselineLineage create(
      PlatformApiBaselineId baselineId,
      String definitionDigest,
      PlatformApiBaselineStatus status,
      PlatformApiBaselineEvidenceKind evidenceKind,
      String evidenceDigest,
      String activationRelease,
      Integer activationBuild,
      String supportStartedRelease,
      String supportEndedRelease,
      String previousLineageDigest) {
    String digest =
        computeDigest(
            baselineId,
            definitionDigest,
            status,
            evidenceKind,
            evidenceDigest,
            activationRelease,
            activationBuild,
            supportStartedRelease,
            supportEndedRelease,
            previousLineageDigest);
    return new PlatformApiBaselineLineage(
        baselineId,
        definitionDigest,
        status,
        evidenceKind,
        evidenceDigest,
        activationRelease,
        activationBuild,
        supportStartedRelease,
        supportEndedRelease,
        previousLineageDigest,
        digest);
  }

  private static void requireEvidenceBoundary(
      PlatformApiBaselineId baselineId,
      String definitionDigest,
      PlatformApiBaselineStatus status,
      PlatformApiBaselineEvidenceKind evidenceKind,
      String evidenceDigest,
      String activationRelease,
      Integer activationBuild,
      String supportStartedRelease,
      String supportEndedRelease) {
    if (evidenceKind == PlatformApiBaselineEvidenceKind.FIXTURE
        && (status.isSupported() || status == PlatformApiBaselineStatus.END_OF_SUPPORT)) {
      throw new IllegalArgumentException(
          "fixture evidence cannot establish an operational baseline lifecycle state");
    }
    if (evidenceKind == PlatformApiBaselineEvidenceKind.IMPORTED_FROZEN_BASELINE
        && (!baselineId.equals(new PlatformApiBaselineId(1, 0))
            || status != PlatformApiBaselineStatus.ACTIVE
            || !PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_DEFINITION_SHA256.equals(
                definitionDigest)
            || !PlatformApiBaselineRegistry.PLATFORM_API_1_0_FROZEN_ARTIFACT_SHA256.equals(
                evidenceDigest))) {
      throw new IllegalArgumentException(
          "imported Platform API 1.0 evidence must exactly match the frozen authority");
    }
    if (status.isSupported()
        && evidenceKind == PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE
        && (activationRelease == null || activationBuild == null || supportStartedRelease == null)
        && !isFrozen10DeprecationWithoutImportedActivationCoordinates(
            baselineId, status, activationRelease, activationBuild, supportStartedRelease)) {
      throw new IllegalArgumentException(
          "protected activation requires release, build, and support-start evidence");
    }
    if (status == PlatformApiBaselineStatus.END_OF_SUPPORT && supportEndedRelease == null) {
      throw new IllegalArgumentException("end-of-support requires supportEndedRelease");
    }
    if (status != PlatformApiBaselineStatus.END_OF_SUPPORT && supportEndedRelease != null) {
      throw new IllegalArgumentException("supportEndedRelease is valid only at end-of-support");
    }
  }

  private static boolean isFrozen10DeprecationWithoutImportedActivationCoordinates(
      PlatformApiBaselineId baselineId,
      PlatformApiBaselineStatus status,
      String activationRelease,
      Integer activationBuild,
      String supportStartedRelease) {
    return baselineId.equals(new PlatformApiBaselineId(1, 0))
        && status == PlatformApiBaselineStatus.DEPRECATED
        && activationRelease == null
        && activationBuild == null
        && supportStartedRelease == null;
  }

  private static String computeDigest(
      PlatformApiBaselineId baselineId,
      String definitionDigest,
      PlatformApiBaselineStatus status,
      PlatformApiBaselineEvidenceKind evidenceKind,
      String evidenceDigest,
      String activationRelease,
      Integer activationBuild,
      String supportStartedRelease,
      String supportEndedRelease,
      String previousLineageDigest) {
    StringBuilder canonical = new StringBuilder("platform-api-baseline-lineage-v1;");
    PlatformApiBaselineDigest.append(
        canonical, Objects.requireNonNull(baselineId, "baselineId").toString());
    PlatformApiBaselineDigest.append(canonical, definitionDigest);
    PlatformApiBaselineDigest.append(
        canonical, Objects.requireNonNull(status, "status").jsonValue());
    PlatformApiBaselineDigest.append(
        canonical, Objects.requireNonNull(evidenceKind, "evidenceKind").jsonValue());
    PlatformApiBaselineDigest.append(canonical, evidenceDigest);
    PlatformApiBaselineDigest.append(canonical, activationRelease);
    PlatformApiBaselineDigest.append(
        canonical, activationBuild == null ? null : Integer.toString(activationBuild));
    PlatformApiBaselineDigest.append(canonical, supportStartedRelease);
    PlatformApiBaselineDigest.append(canonical, supportEndedRelease);
    PlatformApiBaselineDigest.append(canonical, previousLineageDigest);
    return PlatformApiBaselineDigest.sha256(canonical.toString());
  }

  private static String optionalReleaseId(String value, String fieldName) {
    if (value == null) {
      return null;
    }
    if (!RELEASE_ID_PATTERN.matcher(value).matches()) {
      throw new IllegalArgumentException(fieldName + " must be a canonical release ID");
    }
    return value;
  }

  private static String optionalPreviousLineageDigest(String value) {
    return value == null
        ? null
        : PlatformApiBaselineDigest.requireSha256(value, "previousLineageDigest");
  }
}
