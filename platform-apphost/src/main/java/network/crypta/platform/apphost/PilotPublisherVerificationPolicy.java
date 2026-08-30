package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Constructs an app-id-aware verification policy for one isolated external-publisher pilot.
 *
 * <p>The ordinary {@link TrustedAppKeys} registry intentionally answers only whether a public key
 * can verify a bundle. A pilot requires a narrower decision: one protected approval authorizes one
 * publisher for one app and an exact set of versions and signature-sidecar digests. The policy
 * applies that subject boundary only after the standard verifier authenticates the signature and
 * every signed payload digest.
 *
 * <p>Construction binds the expected pilot and node identities, the approval validity window, and
 * the exact normal, catalog, and pilot registry digests. It rejects key-ID or public-key overlap
 * between those roles and requires the dedicated pilot registry to contain only the approved key.
 * Bundles signed by other keys continue through ordinary Stable verification.
 *
 * <p>The result is an immutable in-memory snapshot. This class neither parses approval JSON nor
 * writes registries, persists keys, or accepts private material. Approval time is checked again at
 * each install, update, launch, and rollback verification.
 */
public final class PilotPublisherVerificationPolicy {
  private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
  private static final Pattern DIGEST = Pattern.compile("sha256:[0-9a-f]{64}");

  private PilotPublisherVerificationPolicy() {}

  /**
   * Creates a bounded signed-bundle policy using the system UTC clock.
   *
   * <p>Creation validates both expected identities, compares all registry roots with the approval,
   * enforces pairwise role separation, and authenticates the approved publisher fingerprint. The
   * returned policy routes bundles bearing that publisher key through the exact app, version, and
   * sidecar checks. Bundles bearing any other key continue through the ordinary Stable registry.
   * The approval window is evaluated against UTC whenever a bundle is verified, not only when the
   * policy is created.
   *
   * @param expectedPilotId protected pilot identity for this runtime job
   * @param expectedPilotNodeId protected isolated-node identity for this runtime job
   * @param approval authenticated public projection of the pilot publisher-key approval receipt
   * @param registries exact normal, catalog, and pilot registry snapshots and authenticated digests
   * @return signed-install policy restricted to approved app versions and signature sidecars
   * @throws IOException if the approval or any registry binding is invalid or inconsistent
   * @throws NullPointerException if {@code approval} or {@code registries} is {@code null}
   * @throws IllegalArgumentException if either expected identity is missing or malformed
   */
  public static AppInstallVerificationPolicy create(
      String expectedPilotId, String expectedPilotNodeId, Approval approval, Registries registries)
      throws IOException {
    return create(expectedPilotId, expectedPilotNodeId, approval, registries, Clock.systemUTC());
  }

  static AppInstallVerificationPolicy create(
      String expectedPilotId,
      String expectedPilotNodeId,
      Approval approval,
      Registries registries,
      Clock clock)
      throws IOException {
    Approval checkedApproval = Objects.requireNonNull(approval, "approval");
    Registries checkedRegistries = Objects.requireNonNull(registries, "registries");
    TrustedAppKeys checkedNormalKeys = checkedRegistries.normalStableKeys();
    TrustedAppKeys checkedCatalogKeys = checkedRegistries.catalogKeys();
    TrustedAppKeys checkedPilotKeys = checkedRegistries.pilotKeys();
    Clock checkedClock = Objects.requireNonNull(clock, "clock");
    String checkedPilotId = requireIdentifier(expectedPilotId, "expectedPilotId");
    String checkedNodeId = requireIdentifier(expectedPilotNodeId, "expectedPilotNodeId");
    if (!checkedApproval.pilotId().equals(checkedPilotId)) {
      throw new AppHostConfigurationException("pilot publisher approval is bound to another pilot");
    }
    if (!checkedApproval.pilotNodeId().equals(checkedNodeId)) {
      throw new AppHostConfigurationException(
          "pilot publisher approval is bound to another pilot node");
    }
    if (!checkedApproval
        .normalStableRegistryDigest()
        .equals(checkedRegistries.normalStableRegistryDigest())) {
      throw new AppHostConfigurationException(
          "normal Stable registry digest differs from the pilot approval");
    }
    if (!checkedApproval
        .catalogRegistryDigest()
        .equals(checkedRegistries.catalogRegistryDigest())) {
      throw new AppHostConfigurationException("catalog registry digest differs from the approval");
    }
    if (!checkedApproval.pilotRegistryDigest().equals(checkedRegistries.pilotRegistryDigest())) {
      throw new AppHostConfigurationException("pilot registry digest differs from the approval");
    }
    checkedNormalKeys.requireDisjointFrom(checkedCatalogKeys);
    checkedNormalKeys.requireDisjointFrom(checkedPilotKeys);
    checkedCatalogKeys.requireDisjointFrom(checkedPilotKeys);
    if (!checkedPilotKeys.keyIds().equals(Set.of(checkedApproval.publisherKeyId()))) {
      throw new AppHostConfigurationException(
          "pilot registry must contain only the approved external publisher key");
    }
    TrustedAppKey publisherKey =
        checkedPilotKeys
            .findActiveForVerification(checkedApproval.publisherKeyId(), checkedClock.instant())
            .orElseThrow(
                () ->
                    new AppHostConfigurationException(
                        "pilot registry omits the approved external publisher key"));
    String actualFingerprint = sha256(publisherKey.publicKey().getEncoded());
    if (!actualFingerprint.equals(checkedApproval.publisherFingerprintSha256())) {
      throw new AppHostConfigurationException(
          "pilot registry publisher fingerprint differs from the approval");
    }
    requireApprovalActive(checkedApproval, checkedClock.instant());
    AppBundleVerifier normalNewBundleVerifier = AppBundleVerifier.requireSigned(checkedNormalKeys);
    AppBundleVerifier normalHistoricalVerifier =
        AppBundleVerifier.requireSignedForHistoricalVerification(checkedNormalKeys);
    AppBundleVerifier pilotNewBundleVerifier = AppBundleVerifier.requireSigned(checkedPilotKeys);
    AppBundleVerifier pilotHistoricalVerifier =
        AppBundleVerifier.requireSignedForHistoricalVerification(checkedPilotKeys);
    return AppInstallVerificationPolicy.requireSignedWithIdentity(
        bundleRoot ->
            verifyBundle(
                bundleRoot,
                checkedApproval,
                normalNewBundleVerifier,
                pilotNewBundleVerifier,
                checkedClock.instant()),
        bundleRoot ->
            verifyBundle(
                bundleRoot,
                checkedApproval,
                normalHistoricalVerifier,
                pilotHistoricalVerifier,
                checkedClock.instant()));
  }

  private static AppBundleVerification verifyBundle(
      Path bundleRoot,
      Approval approval,
      AppBundleVerifier normalVerifier,
      AppBundleVerifier pilotVerifier,
      Instant verifiedAt)
      throws IOException {
    AppBundleSignature signature =
        AppBundleVerifier.read(bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
    if (approval.publisherKeyId().equals(signature.keyId())) {
      return verifyApprovedBundle(bundleRoot, approval, pilotVerifier, verifiedAt);
    }
    return normalVerifier.verify(bundleRoot);
  }

  private static AppBundleVerification verifyApprovedBundle(
      Path bundleRoot, Approval approval, AppBundleVerifier verifier, Instant verifiedAt)
      throws IOException {
    requireApprovalActive(approval, verifiedAt);
    AppBundleVerification verification = verifier.verify(bundleRoot);
    if (!verification.signed() || !approval.publisherKeyId().equals(verification.keyId())) {
      throw new AppDistributionException(
          "bundle is not signed by the pilot-approved external publisher");
    }
    AppBundleManifest manifest =
        AppBundleManifestParser.parse(
            bundleRoot.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME));
    if (!approval.appId().equals(manifest.appId())) {
      throw new AppDistributionException("pilot publisher approval does not authorize this app id");
    }
    Subject subject = approval.subjectsByVersion().get(manifest.appVersion());
    if (subject == null) {
      throw new AppDistributionException(
          "pilot publisher approval does not authorize this app version");
    }
    Path signatureFile = bundleRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME);
    String signatureDigest = sha256(Files.readAllBytes(signatureFile));
    if (!subject.bundleSignatureDigest().equals(signatureDigest)) {
      throw new AppDistributionException(
          "bundle signature sidecar differs from the pilot-approved subject");
    }
    return verification;
  }

  private static void requireApprovalActive(Approval approval, Instant instant)
      throws AppHostConfigurationException {
    if (approval.revoked()
        || instant.isBefore(approval.validFrom())
        || !instant.isBefore(approval.validUntil())) {
      throw new AppHostConfigurationException(
          "pilot publisher approval is revoked or outside its validity window");
    }
  }

  private static String sha256(byte[] value) {
    if (value == null || value.length == 0) {
      throw new IllegalArgumentException("public or sidecar bytes must not be empty");
    }
    try {
      return "sha256:"
          + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String requireIdentifier(String value, String field) {
    if (value == null || !IDENTIFIER.matcher(value).matches()) {
      throw new IllegalArgumentException(field + " is missing or malformed");
    }
    return value;
  }

  private static void requireDigest(String value, String field) {
    if (value == null || !DIGEST.matcher(value).matches()) {
      throw new IllegalArgumentException(field + " must be a canonical SHA-256 digest");
    }
  }

  /**
   * Runtime-safe projection of an authenticated pilot publisher-key approval receipt.
   *
   * <p>Only bounded public metadata is represented. The receipt signature, handoff digest, catalog
   * authority, and protected-workflow coordinates remain certification evidence; the runtime needs
   * only the exact subject and validity constraints listed here. Construction validates canonical
   * identifiers and SHA-256 digests, requires a nonempty validity window, and copies the subject
   * collection into an immutable list with one entry per version.
   *
   * <p>This projection does not grant trust by itself. {@link
   * PilotPublisherVerificationPolicy#create(String, String, Approval, Registries)} compares it with
   * independently captured registry snapshots, confirms the publisher fingerprint, and evaluates
   * revocation and time before returning an installation policy.
   *
   * @param pilotId protected pilot identity
   * @param pilotNodeId isolated node identity authorized to use the approval
   * @param appId only app id the external key may authorize
   * @param publisherKeyId external signature key id expected in bundle sidecars
   * @param publisherFingerprintSha256 SHA-256 of the canonical X.509 public key encoding
   * @param normalStableRegistryDigest SHA-256 of the exact normal Stable registry bytes
   * @param catalogRegistryDigest SHA-256 of the exact PR-293 catalog registry bytes
   * @param pilotRegistryDigest SHA-256 of the exact dedicated pilot registry bytes
   * @param validFrom inclusive approval start
   * @param validUntil exclusive approval expiry
   * @param revoked whether protected authority revoked this approval
   * @param subjects exact allowed app-version and signature-sidecar subjects
   */
  public record Approval(
      String pilotId,
      String pilotNodeId,
      String appId,
      String publisherKeyId,
      String publisherFingerprintSha256,
      String normalStableRegistryDigest,
      String catalogRegistryDigest,
      String pilotRegistryDigest,
      Instant validFrom,
      Instant validUntil,
      boolean revoked,
      Collection<Subject> subjects) {
    /**
     * Creates a validated immutable approval projection.
     *
     * <p>All identities must use the bounded runtime identifier syntax, all fingerprints and roots
     * must be canonical SHA-256 values, and the exclusive expiry must follow the inclusive start.
     * The constructor defensively copies the subject collection and rejects null entries, an empty
     * collection, or more than one subject for the same app version.
     *
     * @param pilotId protected pilot identity bound to this approval
     * @param pilotNodeId isolated node identity authorized to use this approval
     * @param appId only application identity the external publisher may authorize
     * @param publisherKeyId external signing-key identity expected in bundle sidecars
     * @param publisherFingerprintSha256 digest of the canonical publisher public-key encoding
     * @param normalStableRegistryDigest digest of the exact ordinary Stable registry bytes
     * @param catalogRegistryDigest digest of the exact catalog-authority registry bytes
     * @param pilotRegistryDigest digest of the exact dedicated pilot registry bytes
     * @param validFrom inclusive instant at which the approval becomes usable
     * @param validUntil exclusive instant at which the approval stops being usable
     * @param revoked whether protected authority has revoked this approval
     * @param subjects exact permitted version and signature-sidecar subjects
     * @throws NullPointerException if a required instant, collection, or subject is {@code null}
     * @throws IllegalArgumentException if a value is malformed or the cohort is inconsistent
     */
    public Approval {
      requireIdentifier(pilotId, "pilotId");
      requireIdentifier(pilotNodeId, "pilotNodeId");
      requireIdentifier(appId, "appId");
      requireIdentifier(publisherKeyId, "publisherKeyId");
      requireDigest(publisherFingerprintSha256, "publisherFingerprintSha256");
      requireDigest(normalStableRegistryDigest, "normalStableRegistryDigest");
      requireDigest(catalogRegistryDigest, "catalogRegistryDigest");
      requireDigest(pilotRegistryDigest, "pilotRegistryDigest");
      Objects.requireNonNull(validFrom, "validFrom");
      Objects.requireNonNull(validUntil, "validUntil");
      if (!validFrom.isBefore(validUntil)) {
        throw new IllegalArgumentException("pilot approval validity window is empty");
      }
      Objects.requireNonNull(subjects, "subjects");
      if (subjects.isEmpty()) {
        throw new IllegalArgumentException("pilot approval must authorize at least one subject");
      }
      subjects = List.copyOf(subjects);
      Map<String, Subject> uniqueVersions = new LinkedHashMap<>();
      for (Subject subject : subjects) {
        Objects.requireNonNull(subject, "subject");
        Subject previous = uniqueVersions.putIfAbsent(subject.appVersion(), subject);
        if (previous != null) {
          throw new IllegalArgumentException(
              "duplicate pilot approval app version: " + subject.appVersion());
        }
      }
    }

    private Map<String, Subject> subjectsByVersion() {
      Map<String, Subject> byVersion = new LinkedHashMap<>();
      for (Subject subject : subjects) {
        Subject previous = byVersion.putIfAbsent(subject.appVersion(), subject);
        if (previous != null) {
          throw new IllegalArgumentException(
              "duplicate pilot approval app version: " + subject.appVersion());
        }
      }
      return Map.copyOf(byVersion);
    }
  }

  /**
   * Exact public-key registry snapshots supplied to an isolated pilot runtime.
   *
   * <p>The digest values are authenticated by the approval and represent SHA-256 over the exact
   * configured registry file bytes. The runtime configuration loader computes them before creating
   * this record. Keeping all three registries separate preserves role isolation while dispatching
   * only the approved external key to the narrower app/version/sidecar checks.
   *
   * <p>The record validates non-null registries and canonical digest syntax but does not read or
   * hash registry files. The runtime loader must derive each key set and digest from the same
   * captured bytes. Policy construction subsequently compares these roots with the approval and
   * rejects overlapping key IDs or public keys.
   *
   * @param normalStableKeys ordinary Stable app-bundle trust registry
   * @param normalStableRegistryDigest digest of the exact normal registry bytes
   * @param catalogKeys PR-293 catalog-signing trust registry
   * @param catalogRegistryDigest digest of the exact catalog registry bytes
   * @param pilotKeys dedicated registry containing only the approved external publisher key
   * @param pilotRegistryDigest digest of the exact pilot registry bytes
   */
  public record Registries(
      TrustedAppKeys normalStableKeys,
      String normalStableRegistryDigest,
      TrustedAppKeys catalogKeys,
      String catalogRegistryDigest,
      TrustedAppKeys pilotKeys,
      String pilotRegistryDigest) {
    /**
     * Creates validated immutable registry bindings.
     *
     * <p>The constructor retains the supplied {@link TrustedAppKeys} snapshots and validates each
     * digest's canonical form. It does not compare the registries with an approval or establish
     * role separation; those checks occur when the verification policy is created.
     *
     * @param normalStableKeys ordinary Stable app-publisher key snapshot
     * @param normalStableRegistryDigest digest of the exact ordinary registry bytes
     * @param catalogKeys catalog-authority signing-key snapshot
     * @param catalogRegistryDigest digest of the exact catalog registry bytes
     * @param pilotKeys dedicated external-publisher key snapshot
     * @param pilotRegistryDigest digest of the exact dedicated pilot registry bytes
     * @throws NullPointerException if any trusted-key snapshot is {@code null}
     * @throws IllegalArgumentException if any registry digest is not canonical SHA-256
     */
    public Registries {
      Objects.requireNonNull(normalStableKeys, "normalStableKeys");
      requireDigest(normalStableRegistryDigest, "normalStableRegistryDigest");
      Objects.requireNonNull(catalogKeys, "catalogKeys");
      requireDigest(catalogRegistryDigest, "catalogRegistryDigest");
      Objects.requireNonNull(pilotKeys, "pilotKeys");
      requireDigest(pilotRegistryDigest, "pilotRegistryDigest");
    }
  }

  /**
   * Exact extracted-bundle subject allowed by one pilot approval.
   *
   * <p>A subject binds one manifest version to the SHA-256 digest of its complete detached
   * signature sidecar. The containing {@link Approval} supplies the app ID and publisher identity,
   * so this record cannot authorize a different app or signing key on its own. Subject matching is
   * exact and does not interpret version ordering, ranges, or mutable aliases.
   *
   * @param appVersion exact manifest version
   * @param bundleSignatureDigest SHA-256 of the exact {@code cryptad-app.signature} bytes
   */
  public record Subject(String appVersion, String bundleSignatureDigest) {
    /**
     * Creates a validated exact bundle subject.
     *
     * <p>The version must satisfy the bounded identifier syntax and the sidecar digest must use the
     * canonical lowercase SHA-256 representation. Cohort-level duplicate-version checks are
     * performed by the enclosing {@link Approval} constructor.
     *
     * @param appVersion exact manifest version accepted by the approval
     * @param bundleSignatureDigest digest of the exact detached signature-sidecar bytes
     * @throws IllegalArgumentException if the version or digest is missing or malformed
     */
    public Subject {
      requireIdentifier(appVersion, "appVersion");
      requireDigest(bundleSignatureDigest, "bundleSignatureDigest");
    }
  }
}
