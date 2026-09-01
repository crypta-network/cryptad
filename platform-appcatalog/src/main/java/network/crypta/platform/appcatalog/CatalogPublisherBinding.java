package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.jetbrains.annotations.Nullable;

/**
 * One host-owned authorization for an app publisher in an exact catalog and app namespace.
 *
 * <p>The record authorizes locally known publisher key material; a catalog entry cannot create or
 * expand it. Catalog, app, key fingerprint, channel, validity window, and approval evidence are all
 * part of the self-digested policy. Optional predecessor and successor identifiers describe a
 * bounded key lineage but grant no authority outside the exact catalog and app scope.
 *
 * @param schemaVersion closed persistent-policy schema version
 * @param bindingId stable local identifier for this publisher authorization
 * @param catalogId exact authenticated catalog identifier covered by the binding
 * @param appId exact normalized application namespace covered by the binding
 * @param publisherKeyId locally known publisher public-key identifier
 * @param publisherKeyFingerprintSha256 canonical publisher public-key fingerprint
 * @param status current local lifecycle state of this authorization
 * @param validFrom inclusive beginning of the publisher authorization window
 * @param validUntil exclusive end of the publisher authorization window
 * @param predecessorKeyId optional approved predecessor in the bounded key lineage
 * @param successorKeyId optional approved successor in the bounded key lineage
 * @param allowedChannels catalog channels approved for this publisher
 * @param approvalSource bounded identity of the authenticated approval source
 * @param approvalDigestSha256 exact digest of the authenticated approval evidence
 * @param createdAt timestamp when the local binding was first created
 * @param updatedAt timestamp of the most recent local policy decision
 * @param reason bounded operator-supplied reason for the decision
 * @param operatorId bounded local operator audit identifier
 * @param selfDigest digest binding every preceding policy field
 */
public record CatalogPublisherBinding(
    int schemaVersion,
    String bindingId,
    String catalogId,
    String appId,
    String publisherKeyId,
    String publisherKeyFingerprintSha256,
    Status status,
    Instant validFrom,
    Instant validUntil,
    Optional<String> predecessorKeyId,
    Optional<String> successorKeyId,
    Set<AppCatalogChannel> allowedChannels,
    String approvalSource,
    String approvalDigestSha256,
    Instant createdAt,
    Instant updatedAt,
    String reason,
    String operatorId,
    String selfDigest) {
  /** Closed persistent schema version emitted for newly created publisher bindings. */
  public static final int CURRENT_SCHEMA_VERSION = 1;

  /** Local lifecycle for a scoped publisher authorization. */
  public enum Status {
    /** Awaiting an explicit local approval decision. */
    PENDING,
    /** Authorizes routine work within the exact scope and validity window. */
    ACTIVE,
    /** Blocks routine work while preserving bounded historical inspection. */
    SUSPENDED,
    /** Permanently blocks routine and historical publisher authorization. */
    REVOKED,
    /** Retains an audit tombstone without granting authorization. */
    REMOVED;

    /**
     * Parses a persisted case-insensitive lifecycle value.
     *
     * @param value persisted lifecycle text
     * @return parsed closed lifecycle status
     */
    static Status parse(String value) {
      try {
        return valueOf(value.toUpperCase(Locale.ROOT));
      } catch (RuntimeException exception) {
        throw FederatedPolicyRecordSupport.invalid("invalid publisher binding status", exception);
      }
    }
  }

  /** Validates and normalizes this immutable local policy record. */
  public CatalogPublisherBinding {
    if (schemaVersion != CURRENT_SCHEMA_VERSION) {
      throw FederatedPolicyRecordSupport.invalid("unsupported publisher binding schema version");
    }
    bindingId =
        FederatedPolicyRecordSupport.requireId(
            bindingId, "publisher binding id", FederatedPolicyRecordSupport.LOCAL_ID);
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    appId = AppCatalogEntry.normalizeAppId(appId);
    publisherKeyId =
        FederatedPolicyRecordSupport.requireId(
            publisherKeyId, "publisher key id", FederatedPolicyRecordSupport.KEY_ID);
    publisherKeyFingerprintSha256 =
        FederatedPolicyRecordSupport.requireDigest(
            publisherKeyFingerprintSha256, "publisher key fingerprint");
    Objects.requireNonNull(status, "status");
    Objects.requireNonNull(validFrom, "validFrom");
    Objects.requireNonNull(validUntil, "validUntil");
    if (!validFrom.isBefore(validUntil)) {
      throw FederatedPolicyRecordSupport.invalid(
          "publisher binding validFrom must precede validUntil");
    }
    predecessorKeyId =
        normalizeLineage(
            Objects.requireNonNull(predecessorKeyId, "predecessorKeyId").orElse(null),
            "predecessor key id",
            publisherKeyId);
    successorKeyId =
        normalizeLineage(
            Objects.requireNonNull(successorKeyId, "successorKeyId").orElse(null),
            "successor key id",
            publisherKeyId);
    allowedChannels = Set.copyOf(Objects.requireNonNull(allowedChannels, "allowedChannels"));
    if (allowedChannels.isEmpty()) {
      throw FederatedPolicyRecordSupport.invalid(
          "publisher binding must allow at least one channel");
    }
    approvalSource =
        FederatedPolicyRecordSupport.requireText(approvalSource, "approval source", 128);
    approvalDigestSha256 =
        FederatedPolicyRecordSupport.requireDigest(approvalDigestSha256, "approval digest");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    if (updatedAt.isBefore(createdAt)) {
      throw FederatedPolicyRecordSupport.invalid("publisher binding updatedAt precedes createdAt");
    }
    reason = FederatedPolicyRecordSupport.requireText(reason, "reason", 512);
    operatorId = FederatedPolicyRecordSupport.requireText(operatorId, "operator id", 128);
    String computed =
        FederatedPolicyRecordSupport.digest(
            canonicalWithoutDigest(
                schemaVersion,
                bindingId,
                catalogId,
                appId,
                publisherKeyId,
                publisherKeyFingerprintSha256,
                status,
                validFrom,
                validUntil,
                predecessorKeyId.orElse(null),
                successorKeyId.orElse(null),
                allowedChannels,
                approvalSource,
                approvalDigestSha256,
                createdAt,
                updatedAt,
                reason,
                operatorId));
    if (selfDigest == null || selfDigest.isBlank()) {
      selfDigest = computed;
    } else if (!computed.equals(
        FederatedPolicyRecordSupport.requireDigest(selfDigest, "publisher binding self-digest"))) {
      throw FederatedPolicyRecordSupport.invalid("publisher binding self-digest mismatch");
    }
  }

  /**
   * Creates a binding while deriving its exact self-digest.
   *
   * @param bindingId stable local binding identifier
   * @param catalogId exact authenticated catalog identifier
   * @param appId exact normalized application namespace
   * @param publisherKeyId locally known publisher key identifier
   * @param publisherKeyFingerprintSha256 canonical publisher key fingerprint
   * @param status initial local lifecycle status
   * @param validFrom inclusive authorization start instant
   * @param validUntil exclusive authorization end instant
   * @param predecessorKeyId optional bounded predecessor key identifier
   * @param successorKeyId optional bounded successor key identifier
   * @param allowedChannels nonempty locally approved catalog channels
   * @param approvalSource bounded authenticated approval source identity
   * @param approvalDigestSha256 exact digest of approval evidence
   * @param createdAt local binding creation timestamp
   * @param updatedAt latest local policy-decision timestamp
   * @param reason bounded operator audit reason
   * @param operatorId bounded local operator identifier
   * @return immutable self-digested publisher binding
   */
  public static CatalogPublisherBinding create(
      String bindingId,
      String catalogId,
      String appId,
      String publisherKeyId,
      String publisherKeyFingerprintSha256,
      Status status,
      Instant validFrom,
      Instant validUntil,
      @Nullable String predecessorKeyId,
      @Nullable String successorKeyId,
      Set<AppCatalogChannel> allowedChannels,
      String approvalSource,
      String approvalDigestSha256,
      Instant createdAt,
      Instant updatedAt,
      String reason,
      String operatorId) {
    return new CatalogPublisherBinding(
        CURRENT_SCHEMA_VERSION,
        bindingId,
        catalogId,
        appId,
        publisherKeyId,
        publisherKeyFingerprintSha256,
        status,
        validFrom,
        validUntil,
        Optional.ofNullable(predecessorKeyId),
        Optional.ofNullable(successorKeyId),
        allowedChannels,
        approvalSource,
        approvalDigestSha256,
        createdAt,
        updatedAt,
        reason,
        operatorId,
        null);
  }

  /**
   * Returns whether this binding authorizes one exact routine publisher decision.
   *
   * @param requestedCatalogId catalog requesting publisher authorization
   * @param requestedAppId application namespace requesting authorization
   * @param requestedKeyId verified bundle-signature key identifier
   * @param requestedFingerprint canonical verified publisher fingerprint
   * @param channel authenticated catalog channel
   * @param now local routine-verification instant
   * @return {@code true} when every scope, lifecycle, and validity constraint matches
   */
  public boolean authorizes(
      String requestedCatalogId,
      String requestedAppId,
      String requestedKeyId,
      String requestedFingerprint,
      AppCatalogChannel channel,
      Instant now) {
    Instant checkedNow = Objects.requireNonNull(now, "now");
    return status == Status.ACTIVE
        && catalogId.equals(AppCatalog.normalizeCatalogId(requestedCatalogId))
        && appId.equals(AppCatalogEntry.normalizeAppId(requestedAppId))
        && publisherKeyId.equals(requestedKeyId)
        && publisherKeyFingerprintSha256.equals(requestedFingerprint)
        && allowedChannels.contains(channel)
        && !checkedNow.isBefore(validFrom)
        && checkedNow.isBefore(validUntil);
  }

  /**
   * Returns whether this policy still permits inspection of an exact retained historical bundle.
   *
   * <p>Suspension blocks new installs and updates but preserves bounded historical inspection.
   * Revocation, removal, and pending approval fail for both new and historical decisions. The
   * original approval window remains authoritative and lineage metadata never activates another key
   * automatically.
   *
   * @param requestedCatalogId catalog associated with retained provenance
   * @param requestedAppId exact retained application namespace
   * @param requestedKeyId retained bundle-signature key identifier
   * @param requestedFingerprint retained canonical publisher fingerprint
   * @param channel authenticated retained catalog channel
   * @param verifiedAt original authorization or installation instant
   * @return {@code true} when current historical policy permits the exact subject
   */
  public boolean authorizesHistorical(
      String requestedCatalogId,
      String requestedAppId,
      String requestedKeyId,
      String requestedFingerprint,
      AppCatalogChannel channel,
      Instant verifiedAt) {
    Instant checkedAt = Objects.requireNonNull(verifiedAt, "verifiedAt");
    return (status == Status.ACTIVE || status == Status.SUSPENDED)
        && catalogId.equals(AppCatalog.normalizeCatalogId(requestedCatalogId))
        && appId.equals(AppCatalogEntry.normalizeAppId(requestedAppId))
        && publisherKeyId.equals(requestedKeyId)
        && publisherKeyFingerprintSha256.equals(requestedFingerprint)
        && allowedChannels.contains(Objects.requireNonNull(channel, "channel"))
        && !checkedAt.isBefore(validFrom)
        && checkedAt.isBefore(validUntil);
  }

  /**
   * Returns the complete canonical persisted representation including its self-digest.
   *
   * @return deterministic newline-terminated policy text
   */
  String canonicalText() {
    return canonicalWithoutDigest(
            schemaVersion,
            bindingId,
            catalogId,
            appId,
            publisherKeyId,
            publisherKeyFingerprintSha256,
            status,
            validFrom,
            validUntil,
            predecessorKeyId.orElse(null),
            successorKeyId.orElse(null),
            allowedChannels,
            approvalSource,
            approvalDigestSha256,
            createdAt,
            updatedAt,
            reason,
            operatorId)
        + "selfDigest="
        + selfDigest
        + '\n';
  }

  /**
   * Builds canonical policy text excluding the self-digest line.
   *
   * @param schemaVersion closed policy schema version
   * @param bindingId stable local binding identifier
   * @param catalogId exact authenticated catalog identifier
   * @param appId exact normalized application namespace
   * @param publisherKeyId locally known publisher key identifier
   * @param publisherKeyFingerprintSha256 canonical publisher key fingerprint
   * @param status local lifecycle status
   * @param validFrom inclusive authorization start instant
   * @param validUntil exclusive authorization end instant
   * @param predecessorKeyId optional predecessor key identifier
   * @param successorKeyId optional successor key identifier
   * @param allowedChannels locally approved catalog channels
   * @param approvalSource authenticated approval source identity
   * @param approvalDigestSha256 exact approval evidence digest
   * @param createdAt local binding creation timestamp
   * @param updatedAt latest local policy-decision timestamp
   * @param reason bounded operator audit reason
   * @param operatorId bounded local operator identifier
   * @return deterministic newline-terminated digest subject
   */
  @SuppressWarnings("java:S107")
  private static String canonicalWithoutDigest(
      int schemaVersion,
      String bindingId,
      String catalogId,
      String appId,
      String publisherKeyId,
      String publisherKeyFingerprintSha256,
      Status status,
      Instant validFrom,
      Instant validUntil,
      @Nullable String predecessorKeyId,
      @Nullable String successorKeyId,
      Set<AppCatalogChannel> allowedChannels,
      String approvalSource,
      String approvalDigestSha256,
      Instant createdAt,
      Instant updatedAt,
      String reason,
      String operatorId) {
    List<String> channels =
        allowedChannels.stream().map(AppCatalogChannel::catalogValue).sorted().toList();
    return "schemaVersion="
        + schemaVersion
        + '\n'
        + "bindingId="
        + bindingId
        + '\n'
        + "catalogId="
        + catalogId
        + '\n'
        + "appId="
        + appId
        + '\n'
        + "publisherKeyId="
        + publisherKeyId
        + '\n'
        + "publisherKeyFingerprintSha256="
        + publisherKeyFingerprintSha256
        + '\n'
        + "status="
        + status.name().toLowerCase(Locale.ROOT)
        + '\n'
        + "validFrom="
        + validFrom
        + '\n'
        + "validUntil="
        + validUntil
        + '\n'
        + "predecessorKeyId="
        + Objects.requireNonNullElse(predecessorKeyId, "")
        + '\n'
        + "successorKeyId="
        + Objects.requireNonNullElse(successorKeyId, "")
        + '\n'
        + "channels="
        + String.join(",", channels)
        + '\n'
        + "approvalSource="
        + approvalSource
        + '\n'
        + "approvalDigestSha256="
        + approvalDigestSha256
        + '\n'
        + "createdAt="
        + createdAt
        + '\n'
        + "updatedAt="
        + updatedAt
        + '\n'
        + "reason="
        + reason
        + '\n'
        + "operatorId="
        + operatorId
        + '\n';
  }

  /**
   * Validates an optional lineage key and prevents a self-reference.
   *
   * @param value optional lineage key identifier
   * @param name field name used in validation failures
   * @param currentKeyId publisher key authorized by this binding
   * @return normalized optional lineage key identifier
   */
  private static Optional<String> normalizeLineage(
      @Nullable String value, String name, String currentKeyId) {
    if (value == null) {
      return Optional.empty();
    }
    String normalized =
        FederatedPolicyRecordSupport.requireId(value, name, FederatedPolicyRecordSupport.KEY_ID);
    if (currentKeyId.equals(normalized)) {
      throw FederatedPolicyRecordSupport.invalid(name + " cannot equal publisher key id");
    }
    return Optional.of(normalized);
  }
}
