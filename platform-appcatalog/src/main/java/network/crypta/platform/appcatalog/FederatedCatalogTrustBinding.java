package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * One explicit local authorization binding between a catalog identity and its signing keys.
 *
 * <p>The binding is host-owned policy, not signed catalog content. Catalog refreshes may consume a
 * binding but cannot modify it. The canonical digest commits every policy field except the digest
 * itself, allowing source and retained-revision records to detect local-policy substitution.
 *
 * <p>Routine authorization requires active lifecycle, exact catalog and signer identity, and an
 * allowed channel. Publisher and reviewer policy digests record which separate local policy sets
 * the operator accepted; they do not merge those roles with catalog signing. The immutable record
 * contains public fingerprints and bounded audit metadata only. Store implementations serialize its
 * canonical text atomically and reject a supplied self-digest that does not match all fields.
 *
 * @param schemaVersion closed persistent-policy schema version
 * @param bindingId stable local identifier for this catalog authorization
 * @param catalogId exact normalized catalog identifier covered by the binding
 * @param signerFingerprints allowed signer key IDs mapped to canonical fingerprints
 * @param status current local lifecycle state of this binding
 * @param allowedChannels catalog channels approved for routine operations
 * @param localPriority local preference used only after conflict policy permits selection
 * @param discoveryProvenanceDigest optional digest of the accepted discovery evidence
 * @param reviewerPolicyDigest optional exact local reviewer-policy digest
 * @param publisherPolicyDigest optional exact local publisher-policy digest
 * @param createdAt timestamp when the local binding was first created
 * @param updatedAt timestamp of the most recent local trust decision
 * @param reason bounded operator-supplied reason for the decision
 * @param operatorId bounded local operator audit identifier
 * @param selfDigest digest binding every preceding policy field
 */
public record FederatedCatalogTrustBinding(
    int schemaVersion,
    String bindingId,
    String catalogId,
    Map<String, String> signerFingerprints,
    Status status,
    Set<AppCatalogChannel> allowedChannels,
    int localPriority,
    Optional<String> discoveryProvenanceDigest,
    Optional<String> reviewerPolicyDigest,
    Optional<String> publisherPolicyDigest,
    Instant createdAt,
    Instant updatedAt,
    String reason,
    String operatorId,
    String selfDigest) {
  /** Closed persistent schema version emitted for newly created trust bindings. */
  public static final int CURRENT_SCHEMA_VERSION = 1;

  /** Closed grammar for stable local binding identifiers. */
  private static final Pattern LOCAL_ID = Pattern.compile("[a-z0-9][a-z0-9._-]{0,127}");

  /** Closed grammar for catalog-signing key identifiers. */
  private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

  /** Closed lowercase hexadecimal SHA-256 grammar. */
  private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");

  /** Local lifecycle for a catalog trust binding. */
  public enum Status {
    /** Awaiting an explicit local trust decision. */
    PENDING,
    /** Authorizes routine work within the exact signer and channel scope. */
    ACTIVE,
    /** Blocks routine work while permitting bounded historical policy evaluation. */
    SUSPENDED,
    /** Permanently blocks routine and historical catalog authorization. */
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
        throw invalid(exception);
      }
    }

    /**
     * Creates the stable failure for an invalid persisted lifecycle value.
     *
     * @param cause parsing failure
     * @return bounded catalog trust validation exception
     */
    private static AppCatalogException invalid(Exception cause) {
      return new AppCatalogException(
          "invalid_catalog_trust_binding", "invalid catalog trust status", cause);
    }
  }

  /** Validates and normalizes one immutable local binding. */
  public FederatedCatalogTrustBinding {
    if (schemaVersion != CURRENT_SCHEMA_VERSION) {
      throw invalid("unsupported catalog trust binding schema version");
    }
    requireId(bindingId, "bindingId", LOCAL_ID);
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    signerFingerprints = normalizedSigners(signerFingerprints);
    Objects.requireNonNull(status, "status");
    allowedChannels = Set.copyOf(Objects.requireNonNull(allowedChannels, "allowedChannels"));
    if (allowedChannels.isEmpty()) {
      throw invalid("catalog trust binding must allow at least one channel");
    }
    if (localPriority < 0 || localPriority > 10_000) {
      throw invalid("catalog trust priority must be between 0 and 10000");
    }
    discoveryProvenanceDigest =
        normalizedDigest(
            Objects.requireNonNull(discoveryProvenanceDigest, "discovery digest").orElse(null),
            "discovery digest");
    reviewerPolicyDigest =
        normalizedDigest(
            Objects.requireNonNull(reviewerPolicyDigest, "reviewer policy digest").orElse(null),
            "reviewer policy digest");
    publisherPolicyDigest =
        normalizedDigest(
            Objects.requireNonNull(publisherPolicyDigest, "publisher policy digest").orElse(null),
            "publisher policy digest");
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
    if (updatedAt.isBefore(createdAt)) {
      throw invalid("catalog trust updatedAt precedes createdAt");
    }
    requireBounded(reason, "reason", 512);
    requireBounded(operatorId, "operatorId", 128);
    String computed =
        digestOf(
            canonicalWithoutDigest(
                schemaVersion,
                bindingId,
                catalogId,
                signerFingerprints,
                status,
                allowedChannels,
                localPriority,
                discoveryProvenanceDigest.orElse(null),
                reviewerPolicyDigest.orElse(null),
                publisherPolicyDigest.orElse(null),
                createdAt,
                updatedAt,
                reason,
                operatorId));
    if (selfDigest == null || selfDigest.isBlank()) {
      selfDigest = computed;
    } else if (!computed.equals(requireDigest(selfDigest, "selfDigest"))) {
      throw invalid("catalog trust binding self-digest mismatch");
    }
  }

  /**
   * Returns an immutable copy of allowed signer key IDs mapped to canonical fingerprints.
   *
   * @return immutable signer identity map
   */
  @Override
  public Map<String, String> signerFingerprints() {
    return Map.copyOf(signerFingerprints);
  }

  /**
   * Creates a binding and derives its self-digest.
   *
   * @param bindingId stable local binding identifier
   * @param catalogId exact authenticated catalog identifier
   * @param signerFingerprints allowed signer IDs and canonical fingerprints
   * @param status initial local lifecycle status
   * @param allowedChannels locally approved routine catalog channels
   * @param localPriority preference used only after conflict authorization
   * @param discoveryProvenanceDigest optional accepted discovery evidence digest
   * @param reviewerPolicyDigest optional accepted reviewer policy-set digest
   * @param publisherPolicyDigest optional accepted publisher policy-set digest
   * @param createdAt local binding creation timestamp
   * @param updatedAt latest local trust-decision timestamp
   * @param reason bounded operator audit reason
   * @param operatorId bounded local operator identifier
   * @return immutable self-digested catalog trust binding
   */
  public static FederatedCatalogTrustBinding create(
      String bindingId,
      String catalogId,
      Map<String, String> signerFingerprints,
      Status status,
      Set<AppCatalogChannel> allowedChannels,
      int localPriority,
      String discoveryProvenanceDigest,
      String reviewerPolicyDigest,
      String publisherPolicyDigest,
      Instant createdAt,
      Instant updatedAt,
      String reason,
      String operatorId) {
    return new FederatedCatalogTrustBinding(
        CURRENT_SCHEMA_VERSION,
        bindingId,
        catalogId,
        signerFingerprints,
        status,
        allowedChannels,
        localPriority,
        Optional.ofNullable(discoveryProvenanceDigest),
        Optional.ofNullable(reviewerPolicyDigest),
        Optional.ofNullable(publisherPolicyDigest),
        createdAt,
        updatedAt,
        reason,
        operatorId,
        null);
  }

  /**
   * Returns whether this binding authorizes new work for the exact signer and channel.
   *
   * @param requestedCatalogId catalog requesting routine authorization
   * @param keyId verified catalog-signature key identifier
   * @param fingerprint canonical verified signer fingerprint
   * @param channel authenticated catalog channel
   * @return {@code true} when every identity, lifecycle, and channel constraint matches
   */
  public boolean authorizes(
      String requestedCatalogId, String keyId, String fingerprint, AppCatalogChannel channel) {
    return status == Status.ACTIVE
        && catalogId.equals(AppCatalog.normalizeCatalogId(requestedCatalogId))
        && Objects.equals(signerFingerprints.get(keyId), fingerprint)
        && allowedChannels.contains(channel);
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
            signerFingerprints,
            status,
            allowedChannels,
            localPriority,
            discoveryProvenanceDigest.orElse(null),
            reviewerPolicyDigest.orElse(null),
            publisherPolicyDigest.orElse(null),
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
   * @param catalogId exact normalized catalog identifier
   * @param signers normalized signer identity map
   * @param status local lifecycle status
   * @param channels locally approved catalog channels
   * @param localPriority local post-conflict preference
   * @param discoveryDigest optional discovery evidence digest
   * @param reviewerDigest optional reviewer policy-set digest
   * @param publisherDigest optional publisher policy-set digest
   * @param createdAt local binding creation timestamp
   * @param updatedAt latest local trust-decision timestamp
   * @param reason bounded operator audit reason
   * @param operatorId bounded local operator identifier
   * @return deterministic newline-terminated digest subject
   */
  private static String canonicalWithoutDigest(
      int schemaVersion,
      String bindingId,
      String catalogId,
      Map<String, String> signers,
      Status status,
      Set<AppCatalogChannel> channels,
      int localPriority,
      String discoveryDigest,
      String reviewerDigest,
      String publisherDigest,
      Instant createdAt,
      Instant updatedAt,
      String reason,
      String operatorId) {
    StringBuilder text =
        new StringBuilder()
            .append("schemaVersion=")
            .append(schemaVersion)
            .append('\n')
            .append("bindingId=")
            .append(bindingId)
            .append('\n')
            .append("catalogId=")
            .append(catalogId)
            .append('\n')
            .append("status=")
            .append(status.name().toLowerCase(Locale.ROOT))
            .append('\n')
            .append("localPriority=")
            .append(localPriority)
            .append('\n')
            .append("createdAt=")
            .append(createdAt)
            .append('\n')
            .append("updatedAt=")
            .append(updatedAt)
            .append('\n')
            .append("reason=")
            .append(reason)
            .append('\n')
            .append("operatorId=")
            .append(operatorId)
            .append('\n');
    List<String> channelValues =
        channels.stream().map(AppCatalogChannel::catalogValue).sorted().toList();
    text.append("channels=").append(String.join(",", channelValues)).append('\n');
    text.append("signerIds=").append(String.join(",", signers.keySet())).append('\n');
    signers.forEach(
        (id, fingerprint) ->
            text.append("signer.").append(id).append('=').append(fingerprint).append('\n'));
    if (discoveryDigest != null) {
      text.append("discoveryDigest=").append(discoveryDigest).append('\n');
    }
    if (reviewerDigest != null) {
      text.append("reviewerPolicyDigest=").append(reviewerDigest).append('\n');
    }
    if (publisherDigest != null) {
      text.append("publisherPolicyDigest=").append(publisherDigest).append('\n');
    }
    return text.toString();
  }

  /**
   * Validates, sorts, and freezes allowed catalog signer identities.
   *
   * @param values signer key IDs mapped to canonical fingerprints
   * @return immutable normalized signer identity map
   */
  private static Map<String, String> normalizedSigners(Map<String, String> values) {
    if (values == null || values.isEmpty() || values.size() > 16) {
      throw invalid("catalog trust binding must contain 1 to 16 signers");
    }
    LinkedHashMap<String, String> normalized = new LinkedHashMap<>();
    values.entrySet().stream()
        .sorted(Map.Entry.comparingByKey())
        .forEach(
            entry -> {
              String id = requireId(entry.getKey(), "signer key id", KEY_ID);
              String prior =
                  normalized.put(id, requireDigest(entry.getValue(), "signer fingerprint"));
              if (prior != null) {
                throw invalid("duplicate signer key id");
              }
            });
    if (normalized.values().stream().distinct().count() != normalized.size()) {
      throw invalid("catalog trust binding aliases one signer fingerprint under multiple ids");
    }
    return Collections.unmodifiableMap(new LinkedHashMap<>(normalized));
  }

  /**
   * Validates an optional lowercase SHA-256 policy digest.
   *
   * @param value optional digest value
   * @param name field name used in failures
   * @return empty value or validated digest
   */
  private static Optional<String> normalizedDigest(String value, String name) {
    return Optional.ofNullable(value).map(item -> requireDigest(item, name));
  }

  /**
   * Requires a lowercase SHA-256 policy digest.
   *
   * @param value digest value
   * @param name field name used in failures
   * @return validated digest
   */
  private static String requireDigest(String value, String name) {
    if (value == null || !SHA256.matcher(value).matches()) {
      throw invalid(name + " must be lowercase SHA-256");
    }
    return value;
  }

  /**
   * Requires a bounded identifier matching a closed grammar.
   *
   * @param value identifier value
   * @param name field name used in failures
   * @param pattern closed accepted identifier grammar
   * @return validated identifier
   */
  private static String requireId(String value, String name, Pattern pattern) {
    String checked = requireBounded(value, name, 128);
    if (!pattern.matcher(checked).matches()) {
      throw invalid("invalid " + name);
    }
    return checked;
  }

  /**
   * Requires bounded nonblank single-line persistent text without delimiters.
   *
   * @param value text value
   * @param name field name used in failures
   * @param max maximum permitted character count
   * @return validated text
   */
  private static String requireBounded(String value, String name, int max) {
    if (value == null
        || value.isBlank()
        || value.length() > max
        || value.indexOf('\n') >= 0
        || value.indexOf('\r') >= 0
        || value.indexOf('=') >= 0) {
      throw invalid("invalid " + name);
    }
    return value;
  }

  /**
   * Computes lowercase SHA-256 over canonical UTF-8 policy text.
   *
   * @param text canonical policy digest subject
   * @return lowercase hexadecimal SHA-256 digest
   */
  private static String digestOf(String text) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /**
   * Creates a stable catalog trust-binding validation failure.
   *
   * @param message bounded validation explanation
   * @return catalog exception with the stable trust-binding error code
   */
  private static AppCatalogException invalid(String message) {
    return new AppCatalogException("invalid_catalog_trust_binding", message);
  }
}
