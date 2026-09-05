package network.crypta.platform.api.appdata;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import network.crypta.platform.api.PlatformApiAppAdmission;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Private, short-lived consent bindings for the bounded Site Publisher draft dataset.
 *
 * <p>The owning service holds its mutation monitor and the host's signed-bundle guard while using
 * this helper. Preview records retain only private comparison digests and public target identity,
 * never draft values. A restart discards outstanding consent. The dataset remains a single store
 * generation; generic multi-record imports are deliberately not part of this protocol.
 *
 * <p>A preview binds the old and proposed content identities, the whole app-data generation, the
 * exact signed target declaration, and the operation mode for five minutes. Commit consumes that
 * preview once and rejects any drift. This helper performs no storage mutation and grants no app
 * permissions. Its mutable preview map requires external serialization by {@link AppDataService};
 * hashing helpers are stateless and do not publish their private comparison inputs.
 */
final class SharesiteDraftWriteGuard {
  /** Only installed app admitted by this migration profile. */
  static final String APP_ID = "site-publisher";

  /** Isolated namespace whose mutations require this consent protocol. */
  static final String NAMESPACE = "sharesite-drafts";

  /** Maximum encoded dataset size in bytes before storage mutation. */
  static final int MAX_DATASET_BYTES = 196_608;

  /** Stable capabilities that the signed installed target must already hold. */
  private static final Set<String> REQUIRED_PERMISSIONS =
      Set.of("app.data.read", "app.data.write", "content.insert.app-document");

  /** Service clock used to expire pending consent after five minutes. */
  private final Clock clock;

  /** At most thirty-two unexpired private bindings, serialized by the owning service. */
  private final Map<String, Preview> previews = new LinkedHashMap<>();

  /**
   * Creates private consent state tied to the supplied service clock.
   *
   * @param clock time source used for preview creation and expiry checks
   */
  SharesiteDraftWriteGuard(Clock clock) {
    this.clock = clock;
  }

  /**
   * Identifies the exact app and namespace requiring guarded mutation.
   *
   * @param appId authenticated app identity selected by the data route
   * @param namespace requested app-owned namespace to check against this profile
   * @return whether this operation targets the isolated Site Publisher draft namespace
   */
  static boolean applies(String appId, String namespace) {
    return APP_ID.equals(appId) && NAMESPACE.equals(namespace);
  }

  /**
   * Rejects generic mutation paths that would bypass draft consent.
   *
   * @param appId authenticated app identity selected by the data route
   * @param namespace requested namespace that generic import or deletion would mutate
   */
  static void rejectUnguardedMutation(String appId, String namespace) {
    if (applies(appId, namespace)) {
      throw failure("sharesite_guard_required");
    }
  }

  /**
   * Validates the signed target declaration and constructs its private consent binding.
   *
   * @param installed fresh installed snapshot supplied under the host mutation guard
   * @param verification historically trusted signature identity for that exact installed bundle
   * @return stable target metadata binding schema, permissions, quota, and signed content
   */
  Map<String, Object> targetBinding(
      InstalledAppSnapshot installed, AppBundleVerification verification) {
    var manifest = installed.manifest();
    var api = manifest.apiCompatibility();
    var namespace = manifest.dataSchemaContract().namespace(NAMESPACE);
    if (!APP_ID.equals(installed.appId())
        || !verification.signed()
        || verification.keyFingerprintSha256() == null
        || verification.signedContentDigestSha256() == null
        || !new HashSet<>(manifest.permissions()).containsAll(REQUIRED_PERMISSIONS)
        || api.targetStability() != TargetStability.STABLE
        || !"1.0".equals(api.targetBaseline())
        || api.experimentalCapabilitiesAccepted()
        || namespace == null
        || namespace.currentSchemaVersion() != 1
        || !Integer.valueOf(1).equals(manifest.dataSchemaContract().currentSchemaVersion())
        || manifest.dataQuotaBytes() == null
        || manifest.dataQuotaBytes() <= 0) {
      throw failure("sharesite_target_not_ready");
    }
    PlatformApiAppAdmission.requireCurrentCompatibility(api, manifest.permissions());
    return Map.of(
        "appId", APP_ID,
        "appVersion", manifest.appVersion(),
        "baseline", "1.0",
        "schemaVersion", 1,
        "quotaBytes", manifest.dataQuotaBytes(),
        "permissions", manifest.permissions().stream().sorted().toList(),
        "publisherFingerprintSha256", verification.keyFingerprintSha256(),
        "signedContentDigestSha256", verification.signedContentDigestSha256(),
        "manifestBindingSha256", digest(manifest.toString()));
  }

  /**
   * Creates or consumes a one-time preview after validating the proposed transition.
   *
   * @param parameters app-owned request fields containing intent, mode, backup acknowledgement, and
   *     consent
   * @param proposed bounded candidate record whose complete value will replace the dataset
   * @param current previous visible dataset record, or null before first import
   * @param target exact signed target binding freshly computed under the host guard
   * @param generation private digest of all current app-data summaries and namespaces
   * @return private preview metadata, or an empty map when exact commit consent succeeds
   */
  Map<String, Object> authorize(
      Map<String, List<String>> parameters,
      AppDataRecord proposed,
      AppDataRecord current,
      Map<String, Object> target,
      String generation) {
    if (!"dataset".equals(proposed.key())
        || proposed.schemaVersion() != 1
        || !AppDataRecord.JSON_CONTENT_TYPE.equals(proposed.contentType())) {
      throw failure("sharesite_invalid_dataset");
    }
    String mode = PlatformApiParameters.requireString(parameters, "writeMode");
    SharesiteDraftDataset.validateTransition(current, proposed, mode);
    String expected = PlatformApiParameters.requireString(parameters, "ifMatchSha256");
    String actual = current == null ? "absent" : current.sha256();
    if (!expected.equals(actual)) {
      throw failure("app_data_write_conflict");
    }
    if (!"true".equals(PlatformApiParameters.readOptionalString(parameters, "backupReady"))) {
      throw failure("sharesite_backup_acknowledgement_required");
    }
    Instant now = clock.instant();
    previews.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().expiresAt()));
    String intent = PlatformApiParameters.requireString(parameters, "writeIntent");
    Preview binding =
        new Preview(actual, proposed.sha256(), target, generation, mode, now.plusSeconds(300));
    if (intent.equals("preview")) {
      if (previews.size() >= 32) {
        throw failure("sharesite_preview_limit");
      }
      String id = UUID.randomUUID().toString();
      previews.put(id, binding);
      return Map.of(
          "previewId", id,
          "currentSha256", actual,
          "proposedSha256", proposed.sha256(),
          "targetBinding", target,
          "expiresAt", binding.expiresAt().toString(),
          "writeMode", mode);
    }
    if (!intent.equals("commit")) {
      throw failure("sharesite_invalid_write_intent");
    }
    String id = PlatformApiParameters.requireString(parameters, "writePreviewId");
    Preview consent = previews.remove(id);
    if (consent == null || !consent.matches(binding)) {
      throw failure("sharesite_stale_preview");
    }
    return Map.of();
  }

  /**
   * Hashes canonical JSON for private generation, lineage, and undo comparisons.
   *
   * @param value JSON-compatible local value whose map keys require deterministic ordering
   * @return lowercase SHA-256 digest for local comparison, never public user-content evidence
   */
  static String canonicalDigest(Object value) {
    return digest(PlatformApiJsonWriter.write(canonical(value)));
  }

  /**
   * Sorts object keys recursively while preserving list order and scalar values.
   *
   * @param value JSON-compatible private value to canonicalize without mutating its containers
   * @return detached sorted containers or the unchanged immutable scalar value
   */
  private static Object canonical(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> sorted = new TreeMap<>();
      map.forEach((key, item) -> sorted.put((String) key, canonical(item)));
      return sorted;
    }
    if (value instanceof List<?> list) {
      return list.stream().map(SharesiteDraftWriteGuard::canonical).toList();
    }
    return value;
  }

  /**
   * Hashes the exact UTF-8 spelling of a private comparison value.
   *
   * @param value literal local string to hash without newline or Unicode normalization
   * @return lowercase SHA-256 digest of the exact UTF-8 encoded input
   */
  static String digest(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("SHA-256 is unavailable.", impossible);
    }
  }

  /**
   * Creates a bounded recovery error without exposing draft values or paths.
   *
   * @param code fixed implementation-owned reason code identifying the rejected draft operation
   * @return conflict response with generic private-preview recovery guidance and no user values
   */
  static PlatformApiException failure(String code) {
    return new PlatformApiException(
        409, code, "Draft operation could not complete. Review a fresh private preview.");
  }

  /**
   * Retains comparison-only private consent state until commit, expiry, or restart.
   *
   * @param currentSha256 previous dataset digest, or the explicit absent-record sentinel
   * @param proposedSha256 exact proposed dataset digest reviewed by the owning app
   * @param target immutable binding for the signed installed target and permissions
   * @param generation private whole-app metadata digest used to reject stale consent
   * @param mode closed import, edit, restore, or undo operation mode
   * @param expiresAt exclusive expiry instant after which this preview cannot authorize commit
   */
  private record Preview(
      String currentSha256,
      String proposedSha256,
      Map<String, Object> target,
      String generation,
      String mode,
      Instant expiresAt) {
    /**
     * Compares operation bindings independently of the newly computed expiry instant.
     *
     * @param other fresh binding reconstructed immediately before the attempted commit
     * @return whether all private identities and operation semantics still match
     */
    boolean matches(Preview other) {
      return Objects.equals(currentSha256, other.currentSha256)
          && Objects.equals(proposedSha256, other.proposedSha256)
          && Objects.equals(target, other.target)
          && Objects.equals(generation, other.generation)
          && Objects.equals(mode, other.mode);
    }
  }
}
