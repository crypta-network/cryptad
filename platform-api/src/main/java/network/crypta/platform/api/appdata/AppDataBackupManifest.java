package network.crypta.platform.api.appdata;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;

/**
 * Versioned metadata envelope for a portable app-data backup.
 *
 * <p>The manifest is the part of a backup bundle that can be inspected before nested app-data
 * exports are restored. It identifies the envelope version, stable backup kind, backup scope,
 * creation time, source daemon version label, encryption mode, and whether the artifact contains
 * sensitive user data. It deliberately omits host paths, temporary files, browser sessions, app
 * tokens, vault material, and app bundle metadata so operator tooling can reason about a backup
 * without learning unrelated node state.
 *
 * <p>PR-250 executable code supports only {@code encryption.mode = "none"}. The explicit encryption
 * object keeps the format ready for a future encrypted payload design without adding ad-hoc
 * passphrase crypto here. Future encrypted modes must use approved Crypta crypto primitives, keep
 * the manifest versioned, and reject unknown modes with the same stable backup-specific error
 * vocabulary used by this record.
 *
 * @param backupVersion backup envelope version understood by this daemon
 * @param kind stable top-level marker for app-data backup bundles
 * @param scope {@code single-app} or {@code all-apps}
 * @param createdAt timestamp recorded when the bundle was created
 * @param sourceCryptaVersion path-free version label for the exporting daemon
 * @param encryption encryption metadata, currently only {@code {"mode":"none"}}
 * @param sensitiveUserData whether the bundle carries raw app-owned user data
 * @see AppDataBackupBundle
 */
public record AppDataBackupManifest(
    int backupVersion,
    String kind,
    String scope,
    Instant createdAt,
    String sourceCryptaVersion,
    Map<String, Object> encryption,
    boolean sensitiveUserData) {
  /**
   * Current app-data backup envelope version.
   *
   * <p>Version {@code 1} is the first portable operator backup envelope for durable app-data. A
   * future version bump must include an explicit parser branch or a stable rejection path so older
   * daemons do not misinterpret backup contents.
   */
  public static final int CURRENT_BACKUP_VERSION = 1;

  /**
   * Stable kind marker for portable durable app-data backups.
   *
   * <p>The value distinguishes user backup artifacts from support bundles, release evidence, app
   * bundles, and arbitrary diagnostic JSON. Parsers reject bundles whose top-level marker does not
   * match this exact string.
   */
  public static final String BACKUP_KIND = "crypta-app-data-backup";

  /**
   * Only executable encryption mode currently supported by PR-250.
   *
   * <p>{@code none} means the serialized backup bundle can contain raw app-owned user data. It is
   * not a promise that nested values are safe for diagnostics, logs, or release artifacts.
   */
  public static final String ENCRYPTION_MODE_NONE = "none";

  /**
   * Creates validated manifest metadata.
   *
   * <p>The constructor enforces the manifest-level compatibility contract before any nested
   * app-data export is considered. Unsupported backup versions and encryption modes receive
   * dedicated error codes, while malformed kind, scope, or encryption metadata collapses to {@code
   * invalid_backup_payload}. A blank source version is normalized to {@code unknown}; it is only an
   * operator hint and must not become a filesystem path or token-bearing value.
   *
   * @throws NullPointerException if {@code createdAt} is {@code null}
   * @throws PlatformApiException if the backup version, kind, scope, or encryption mode is invalid
   */
  public AppDataBackupManifest {
    if (backupVersion != CURRENT_BACKUP_VERSION) {
      throw new PlatformApiException(
          400, "unsupported_backup_version", "Unsupported app-data backup version.");
    }
    if (!BACKUP_KIND.equals(kind)) {
      throw invalidBackupPayload();
    }
    if (!AppDataBackupOptions.SCOPE_SINGLE_APP.equals(scope)
        && !AppDataBackupOptions.SCOPE_ALL_APPS.equals(scope)) {
      throw invalidBackupPayload();
    }
    Objects.requireNonNull(createdAt, "createdAt");
    sourceCryptaVersion =
        sourceCryptaVersion == null || sourceCryptaVersion.isBlank()
            ? "unknown"
            : sourceCryptaVersion.trim();
    encryption = normalizeEncryption(encryption);
  }

  /**
   * Builds a manifest for a newly created backup bundle.
   *
   * <p>Service code calls this factory when assembling a backup response from current durable
   * app-data state. The method fixes the version and kind to the current implementation and marks
   * the bundle as sensitive user data. The caller still chooses whether the backup covers one app
   * or all known app ids and supplies the clock-derived creation timestamp.
   *
   * @param scope backup scope requested by the operator
   * @param createdAt creation timestamp to place in the manifest
   * @param sourceCryptaVersion daemon version label to include without paths or tokens
   * @return manifest with {@code encryption.mode = none} and sensitive user data marked
   */
  public static AppDataBackupManifest create(
      String scope, Instant createdAt, String sourceCryptaVersion) {
    return new AppDataBackupManifest(
        CURRENT_BACKUP_VERSION,
        BACKUP_KIND,
        scope,
        createdAt,
        sourceCryptaVersion,
        Map.of("mode", ENCRYPTION_MODE_NONE),
        true);
  }

  /**
   * Converts this manifest to deterministic JSON-compatible fields.
   *
   * <p>The returned map uses the top-level field order expected by bundle serialization. It
   * contains metadata only and no nested app exports, so it is safe to use for route shape checks
   * and compatibility evidence. A complete backup bundle still becomes sensitive when app entries
   * are appended.
   *
   * @return manifest fields in backup envelope order
   */
  public Map<String, Object> toJsonValue() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("backupVersion", backupVersion);
    json.put("kind", kind);
    json.put("scope", scope);
    json.put("createdAt", createdAt.toString());
    json.put("sourceCryptaVersion", sourceCryptaVersion);
    json.put("sensitiveUserData", sensitiveUserData);
    json.put("encryption", encryption);
    return json;
  }

  private static Map<String, Object> normalizeEncryption(Map<String, Object> rawEncryption) {
    if (rawEncryption == null) {
      throw invalidBackupPayload();
    }
    Object mode = rawEncryption.get("mode");
    if (!(mode instanceof String modeText) || modeText.isBlank()) {
      throw invalidBackupPayload();
    }
    if (!ENCRYPTION_MODE_NONE.equals(modeText)) {
      throw new PlatformApiException(
          400, "unsupported_backup_encryption", "Unsupported app-data backup encryption mode.");
    }
    LinkedHashMap<String, Object> encryptionJson = LinkedHashMap.newLinkedHashMap(1);
    encryptionJson.put("mode", ENCRYPTION_MODE_NONE);
    return java.util.Collections.unmodifiableMap(encryptionJson);
  }

  static PlatformApiException invalidBackupPayload() {
    return new PlatformApiException(
        400, "invalid_backup_payload", "Invalid app-data backup payload.");
  }
}
