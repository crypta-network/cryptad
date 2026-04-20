package network.crypta.platform.appdist;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Parsed v1 manifest for a staged app bundle.
 *
 * <p>{@code AppBundleManifest} is the appdist-owned normalized form of {@code
 * cryptad-app.properties}. It preserves the manifest fields that matter to bundle signing,
 * verification, and installability checks without depending on the higher-level AppHost model.
 * Parsing normalizes app identifiers, executable paths, permissions, and quota metadata before
 * callers use the values for digest generation.
 *
 * <p>The manifest is signed indirectly because {@code cryptad-app.properties} is always included in
 * {@code cryptad-app.digests}. Any change to app identity, display version, executable path,
 * permissions, or quota metadata after signing therefore invalidates the bundle. The record remains
 * immutable after construction and is safe to pass between parser, digest writer, and verification
 * code without defensive copying beyond the permissions list.
 *
 * @param manifestVersion manifest schema version, currently required to be {@code 1}
 * @param appId stable lower-case application identifier safe for managed bundle paths
 * @param appName human-readable application name shown by host and API surfaces
 * @param appVersion display version string recorded in installed app summaries
 * @param execPathText executable path relative to the bundle root, using normalized separators
 * @param uiEntry optional UI entry path, or {@code null} when the app has no bundled UI surface
 * @param permissions normalized permission strings declared by the app manifest
 * @param dataQuotaBytes optional mutable data quota metadata in bytes, or {@code null}
 * @param cacheQuotaBytes optional mutable cache quota metadata in bytes, or {@code null}
 */
public record AppBundleManifest(
    int manifestVersion,
    String appId,
    String appName,
    String appVersion,
    String execPathText,
    String uiEntry,
    List<String> permissions,
    Long dataQuotaBytes,
    Long cacheQuotaBytes) {
  private static final Pattern APP_ID_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");

  /**
   * Creates a validated staged-bundle manifest snapshot.
   *
   * <p>This constructor enforces value-level invariants after the parser has handled manifest text
   * syntax. It rejects unsupported schema versions, blank required fields, malformed app ids, null
   * permission lists, and negative quotas. It does not check whether {@code app.exec} exists on
   * disk; use {@link AppBundleStructureValidator#validate(Path)} for filesystem and launchability
   * checks.
   *
   * @param manifestVersion manifest schema version, currently required to be {@code 1}
   * @param appId stable lower-case application identifier safe for managed bundle paths
   * @param appName human-readable application name shown by host and API surfaces
   * @param appVersion display version string recorded in installed app summaries
   * @param execPathText executable path relative to the bundle root, using normalized separators
   * @param uiEntry optional UI entry path, or {@code null} when the app has no bundled UI surface
   * @param permissions normalized permission strings declared by the app manifest
   * @param dataQuotaBytes optional mutable data quota metadata in bytes, or {@code null}
   * @param cacheQuotaBytes optional mutable cache quota metadata in bytes, or {@code null}
   * @throws IllegalArgumentException if any value cannot represent a valid v1 app manifest
   */
  public AppBundleManifest {
    if (manifestVersion != 1) {
      throw new IllegalArgumentException("unsupported manifest.version: " + manifestVersion);
    }
    appId = normalizeAppId(appId);
    appName = requireNonBlank(appName, "app.name");
    appVersion = requireNonBlank(appVersion, "app.version");
    execPathText = requireNonBlank(execPathText, "app.exec");
    uiEntry = normalizeOptional(uiEntry);
    permissions = List.copyOf(Objects.requireNonNull(permissions, "permissions"));
    dataQuotaBytes = normalizeQuota(dataQuotaBytes, "quota.data.bytes");
    cacheQuotaBytes = normalizeQuota(cacheQuotaBytes, "quota.cache.bytes");
  }

  /**
   * Returns the executable path as a normalized relative bundle path.
   *
   * <p>The returned {@link Path} is suitable for resolving against a known bundle root. Callers
   * should still validate the resolved path with {@link AppBundleStructureValidator} before
   * trusting it, because this method does not inspect the file system.
   *
   * @return normalized executable path within the bundle
   */
  public Path execPath() {
    return Path.of(execPathText).normalize();
  }

  /**
   * Normalizes and validates an app id.
   *
   * <p>App ids are trimmed, converted to lower case, and constrained to path-safe characters. The
   * same normalization is used before digesting or installing a bundle so callers do not need a
   * second app-id canonicalization step.
   *
   * @param appId raw application identifier from a manifest or caller input
   * @return normalized lower-case app id
   * @throws NullPointerException if {@code appId} is {@code null}
   * @throws IllegalArgumentException if the normalized id is empty or contains unsupported syntax
   */
  public static String normalizeAppId(String appId) {
    Objects.requireNonNull(appId, "appId");
    String normalized = appId.trim().toLowerCase(Locale.ROOT);
    if (!APP_ID_PATTERN.matcher(normalized).matches()) {
      throw new IllegalArgumentException("invalid app id: " + appId);
    }
    return normalized;
  }

  private static String normalizeOptional(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }

  private static Long normalizeQuota(Long quota, String fieldName) {
    if (quota == null) {
      return null;
    }
    if (quota < 0L) {
      throw new IllegalArgumentException(fieldName + " must be >= 0");
    }
    return quota;
  }

  private static String requireNonBlank(String value, String fieldName) {
    Objects.requireNonNull(value, fieldName);
    String trimmed = value.trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return trimmed;
  }
}
