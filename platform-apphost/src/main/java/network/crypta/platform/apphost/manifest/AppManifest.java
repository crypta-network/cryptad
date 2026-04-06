package network.crypta.platform.apphost.manifest;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import network.crypta.platform.apphost.InstalledAppPaths;

/**
 * Parsed v1 manifest for an installed application.
 *
 * <p>{@code AppManifest} is the immutable normalized form of {@code cryptad-app.properties}. It
 * carries the small set of metadata that AppHost v1 needs to identify a bundle, resolve its
 * executable, expose a human-readable name and version, and publish optional permission and quota
 * hints to higher layers.
 *
 * <p>The record stores string fields in their validated canonical form rather than preserving the
 * source file verbatim. In particular, the app id is lower-cased, required text fields are trimmed,
 * permissions are copied into a deterministic immutable list, and optional quota fields are checked
 * for non-negative values before the manifest is exposed to runtime code.
 *
 * @param manifestVersion manifest schema version
 * @param appId stable path-safe app identifier
 * @param appName human-readable application name
 * @param appVersion display version string
 * @param execPathText executable path relative to the installed app root
 * @param uiEntry optional UI entry path, or {@code null}
 * @param permissions normalized permission strings
 * @param dataQuotaBytes optional data quota metadata, or {@code null}
 * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
 */
public record AppManifest(
    int manifestVersion,
    String appId,
    String appName,
    String appVersion,
    String execPathText,
    String uiEntry,
    List<String> permissions,
    Long dataQuotaBytes,
    Long cacheQuotaBytes) {
  /**
   * Creates a validated manifest snapshot.
   *
   * @param manifestVersion manifest schema version
   * @param appId stable path-safe app identifier
   * @param appName human-readable application name
   * @param appVersion display version string
   * @param execPathText executable path relative to the installed app root
   * @param uiEntry optional UI entry path, or {@code null}
   * @param permissions normalized permission strings
   * @param dataQuotaBytes optional data quota metadata, or {@code null}
   * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
   */
  public AppManifest {
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
   * Returns the executable path as a relative bundle path.
   *
   * <p>The returned path is normalized but intentionally remains relative. Callers are expected to
   * resolve it beneath an installed bundle root through {@code InstalledAppPaths} rather than treat
   * it as an absolute filesystem location on its own.
   *
   * @return relative executable path inside the installed bundle
   */
  public Path execPath() {
    return Path.of(execPathText).normalize();
  }

  /**
   * Returns permissions as a deterministic comma-separated environment value.
   *
   * <p>This is primarily useful for launch-time environment injection and diagnostics where the
   * host needs a stable textual representation of the manifest permission list.
   *
   * @return comma-separated permissions, or an empty string when the manifest declares none
   */
  public String permissionsCsv() {
    return String.join(",", permissions);
  }

  /**
   * Normalizes and validates an app id.
   *
   * <p>The method trims the input, lower-cases it using {@link Locale#ROOT}, and validates it
   * against the same path-safe rules used by {@link InstalledAppPaths}. The result is suitable for
   * directory naming and for stable identity comparisons across APIs.
   *
   * @param appId raw application identifier
   * @return normalized lower-case app id
   * @throws IllegalArgumentException if the identifier is blank or does not match the supported
   *     AppHost naming pattern
   */
  public static String normalizeAppId(String appId) {
    String normalized = requireNonBlank(appId, "app.id").toLowerCase(Locale.ROOT);
    InstalledAppPaths.normalizeAppId(normalized);
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
