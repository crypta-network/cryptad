package network.crypta.platform.appdist;

import java.net.URI;
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
 * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
 * @param uiEntry optional UI entry path, or {@code null} when the app has no bundled UI surface
 * @param permissions normalized permission strings declared by the app manifest
 * @param dataQuotaBytes optional mutable data quota metadata in bytes, or {@code null}
 * @param cacheQuotaBytes optional mutable cache quota metadata in bytes, or {@code null}
 * @param restartPolicy normalized process restart policy
 * @param restartMaxAttempts maximum automatic restart attempts for one daemon-managed run
 * @param restartBackoffMillis delay before an automatic restart attempt
 */
public record AppBundleManifest(
    int manifestVersion,
    String appId,
    String appName,
    String appVersion,
    String execPathText,
    AppUiMode uiMode,
    String uiEntry,
    List<String> permissions,
    Long dataQuotaBytes,
    Long cacheQuotaBytes,
    AppRestartPolicy restartPolicy,
    int restartMaxAttempts,
    long restartBackoffMillis) {
  private static final Pattern APP_ID_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final Pattern WINDOWS_DRIVE_PREFIX_PATTERN = Pattern.compile("^[a-zA-Z]:.*");

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
   * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
   * @param uiEntry optional UI entry path, or {@code null} when the app has no bundled UI surface
   * @param permissions normalized permission strings declared by the app manifest
   * @param dataQuotaBytes optional mutable data quota metadata in bytes, or {@code null}
   * @param cacheQuotaBytes optional mutable cache quota metadata in bytes, or {@code null}
   * @param restartPolicy normalized process restart policy
   * @param restartMaxAttempts maximum automatic restart attempts for one daemon-managed run
   * @param restartBackoffMillis delay before an automatic restart attempt
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
    uiMode = inferUiMode(uiMode, uiEntry);
    uiEntry = normalizeUiEntry(uiMode, uiEntry);
    permissions = List.copyOf(Objects.requireNonNull(permissions, "permissions"));
    dataQuotaBytes = normalizeQuota(dataQuotaBytes, "quota.data.bytes");
    cacheQuotaBytes = normalizeQuota(cacheQuotaBytes, "quota.cache.bytes");
    Objects.requireNonNull(restartPolicy, "restartPolicy");
    requireValidRestartMaxAttempts(restartMaxAttempts);
    requireValidRestartBackoffMillis(restartBackoffMillis);
  }

  /**
   * Creates a manifest with the default restart policy.
   *
   * @param manifestVersion manifest schema version, currently required to be {@code 1}
   * @param appId stable lower-case application identifier safe for managed bundle paths
   * @param appName human-readable application name shown by host and API surfaces
   * @param appVersion display version string recorded in installed app summaries
   * @param execPathText executable path relative to the bundle root, using normalized separators
   * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
   * @param uiEntry optional UI entry path, or {@code null} when the app has no bundled UI surface
   * @param permissions normalized permission strings declared by the app manifest
   * @param dataQuotaBytes optional mutable data quota metadata in bytes, or {@code null}
   * @param cacheQuotaBytes optional mutable cache quota metadata in bytes, or {@code null}
   */
  @SuppressWarnings("unused")
  public AppBundleManifest(
      int manifestVersion,
      String appId,
      String appName,
      String appVersion,
      String execPathText,
      AppUiMode uiMode,
      String uiEntry,
      List<String> permissions,
      Long dataQuotaBytes,
      Long cacheQuotaBytes) {
    this(
        manifestVersion,
        appId,
        appName,
        appVersion,
        execPathText,
        uiMode,
        uiEntry,
        permissions,
        dataQuotaBytes,
        cacheQuotaBytes,
        AppRestartPolicy.NEVER,
        0,
        0L);
  }

  /**
   * Creates a manifest using the backward-compatible UI-mode inference rules.
   *
   * <p>This overload keeps existing tests and callers source-compatible while the parser supplies
   * the explicit canonical mode field for newly parsed manifests.
   *
   * @param manifestVersion manifest schema version, currently required to be {@code 1}
   * @param appId stable lower-case application identifier safe for managed bundle paths
   * @param appName human-readable application name shown by host and API surfaces
   * @param appVersion display version string recorded in installed app summaries
   * @param execPathText executable path relative to the bundle root, using normalized separators
   * @param uiEntry optional UI entry path, or {@code null} when the app has no browser UI surface
   * @param permissions normalized permission strings declared by the app manifest
   * @param dataQuotaBytes optional mutable data quota metadata in bytes, or {@code null}
   * @param cacheQuotaBytes optional mutable cache quota metadata in bytes, or {@code null}
   */
  public AppBundleManifest(
      int manifestVersion,
      String appId,
      String appName,
      String appVersion,
      String execPathText,
      String uiEntry,
      List<String> permissions,
      Long dataQuotaBytes,
      Long cacheQuotaBytes) {
    this(
        manifestVersion,
        appId,
        appName,
        appVersion,
        execPathText,
        null,
        uiEntry,
        permissions,
        dataQuotaBytes,
        cacheQuotaBytes,
        AppRestartPolicy.NEVER,
        0,
        0L);
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
   * Returns the static UI entry as a normalized relative bundle path.
   *
   * <p>This method is only valid for {@link AppUiMode#STATIC} manifests. The parser and record
   * constructor have already rejected absolute paths, traversal, and platform-specific absolute
   * forms, but callers still need filesystem checks before serving or trusting the resolved file.
   *
   * @return normalized static UI entry path within the bundle
   * @throws IllegalStateException if this manifest does not declare a static UI
   */
  public Path staticUiEntryPath() {
    if (uiMode != AppUiMode.STATIC) {
      throw new IllegalStateException("app.ui.mode is not static: " + uiMode.manifestValue());
    }
    return Path.of(uiEntry).normalize();
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

  private static AppUiMode inferUiMode(AppUiMode explicitMode, String uiEntry) {
    if (explicitMode != null) {
      return explicitMode;
    }
    if (uiEntry == null) {
      return AppUiMode.NONE;
    }
    return uiEntry.startsWith("/") ? AppUiMode.SHELL_PANEL : AppUiMode.STATIC;
  }

  private static String normalizeUiEntry(AppUiMode uiMode, String uiEntry) {
    return switch (Objects.requireNonNull(uiMode, "uiMode")) {
      case NONE -> normalizeNoUiEntry(uiEntry);
      case SHELL_PANEL -> normalizeShellPanelUiEntry(uiEntry);
      case STATIC -> normalizeStaticUiEntry(uiEntry);
    };
  }

  private static String normalizeNoUiEntry(String uiEntry) {
    if (uiEntry != null) {
      throw new IllegalArgumentException("app.ui.entry must be absent when app.ui.mode=none");
    }
    return null;
  }

  private static String normalizeShellPanelUiEntry(String uiEntry) {
    if (uiEntry == null) {
      throw new IllegalArgumentException("app.ui.entry is required when app.ui.mode=shell-panel");
    }
    if (!uiEntry.startsWith("/") || uiEntry.startsWith("//")) {
      throw new IllegalArgumentException("app.ui.entry must be an absolute local path");
    }
    try {
      URI uri = URI.create("http://localhost" + uiEntry);
      if (!"localhost".equals(uri.getHost())
          || uri.getRawPath() == null
          || !uri.getRawPath().startsWith("/")
          || uri.getRawUserInfo() != null) {
        throw new IllegalArgumentException("app.ui.entry must be an absolute local path");
      }
    } catch (IllegalArgumentException exception) {
      throw new IllegalArgumentException("app.ui.entry must be an absolute local path", exception);
    }
    return uiEntry;
  }

  private static String normalizeStaticUiEntry(String uiEntry) {
    if (uiEntry == null) {
      throw new IllegalArgumentException("app.ui.entry is required when app.ui.mode=static");
    }
    String staticUiEntry = normalizeRelativeUiPath(uiEntry);
    if (AppDistributionSidecars.isDistributionSidecar(staticUiEntry)) {
      throw new IllegalArgumentException(
          "app.ui.entry must not point at distribution sidecar: " + staticUiEntry);
    }
    return staticUiEntry;
  }

  private static String normalizeRelativeUiPath(String rawValue) {
    String normalized = rawValue.trim().replace('\\', '/');
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("app.ui.entry must not be blank");
    }
    if (normalized.startsWith("/")
        || normalized.startsWith("\\")
        || WINDOWS_DRIVE_PREFIX_PATTERN.matcher(normalized).matches()) {
      throw new IllegalArgumentException("app.ui.entry must be relative: " + rawValue);
    }
    String[] segments = normalized.split("/", -1);
    for (String segment : segments) {
      if (segment.isBlank() || segment.equals(".") || segment.equals("..")) {
        throw new IllegalArgumentException(
            "app.ui.entry must stay under the app root: " + rawValue);
      }
      if (segment.indexOf(':') >= 0 || containsControlCharacter(segment)) {
        throw new IllegalArgumentException(
            "app.ui.entry contains an unsafe path segment: " + rawValue);
      }
    }
    return String.join("/", segments);
  }

  private static boolean containsControlCharacter(String segment) {
    for (int index = 0; index < segment.length(); index++) {
      if (Character.isISOControl(segment.charAt(index))) {
        return true;
      }
    }
    return false;
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

  private static void requireValidRestartMaxAttempts(int maxAttempts) {
    if (maxAttempts < 0) {
      throw new IllegalArgumentException("app.restart.maxAttempts must be >= 0");
    }
  }

  private static void requireValidRestartBackoffMillis(long backoffMillis) {
    if (backoffMillis < 0L) {
      throw new IllegalArgumentException("app.restart.backoff.ms must be >= 0");
    }
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
