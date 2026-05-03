package network.crypta.platform.apphost.manifest;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppRestartPolicy;
import network.crypta.platform.appdist.AppSandboxMode;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;

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
 * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
 * @param uiEntry optional UI entry path, or {@code null}
 * @param permissions normalized permission strings
 * @param apiCompatibility optional Platform API contract metadata declared by the app
 * @param dataQuotaBytes optional data quota metadata, or {@code null}
 * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
 * @param sandboxPolicy requested process sandbox policy
 * @param restartPolicy normalized process restart policy
 * @param restartMaxAttempts maximum automatic restart attempts for one daemon-managed run
 * @param restartBackoffMillis delay before an automatic restart attempt
 */
public record AppManifest(
    int manifestVersion,
    String appId,
    String appName,
    String appVersion,
    String execPathText,
    AppUiMode uiMode,
    String uiEntry,
    List<String> permissions,
    AppApiCompatibilityMetadata apiCompatibility,
    Long dataQuotaBytes,
    Long cacheQuotaBytes,
    AppSandboxPolicy sandboxPolicy,
    AppRestartPolicy restartPolicy,
    int restartMaxAttempts,
    long restartBackoffMillis) {
  /**
   * Creates a validated manifest snapshot.
   *
   * @param manifestVersion manifest schema version
   * @param appId stable path-safe app identifier
   * @param appName human-readable application name
   * @param appVersion display version string
   * @param execPathText executable path relative to the installed app root
   * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
   * @param uiEntry optional UI entry path, or {@code null}
   * @param permissions normalized permission strings
   * @param apiCompatibility optional Platform API contract metadata declared by the app
   * @param dataQuotaBytes optional data quota metadata, or {@code null}
   * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
   * @param sandboxPolicy requested process sandbox policy
   * @param restartPolicy normalized process restart policy
   * @param restartMaxAttempts maximum automatic restart attempts for one daemon-managed run
   * @param restartBackoffMillis delay before an automatic restart attempt
   */
  public AppManifest {
    AppBundleManifest normalized =
        new AppBundleManifest(
            manifestVersion,
            appId,
            appName,
            appVersion,
            execPathText,
            uiMode,
            uiEntry,
            permissions,
            apiCompatibility,
            dataQuotaBytes,
            cacheQuotaBytes,
            Objects.requireNonNullElse(sandboxPolicy, AppSandboxPolicy.defaults()).mode(),
            sandboxPolicy != null && sandboxPolicy.required(),
            restartPolicy,
            restartMaxAttempts,
            restartBackoffMillis);
    manifestVersion = normalized.manifestVersion();
    appId = normalized.appId();
    appName = normalized.appName();
    appVersion = normalized.appVersion();
    execPathText = normalized.execPathText();
    uiMode = normalized.uiMode();
    uiEntry = normalized.uiEntry();
    permissions = normalized.permissions();
    apiCompatibility = normalized.apiCompatibility();
    dataQuotaBytes = normalized.dataQuotaBytes();
    cacheQuotaBytes = normalized.cacheQuotaBytes();
    sandboxPolicy = new AppSandboxPolicy(normalized.sandboxMode(), normalized.sandboxRequired());
    restartPolicy = normalized.restartPolicy();
    restartMaxAttempts = normalized.restartMaxAttempts();
    restartBackoffMillis = normalized.restartBackoffMillis();
  }

  /**
   * Creates a manifest with no API compatibility metadata.
   *
   * <p>This overload preserves source compatibility for callers that construct AppHost manifests
   * directly using the pre-compatibility constructor shape.
   *
   * @param manifestVersion manifest schema version
   * @param appId stable path-safe app identifier
   * @param appName human-readable application name
   * @param appVersion display version string
   * @param execPathText executable path relative to the installed app root
   * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
   * @param uiEntry optional UI entry path, or {@code null}
   * @param permissions normalized permission strings
   * @param dataQuotaBytes optional data quota metadata, or {@code null}
   * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
   * @param sandboxPolicy requested process sandbox policy
   * @param restartPolicy normalized process restart policy
   * @param restartMaxAttempts maximum automatic restart attempts for one daemon-managed run
   * @param restartBackoffMillis delay before an automatic restart attempt
   */
  public AppManifest(
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
      AppSandboxPolicy sandboxPolicy,
      AppRestartPolicy restartPolicy,
      int restartMaxAttempts,
      long restartBackoffMillis) {
    this(
        manifestVersion,
        appId,
        appName,
        appVersion,
        execPathText,
        uiMode,
        uiEntry,
        permissions,
        AppApiCompatibilityMetadata.undeclared(),
        dataQuotaBytes,
        cacheQuotaBytes,
        sandboxPolicy,
        restartPolicy,
        restartMaxAttempts,
        restartBackoffMillis);
  }

  /**
   * Creates a manifest with explicit restart policy and default no-sandbox policy.
   *
   * @param manifestVersion manifest schema version
   * @param appId stable path-safe app identifier
   * @param appName human-readable application name
   * @param appVersion display version string
   * @param execPathText executable path relative to the installed app root
   * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
   * @param uiEntry optional UI entry path, or {@code null}
   * @param permissions normalized permission strings
   * @param dataQuotaBytes optional data quota metadata, or {@code null}
   * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
   * @param restartPolicy normalized process restart policy
   * @param restartMaxAttempts maximum automatic restart attempts for one daemon-managed run
   * @param restartBackoffMillis delay before an automatic restart attempt
   */
  public AppManifest(
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
        AppSandboxPolicy.defaults(),
        restartPolicy,
        restartMaxAttempts,
        restartBackoffMillis);
  }

  /**
   * Creates a manifest with explicit sandbox fields and the default restart policy.
   *
   * @param manifestVersion manifest schema version
   * @param appId stable path-safe app identifier
   * @param appName human-readable application name
   * @param appVersion display version string
   * @param execPathText executable path relative to the installed app root
   * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
   * @param uiEntry optional UI entry path, or {@code null}
   * @param permissions normalized permission strings
   * @param dataQuotaBytes optional data quota metadata, or {@code null}
   * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
   * @param sandboxMode requested process sandbox mode
   * @param sandboxRequired whether launch must fail when the requested sandbox mode is unsupported
   */
  public AppManifest(
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
      AppSandboxMode sandboxMode,
      boolean sandboxRequired) {
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
        new AppSandboxPolicy(sandboxMode, sandboxRequired),
        AppRestartPolicy.NEVER,
        0,
        0L);
  }

  /**
   * Creates a manifest with the default restart policy.
   *
   * @param manifestVersion manifest schema version
   * @param appId stable path-safe app identifier
   * @param appName human-readable application name
   * @param appVersion display version string
   * @param execPathText executable path relative to the installed app root
   * @param uiMode normalized browser UI ownership mode declared or inferred from the manifest
   * @param uiEntry optional UI entry path, or {@code null}
   * @param permissions normalized permission strings
   * @param dataQuotaBytes optional data quota metadata, or {@code null}
   * @param cacheQuotaBytes optional cache quota metadata, or {@code null}
   */
  public AppManifest(
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
        AppSandboxPolicy.defaults(),
        AppRestartPolicy.NEVER,
        0,
        0L);
  }

  /**
   * Creates a manifest using the appdist-owned backward-compatible UI-mode inference rules.
   *
   * <p>This overload preserves source compatibility for tests and embeddings that construct AppHost
   * manifests directly. Text parsed from {@code cryptad-app.properties} normally arrives through
   * {@link AppManifestParser}, which supplies the canonical normalized mode.
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
  public AppManifest(
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
        new AppBundleManifest(
            manifestVersion,
            appId,
            appName,
            appVersion,
            execPathText,
            uiEntry,
            permissions,
            dataQuotaBytes,
            cacheQuotaBytes));
  }

  private AppManifest(AppBundleManifest manifest) {
    this(
        manifest.manifestVersion(),
        manifest.appId(),
        manifest.appName(),
        manifest.appVersion(),
        manifest.execPathText(),
        manifest.uiMode(),
        manifest.uiEntry(),
        manifest.permissions(),
        manifest.apiCompatibility(),
        manifest.dataQuotaBytes(),
        manifest.cacheQuotaBytes(),
        new AppSandboxPolicy(manifest.sandboxMode(), manifest.sandboxRequired()),
        manifest.restartPolicy(),
        manifest.restartMaxAttempts(),
        manifest.restartBackoffMillis());
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
   * Returns the static UI entry as a normalized relative installed-bundle path.
   *
   * @return normalized static UI entry path within the installed bundle
   * @throws IllegalStateException if this manifest does not declare a static UI
   */
  public Path staticUiEntryPath() {
    if (uiMode != AppUiMode.STATIC) {
      throw new IllegalStateException("app.ui.mode is not static: " + uiMode.manifestValue());
    }
    return Path.of(uiEntry).normalize();
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
    String trimmed = Objects.requireNonNull(appId, "app.id").trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException("app.id must not be blank");
    }
    String normalized = trimmed.toLowerCase(Locale.ROOT);
    InstalledAppPaths.normalizeAppId(normalized);
    return normalized;
  }
}
