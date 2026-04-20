package network.crypta.platform.apphost.manifest;

import java.io.IOException;
import java.nio.file.Path;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Parser and validator for the v1 app-host manifest format.
 *
 * <p>This AppHost-facing adapter delegates the low-level parsing rules to the appdist leaf so the
 * staged-bundle tooling and runtime installation flow stay aligned on manifest semantics.
 */
public final class AppManifestParser {
  /** Canonical manifest filename stored at the installed app root. */
  public static final String MANIFEST_FILE_NAME = AppBundleManifestParser.MANIFEST_FILE_NAME;

  private AppManifestParser() {}

  /**
   * Parses a manifest from UTF-8 text content.
   *
   * @param content manifest content in properties-style syntax
   * @return the validated AppHost manifest snapshot
   * @throws IOException if the manifest content is invalid, incomplete, or cannot be normalized
   */
  public static AppManifest parseContent(String content) throws IOException {
    try {
      return toAppManifest(AppBundleManifestParser.parseContent(content));
    } catch (AppDistributionException exception) {
      throw new AppManifestException(exception.getMessage(), exception);
    }
  }

  /**
   * Parses a manifest from an on-disk properties file.
   *
   * @param manifestFile path to {@code cryptad-app.properties}
   * @return the validated AppHost manifest snapshot
   * @throws IOException if the file cannot be read safely or the manifest content is invalid
   */
  public static AppManifest parse(Path manifestFile) throws IOException {
    try {
      return toAppManifest(AppBundleManifestParser.parse(manifestFile));
    } catch (AppDistributionException exception) {
      throw new AppManifestException(exception.getMessage(), exception);
    }
  }

  private static AppManifest toAppManifest(AppBundleManifest manifest) {
    return new AppManifest(
        manifest.manifestVersion(),
        manifest.appId(),
        manifest.appName(),
        manifest.appVersion(),
        manifest.execPathText(),
        manifest.uiEntry(),
        manifest.permissions(),
        manifest.dataQuotaBytes(),
        manifest.cacheQuotaBytes());
  }
}
