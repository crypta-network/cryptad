package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.nio.file.Path;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import network.crypta.platform.apphost.manifest.AppManifestParser;

/**
 * Provides the staged-bundle operations shared by the app update lifecycle.
 *
 * <p>This package-private helper keeps manifest format knowledge out of {@link AppUpdateService}.
 * It resolves and parses the canonical manifest from an already prepared bundle directory, and it
 * classifies the AppHost failures that describe an invalid staged bundle. Callers remain
 * responsible for mapping those failures to the appropriate lifecycle response and for closing
 * retained catalog plans.
 *
 * <p>The helper does not authorize catalogs, publishers, reviewers, or migrations. It reads only
 * the staged manifest selected by the caller and preserves the parser and AppHost exception
 * semantics used before this responsibility was extracted. The type has no mutable state and is
 * safe to use from concurrent update checks.
 */
final class AppUpdateBundleSupport {
  /** Prevents construction of this stateless utility type. */
  private AppUpdateBundleSupport() {}

  /**
   * Reads the canonical manifest from a staged bundle directory.
   *
   * @param stagedBundleDirectory root of the already prepared app bundle
   * @return the parsed and validated app manifest
   * @throws IOException if the manifest is absent, unreadable, or invalid
   */
  static AppManifest readManifest(Path stagedBundleDirectory) throws IOException {
    return AppManifestParser.parse(
        stagedBundleDirectory.resolve(AppManifestParser.MANIFEST_FILE_NAME));
  }

  /**
   * Reports whether an AppHost failure describes invalid staged bundle content.
   *
   * @param exception failure returned by an AppHost install or update operation
   * @return {@code true} when the failure identifies an invalid manifest or bundle shape
   */
  static boolean isInvalidBundleFailure(AppHostException exception) {
    if (exception instanceof AppManifestException) {
      return true;
    }
    String message = exception.getMessage();
    if (message == null || message.isBlank()) {
      return false;
    }
    return message.startsWith("stagedAppDirectory ")
        || message.startsWith("staging directory ")
        || message.startsWith("copied manifest ")
        || message.startsWith("copied app.exec ")
        || message.startsWith("app.ui.entry ")
        || message.startsWith("app.exec ")
        || message.startsWith("staged app bundle ");
  }

  /**
   * Reports whether an AppHost failure came from signed-bundle verification.
   *
   * @param exception failure returned by an AppHost install or update operation
   * @return {@code true} when signed-bundle verification rejected the staged bundle
   */
  static boolean isSignedBundleVerificationFailure(AppHostException exception) {
    return exception instanceof AppBundleVerificationException;
  }
}
