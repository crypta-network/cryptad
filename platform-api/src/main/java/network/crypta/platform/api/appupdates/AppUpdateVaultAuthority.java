package network.crypta.platform.api.appupdates;

import java.util.LinkedHashSet;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Applies post-update AppVault grant cleanup without exposing vault failures to callers.
 *
 * <p>An app update may remove permissions that previously authorized access to AppVault entries.
 * After AppHost commits the new bundle, the lifecycle passes the resulting installed snapshot to
 * this helper. The helper derives the exact current permission set and asks AppVault to disable
 * grants that no longer have a matching permission.
 *
 * <p>Cleanup is best-effort because it occurs after the bundle commit. A missing vault service is
 * treated as successful cleanup, while a vault-domain failure is reported to the lifecycle as a
 * boolean so it can produce a bounded warning. The utility has no mutable state and is safe for
 * concurrent callers when the supplied AppVault service is safe for concurrent use.
 */
final class AppUpdateVaultAuthority {
  /** Prevents construction of this stateless utility. */
  private AppUpdateVaultAuthority() {}

  /**
   * Disables grants for vault permissions absent from the committed manifest.
   *
   * @param appVaultService configured vault service, or {@code null} when unavailable
   * @param updated installed snapshot produced by the completed update
   * @return {@code true} when cleanup succeeded or no service is configured
   */
  static boolean disableRemovedGrants(
      AppVaultService appVaultService, InstalledAppSnapshot updated) {
    if (appVaultService == null) {
      return true;
    }
    try {
      appVaultService.disableGrantsForRemovedVaultPermissions(
          updated.appId(), new LinkedHashSet<>(updated.manifest().permissions()));
      return true;
    } catch (AppVaultException _) {
      return false;
    }
  }
}
