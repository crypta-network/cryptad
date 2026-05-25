package network.crypta.platform.apphost;

/**
 * Operator choices for removing an installed app.
 *
 * <p>The default uninstall behavior removes the immutable bundle and all host-owned mutable state.
 * Setting {@link #preserveData()} keeps the app's persistent data directory, including host-managed
 * durable app-data records, while still removing the immutable bundle, cache, run state, rollback
 * bundle, and live runtime bookkeeping. This option is intended for explicit operator-controlled
 * reinstall or migration workflows, not for app-originated self-preservation.
 *
 * <p>Callers that accept Platform API requests must decide whether a principal is allowed to
 * request preservation before creating these options. AppHost treats the options as an already
 * authorized local management decision and applies them to the filesystem cleanup step only.
 *
 * <p>Preserved data is still scoped to the same normalized app id. Reinstalling a different app id
 * does not gain access to the retained directory, and preserving data does not keep process tokens,
 * browser sessions, cache files, or run-state artifacts.
 *
 * @param preserveData whether the persistent per-app data directory should survive uninstall
 */
public record AppUninstallOptions(boolean preserveData) {
  private static final AppUninstallOptions REMOVE_ALL = new AppUninstallOptions(false);

  /**
   * Returns the default behavior: remove bundle, data, cache, run state, and rollback data.
   *
   * <p>This is the behavior used by the legacy {@code uninstall(appId)} overload and by
   * app-originated uninstall requests. It leaves no preserved per-app durable state behind.
   *
   * @return default uninstall options that remove all app-owned local state
   */
  public static AppUninstallOptions removeAll() {
    return REMOVE_ALL;
  }

  /**
   * Returns options that keep the persistent per-app data directory.
   *
   * <p>Operators can use this mode before reinstalling, migrating, or temporarily removing an app
   * while keeping user-owned local state. The immutable bundle and runtime artifacts are still
   * removed, so the option is not a rollback mechanism.
   *
   * @return uninstall options for preserving persistent app data
   */
  public static AppUninstallOptions preservingData() {
    return new AppUninstallOptions(true);
  }
}
