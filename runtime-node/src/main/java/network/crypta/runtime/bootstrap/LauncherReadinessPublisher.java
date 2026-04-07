package network.crypta.runtime.bootstrap;

import java.io.IOException;
import java.nio.file.Path;
import network.crypta.fs.readiness.LauncherReadinessFiles;
import network.crypta.fs.readiness.LauncherReadinessInfo;

/**
 * Publishes the daemon-to-launcher readiness file once the HTTP shell is fully usable.
 *
 * <p>This helper keeps the small readiness-file write protocol out of the node kernel while letting
 * runtime startup publish the structured launcher signal at the existing post-start lifecycle hook.
 */
public final class LauncherReadinessPublisher {
  /** Utility holder; use {@link #publishReady(Path, int)} instead of creating instances. */
  private LauncherReadinessPublisher() {}

  /**
   * Writes the current ready payload beneath the supplied runtime directory.
   *
   * @param runDir resolved runtime directory used by the active daemon process
   * @param listenPort HTTP port that the launcher should open once the shell is ready
   * @throws IOException if the readiness file cannot be written
   */
  @SuppressWarnings("unused")
  public static void publishReady(Path runDir, int listenPort) throws IOException {
    publishReady(runDir, listenPort, LauncherReadinessInfo.DEFAULT_UI_ROOT);
  }

  /**
   * Writes the current ready payload beneath the supplied runtime directory.
   *
   * @param runDir resolved runtime directory used by the active daemon process
   * @param listenPort HTTP port that the launcher should open once the shell is ready
   * @param uiRoot primary browser-facing UI root that the launcher should open
   * @throws IOException if the readiness file cannot be written
   */
  public static void publishReady(Path runDir, int listenPort, String uiRoot) throws IOException {
    LauncherReadinessFiles.write(
        LauncherReadinessFiles.resolve(runDir), LauncherReadinessInfo.ready(listenPort, uiRoot));
  }
}
