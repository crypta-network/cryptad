package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Transport-neutral host API for locally installed out-of-process applications.
 *
 * <p>The interface stays intentionally small for AppHost v1: install from a local staging
 * directory, list and describe installed apps, and manage one running child process per app.
 */
public interface AppHost {
  /**
   * Installs one app from a local staging directory.
   *
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties}
   * @return installed application snapshot
   * @throws IOException if validation, copying, or directory provisioning fails
   */
  InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory) throws IOException;

  /**
   * Removes one installed app and its host-owned directories.
   *
   * @param appId stable application identifier
   * @throws IOException if the app is running, missing, or cannot be removed
   */
  void uninstall(String appId) throws IOException;

  /**
   * Lists all installed apps.
   *
   * @return installed application snapshots sorted by app id
   * @throws IOException if the installed-app tree cannot be scanned
   */
  List<InstalledAppSnapshot> listInstalled() throws IOException;

  /**
   * Describes one installed app.
   *
   * @param appId stable application identifier
   * @return installed snapshot when present
   * @throws IOException if the installed-app tree cannot be read
   */
  Optional<InstalledAppSnapshot> describe(String appId) throws IOException;

  /**
   * Starts one installed app as a child process.
   *
   * @param appId stable application identifier
   * @return running snapshot including the fresh launch token
   * @throws IOException if the child process cannot be launched
   */
  RunningAppSnapshot start(String appId) throws IOException;

  /**
   * Stops one running app if it is active.
   *
   * @param appId stable application identifier
   * @return {@code true} when a running process was stopped; {@code false} otherwise
   * @throws IOException if the child process cannot be stopped cleanly
   */
  boolean stop(String appId) throws IOException;

  /**
   * Returns the current live process snapshot, if any.
   *
   * @param appId stable application identifier
   * @return running snapshot when the child is alive
   */
  Optional<RunningAppSnapshot> status(String appId);

  /**
   * Lists all live child processes.
   *
   * @return immutable list of running snapshots sorted by app id
   */
  List<RunningAppSnapshot> listRunning();
}
