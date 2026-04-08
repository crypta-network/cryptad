package network.crypta.platform.apphost;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * Transport-neutral host API for locally installed out-of-process applications.
 *
 * <p>{@code AppHost} defines the narrow lifecycle surface that higher-level shells, transports, and
 * future management APIs use to interact with locally installed app bundles. The interface is
 * intentionally conservative for AppHost v1: it installs validated bundles from a caller-supplied
 * staging directory, exposes immutable installation metadata, and manages at most one live child
 * process per installed application identifier.
 *
 * <p>Implementations are responsible for keeping host-owned filesystem layout and runtime state
 * consistent with the returned snapshots. Callers can treat {@link InstalledAppSnapshot} and {@link
 * RunningAppSnapshot} as point-in-time views rather than persistent handles. A later call to {@link
 * #describe(String)}, {@link #status(String)}, or {@link #listRunning()} may therefore reflect
 * newer filesystem or process state than an earlier snapshot.
 */
public interface AppHost {
  /**
   * Installs one app from a local staging directory.
   *
   * <p>The staging directory is treated as caller-owned input. Implementations validate the
   * manifest, copy the bundle into host-managed storage, provision any required mutable
   * directories, and return a snapshot that reflects the installed copy rather than the original
   * staging path.
   *
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties} and the
   *     files referenced by the manifest
   * @return installed application snapshot describing the copied bundle and derived host paths
   * @throws IOException if validation fails, filesystem boundaries are unsafe, the bundle cannot be
   *     copied, or host-owned directories cannot be provisioned
   */
  InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory) throws IOException;

  /**
   * Replaces one installed app bundle from a local staging directory.
   *
   * <p>The supplied staging directory is validated using the same caller-owned input rules as
   * installation, but the staged manifest must target the already-installed app being updated.
   * Implementations replace only the immutable installed bundle contents. The host-owned data,
   * cache, and run directories remain attached to the existing app id and are preserved across the
   * update.
   *
   * <p>AppHost v1 keeps update semantics intentionally narrow and explicit: the target app must
   * already be installed and must not be running. Implementations should therefore reject updates
   * for missing or live apps rather than attempting implicit stop/start choreography.
   *
   * @param appId stable application identifier
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties} and the
   *     files referenced by the manifest
   * @return installed application snapshot describing the replaced bundle and preserved host paths
   * @throws IOException if validation fails, the staged bundle targets a different app id, the app
   *     is missing or still running, or the replacement cannot be completed safely
   */
  InstalledAppSnapshot updateFromDirectory(String appId, Path stagedAppDirectory)
      throws IOException;

  /**
   * Removes one installed app and its host-owned directories.
   *
   * <p>This operation removes both the immutable installed bundle and the mutable per-app data,
   * cache, and run directories that belong to the host layout. Implementations are expected to
   * reject removal while the app is still running, so callers do not delete files out from under a
   * live child process.
   *
   * @param appId stable application identifier
   * @throws IOException if the app is still running, is not installed, or any owned files cannot be
   *     removed cleanly
   */
  void uninstall(String appId) throws IOException;

  /**
   * Lists all installed apps.
   *
   * <p>The returned list is a fresh filesystem-backed snapshot. Callers should not assume the list
   * remains current after the method returns, especially if another actor is installing or
   * uninstalling applications concurrently.
   *
   * @return installed application snapshots sorted by app id
   * @throws IOException if the installed-app tree cannot be scanned, or one of the installed
   *     manifests cannot be read safely
   */
  List<InstalledAppSnapshot> listInstalled() throws IOException;

  /**
   * Describes one installed app.
   *
   * @param appId stable application identifier
   * @return installed snapshot when the application is present, or {@link Optional#empty()} when it
   *     is not installed
   * @throws IOException if the installed-app tree cannot be read safely or the installed manifest
   *     is invalid
   */
  Optional<InstalledAppSnapshot> describe(String appId) throws IOException;

  /**
   * Starts one installed app as a child process.
   *
   * <p>Implementations are expected to validate the installed bundle again at launch time, create
   * or refresh runtime directories, start the child process, and return a snapshot that includes a
   * fresh launch token and representative process identifier. A successful return means the host
   * considers the app running and manageable through {@link #status(String)} and {@link
   * #stop(String)}.
   *
   * @param appId stable application identifier
   * @return running snapshot including the fresh launch token and launch timestamp
   * @throws IOException if the app is not installed, is already running, or the child process
   *     cannot be launched and tracked successfully
   */
  RunningAppSnapshot start(String appId) throws IOException;

  /**
   * Stops one running app if it is active.
   *
   * <p>A return value of {@code false} means the host had no live process to stop at the time of
   * the call. A return value of {@code true} means the host successfully transitioned a running app
   * to the stopped state. Implementations may use graceful termination followed by escalation, but
   * they should not report success while a recovered child process is still running.
   *
   * @param appId stable application identifier
   * @return {@code true} when a running process was found and stopped; {@code false} when no live
   *     process was present
   * @throws IOException if a running app cannot be stopped cleanly within the implementation's
   *     shutdown policy
   */
  boolean stop(String appId) throws IOException;

  /**
   * Returns the current live process snapshot, if any.
   *
   * @param appId stable application identifier
   * @return running snapshot when the app is still tracked as live, or {@link Optional#empty()}
   *     when it is not currently running
   */
  Optional<RunningAppSnapshot> status(String appId);

  /**
   * Lists all live child processes.
   *
   * <p>The returned list is a point-in-time runtime view. It is sorted by app id to give callers a
   * stable ordering for display, polling, and test assertions.
   *
   * @return immutable list of running snapshots sorted by app id
   */
  List<RunningAppSnapshot> listRunning();
}
