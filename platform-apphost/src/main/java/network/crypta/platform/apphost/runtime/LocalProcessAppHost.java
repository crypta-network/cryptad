package network.crypta.platform.apphost.runtime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import network.crypta.fs.AppEnv;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.jetbrains.annotations.NotNull;

/**
 * Default AppHost implementation that launches installed apps out of process.
 *
 * <p>{@code LocalProcessAppHost} is the concrete AppHost v1 runtime that manages validated app
 * bundles on the local filesystem and launches them as child processes of the current daemon. It
 * owns the install-time copy flow, mutable directory preparation, launch environment injection,
 * process-tree tracking, shutdown escalation, and best-effort recovery for wrapper and daemonizing
 * launch patterns across supported platforms.
 *
 * <p>The implementation keeps the runtime state in memory only. It is intended to be the reusable
 * local execution core beneath future shell and transport layers, not a full sandbox or persistent
 * supervisor. It therefore does not attempt to restart recovery across daemon restarts or hard
 * enforcement of manifest quota hints.
 */
public final class LocalProcessAppHost implements AppHost {
  private static final Duration DEFAULT_STOP_TIMEOUT = Duration.ofSeconds(5);
  private static final String TEMP_INSTALL_PREFIX = "app-install-";
  private static final String TEMP_UPDATE_BACKUP_PREFIX = TEMP_INSTALL_PREFIX + "backup-";
  private static final String LOCAL_DIRECTORY_NAME = "local";
  private static final String INSTALLED_APPS_DIR_LABEL = "installedAppsDir";
  private static final String WINDOWS_SYSTEM32_DIRECTORY = "System32";
  private static final String PROC_ROOT = "/proc";
  private static final List<String> WINDOWS_ROOT_ENVIRONMENT_NAMES =
      List.of("SystemRoot", "SYSTEMROOT", "WINDIR");
  private static final int MAX_SHEBANG_PROBE_BYTES = 4096;
  private static final int DOS_HEADER_SIZE = 64;
  private static final int PE_POINTER_OFFSET = 0x3C;
  private static final int COFF_HEADER_SIZE = 24;
  private static final int IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
  private static final int IMAGE_FILE_DLL = 0x2000;
  static final TimingConfig DEFAULT_TIMING =
      new TimingConfig(
          Duration.ofSeconds(2),
          Duration.ofMillis(500),
          Duration.ofMillis(200),
          Duration.ofMillis(200),
          Duration.ofMillis(100),
          Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(100)),
          Duration.ofMillis(5),
          Duration.ofMillis(100));
  private static final List<String> BASE_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/usr", "bin").toString(),
          Path.of("/bin").toString(),
          Path.of("/usr", "sbin").toString(),
          Path.of("/sbin").toString(),
          Path.of("/usr", LOCAL_DIRECTORY_NAME, "bin").toString(),
          Path.of("/usr", LOCAL_DIRECTORY_NAME, "sbin").toString());
  private static final List<String> MAC_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/opt", "homebrew", "bin").toString(),
          Path.of("/opt", "homebrew", "sbin").toString(),
          Path.of("/opt", LOCAL_DIRECTORY_NAME, "bin").toString(),
          Path.of("/opt", LOCAL_DIRECTORY_NAME, "sbin").toString());
  private static final List<String> LINUX_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/home", "linuxbrew", ".linuxbrew", "bin").toString(),
          Path.of("/home", "linuxbrew", ".linuxbrew", "sbin").toString());
  private static final int TOKEN_BYTES = 32;

  private final AppHostLayout layout;
  private final Duration stopTimeout;
  private final SecureRandom secureRandom;
  private final AppEnv appEnv;
  private final TimingConfig timing;
  private final ManagedTreeDeleter managedTreeDeleter;
  private final Map<String, RunningProcess> runningApps = new ConcurrentHashMap<>();

  /**
   * Creates a host bound to the supplied layout.
   *
   * <p>This convenience constructor uses the default stop timeout, a fresh secure token generator,
   * and the ambient {@link AppEnv} for platform detection.
   *
   * @param layout filesystem layout managed by the host
   */
  @SuppressWarnings("unused")
  public LocalProcessAppHost(AppHostLayout layout) {
    this(layout, DEFAULT_STOP_TIMEOUT, new SecureRandom(), new AppEnv());
  }

  /**
   * Creates a host with an explicit stop timeout and token generator.
   *
   * <p>This overload is primarily useful for tests and controlled embeddings that need a
   * non-default shutdown policy or deterministic token generation while still using the ambient
   * platform environment.
   *
   * @param layout filesystem layout managed by the host
   * @param stopTimeout bounded timeout used before force-killing a child process
   * @param secureRandom secure token generator for launch-token generation
   */
  public LocalProcessAppHost(
      AppHostLayout layout, Duration stopTimeout, SecureRandom secureRandom) {
    this(layout, stopTimeout, secureRandom, new AppEnv(), DEFAULT_TIMING);
  }

  LocalProcessAppHost(
      AppHostLayout layout, Duration stopTimeout, SecureRandom secureRandom, AppEnv appEnv) {
    this(layout, stopTimeout, secureRandom, appEnv, DEFAULT_TIMING);
  }

  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing) {
    this(layout, stopTimeout, secureRandom, appEnv, timing, LocalProcessAppHost::deleteRecursively);
  }

  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing,
      ManagedTreeDeleter managedTreeDeleter) {
    this.layout = Objects.requireNonNull(layout, "layout");
    this.stopTimeout = Objects.requireNonNull(stopTimeout, "stopTimeout");
    this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
    this.appEnv = Objects.requireNonNull(appEnv, "appEnv");
    this.timing = Objects.requireNonNull(timing, "timing");
    this.managedTreeDeleter = Objects.requireNonNull(managedTreeDeleter, "managedTreeDeleter");
    if (stopTimeout.isZero() || stopTimeout.isNegative()) {
      throw new IllegalArgumentException("stopTimeout must be positive");
    }
  }

  /**
   * Installs one app from a local staging directory.
   *
   * <p>The staging tree is treated as caller-controlled input. The host validates that tree and
   * copies it into a temporary managed location. It then parses the copied manifest, validates the
   * copied executable, provisions the mutable directories that belong to the derived app id, and
   * moves the copied bundle into place atomically when possible.
   *
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties}
   * @return installed application snapshot describing the copied bundle and managed paths
   * @throws IOException if the staging tree is unsafe, the bundle is invalid, host-owned path
   *     boundaries are violated, or the copied bundle cannot be installed cleanly
   */
  @Override
  public synchronized InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory)
      throws IOException {
    Path stagingRoot = normalizeExistingDirectory(stagedAppDirectory);
    rejectOverlappingInstallTree(stagingRoot, layout.installedAppsDir());
    Path installedAppsDir = layout.installedAppsDir();
    ensureManagedDirectory(layout.dataDir(), installedAppsDir);
    Path temporaryInstallRoot = Files.createTempDirectory(installedAppsDir, TEMP_INSTALL_PREFIX);
    try {
      copyDirectoryTree(stagingRoot, temporaryInstallRoot);
      AppManifest manifest = validateCopiedBundle(temporaryInstallRoot);
      InstalledAppPaths paths = layout.pathsFor(manifest.appId());
      rejectOverlappingMutableAppDirectories(stagingRoot, paths);
      if (Files.exists(paths.installedRoot())) {
        throw new AppHostException("app already installed: " + manifest.appId());
      }
      validateManagedMutableDirectories(paths);
      paths.ensureMutableDirectories();
      moveIntoPlace(temporaryInstallRoot, paths.installedRoot());
      return new InstalledAppSnapshot(manifest, paths);
    } catch (IOException | RuntimeException e) {
      deleteRecursively(temporaryInstallRoot);
      throw e;
    }
  }

  /**
   * Replaces one installed app bundle from a local staging directory.
   *
   * <p>The update flow deliberately reuses the installation model: the caller provides a local
   * staged directory, the host copies and validates that bundle under managed storage, and the
   * staged manifest must target the same normalized app id as the existing installation. Only the
   * immutable installed bundle root is replaced. The host-owned data, cache, and run directories
   * remain in place and are preserved.
   *
   * <p>AppHost v1 keeps replacement conservative and explicit. The target app must already be
   * installed and stopped before any filesystem mutation occurs.
   *
   * @param appId stable application identifier
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties}
   * @return installed application snapshot describing the replaced bundle and preserved host paths
   * @throws IOException if the app is missing or still running, the staged bundle is invalid or
   *     targets a different app id, or the replacement cannot be completed safely
   */
  @Override
  public synchronized InstalledAppSnapshot updateFromDirectory(
      String appId, Path stagedAppDirectory) throws IOException {
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    Path stagingRoot = normalizeExistingDirectory(stagedAppDirectory);
    Path installedAppsDir = validateInstalledAppsDirectory();
    rejectOverlappingInstallTree(stagingRoot, installedAppsDir);
    InstalledAppPaths paths = layout.pathsFor(normalizedAppId);
    rejectOverlappingMutableAppDirectories(stagingRoot, paths);
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("cannot update a running app: " + normalizedAppId);
    }
    if (!Files.isDirectory(paths.installedRoot(), LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException("app is not installed: " + normalizedAppId);
    }
    validateManagedMutableDirectories(paths);
    paths.ensureMutableDirectories();

    Path temporaryInstallRoot = Files.createTempDirectory(installedAppsDir, TEMP_INSTALL_PREFIX);
    Path backupInstallRoot =
        temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");
    try {
      copyDirectoryTree(stagingRoot, temporaryInstallRoot);
      AppManifest manifest = validateCopiedBundle(temporaryInstallRoot);
      requireMatchingUpdateTarget(normalizedAppId, manifest);
      replaceInstalledBundle(paths.installedRoot(), temporaryInstallRoot, backupInstallRoot);
      return new InstalledAppSnapshot(manifest, paths);
    } catch (IOException | RuntimeException e) {
      deleteScratchTreeIfPresent(temporaryInstallRoot);
      throw e;
    }
  }

  /**
   * Removes one installed app and its host-owned directories.
   *
   * <p>The host revalidates the managed installation tree before deletion and refuses to uninstall
   * a live app, so callers do not remove files that a running process is still using.
   *
   * @param appId stable application identifier
   * @throws IOException if the app is running, missing, outside the validated managed tree, or any
   *     owned files cannot be removed
   */
  @Override
  public synchronized void uninstall(String appId) throws IOException {
    validateInstalledAppsDirectory();
    InstalledAppPaths paths = layout.pathsFor(appId);
    if (liveRunningProcess(paths.appId()) != null) {
      throw new AppHostException("cannot uninstall a running app: " + appId);
    }
    if (!Files.exists(paths.installedRoot())) {
      throw new AppHostException("app is not installed: " + appId);
    }

    deleteRecursively(paths.installedRoot());
    deleteRecursively(paths.dataDir());
    deleteRecursively(paths.cacheDir());
    deleteRecursively(paths.runDir());
  }

  /**
   * Lists all installed apps.
   *
   * <p>The result is built from the validated managed installation tree and sorted by directory
   * name. Temporary install leftovers and non-app entries are skipped so stale partial
   * installations do not poison the whole listing operation.
   *
   * @return installed application snapshots sorted by app id
   * @throws IOException if the managed installation tree cannot be validated or scanned safely
   */
  @Override
  public synchronized List<InstalledAppSnapshot> listInstalled() throws IOException {
    Path installedAppsDir = validateInstalledAppsDirectory();
    if (!Files.isDirectory(installedAppsDir, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }

    List<InstalledAppSnapshot> installed = new ArrayList<>();
    try (var children = Files.list(installedAppsDir)) {
      for (Path appRoot :
          children.sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
        if (shouldSkipInstalledEntry(appRoot)) {
          continue;
        }
        AppManifest manifest = readInstalledManifest(appRoot);
        installed.add(new InstalledAppSnapshot(manifest, layout.pathsFor(manifest.appId())));
      }
    }
    return List.copyOf(installed);
  }

  /**
   * Describes one installed app.
   *
   * @param appId stable application identifier
   * @return installed snapshot when present, or {@link Optional#empty()} when the app is not
   *     currently installed
   * @throws IOException if the managed installation tree cannot be validated, or the installed
   *     manifest cannot be read safely
   */
  @Override
  public synchronized Optional<InstalledAppSnapshot> describe(String appId) throws IOException {
    validateInstalledAppsDirectory();
    InstalledAppPaths paths = layout.pathsFor(appId);
    if (!Files.isDirectory(paths.installedRoot(), LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(
        new InstalledAppSnapshot(readInstalledManifest(paths.installedRoot()), paths));
  }

  /**
   * Starts one installed app as a child process.
   *
   * <p>Launch revalidates the installed manifest and executable. It recreates mutable directories
   * as needed, clears the previous process log, injects a fresh launch token into the child
   * environment, and then observes the launched process tree long enough to reject immediate
   * failures or capture a daemonized handoff.
   *
   * @param appId stable application identifier
   * @return running snapshot including the launch token, representative pid, and start timestamp
   * @throws IOException if the app is not installed, is already running, fails validation at launch
   *     time, or cannot be launched and tracked as a live process
   */
  @Override
  public synchronized RunningAppSnapshot start(String appId) throws IOException {
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("app is already running: " + appId);
    }

    InstalledAppSnapshot installation =
        describe(normalizedAppId)
            .orElseThrow(() -> new AppHostException("app is not installed: " + appId));
    InstalledAppPaths paths = installation.paths();
    validateManagedMutableDirectories(paths);
    paths.ensureMutableDirectories();
    Files.deleteIfExists(paths.processLogFile());

    Path executable =
        resolveBundleEntry(
            paths.installedRoot(), installation.manifest().execPath(), "installed app.exec");
    if (!Files.isRegularFile(executable, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(
          "installed app.exec does not exist: " + installation.manifest().execPathText());
    }

    String token = generateToken();
    List<String> command = launchCommand(executable);
    ProcessBuilder builder = new ProcessBuilder(command);
    builder.directory(paths.installedRoot().toFile());
    builder.redirectErrorStream(true);
    builder.redirectOutput(ProcessBuilder.Redirect.appendTo(paths.processLogFile().toFile()));
    populateEnvironment(builder.environment(), installation.manifest(), paths, token, appEnv);

    Instant startedAt = Instant.now();
    Process process = builder.start();
    discardChildInput(process, appId);
    List<ProcessHandle> startupProcessTree = observeStartupProcessTree(process, normalizedAppId);
    if (startupProcessTree.isEmpty()) {
      startupProcessTree =
          recoverTrackedProcesses(
              installation.manifest(),
              paths,
              token,
              startedAt,
              List.of(process.toHandle()),
              ProcessHandle.allProcesses().toList());
    }
    if (startupProcessTree.isEmpty()) {
      throw startupFailure(appId, process);
    }
    RunningAppSnapshot snapshot =
        new RunningAppSnapshot(
            installation.manifest(),
            paths,
            token,
            representativePid(
                startupProcessTree,
                process.pid(),
                preferDescendantPid(executable, startupProcessTree)),
            startedAt);
    CompletableFuture<Void> exitCleanup = new CompletableFuture<>();
    RunningProcess runningProcess =
        new RunningProcess(process, snapshot, exitCleanup, startupProcessTree);
    runningApps.put(normalizedAppId, runningProcess);
    startTrackedProcessTreeObserver(normalizedAppId, process, exitCleanup);
    RunningProcess liveRunningProcess = liveRunningProcess(normalizedAppId);
    if (liveRunningProcess == null) {
      throw startupFailure(appId, process);
    }
    return liveRunningProcess.snapshot();
  }

  /**
   * Stops one running app if it is active.
   *
   * <p>The shutdown flow refreshes the tracked process tree, attempts graceful termination first,
   * escalates when needed, and performs a final re-scan before reporting success so that recovered
   * descendant processes are not left running silently.
   *
   * @param appId stable application identifier
   * @return {@code true} when a running process was found and stopped, or {@code false} when the
   *     host had no live process for that app id
   * @throws IOException if a running process tree cannot be shut down cleanly within the configured
   *     stop timeout
   */
  @Override
  public synchronized boolean stop(String appId) throws IOException {
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    RunningProcess runningProcess = liveRunningProcess(normalizedAppId);
    if (runningProcess == null) {
      return false;
    }

    RunningProcess trackedRunningProcess =
        trackRunningProcessForStop(normalizedAppId, runningProcess);
    if (trackedRunningProcess == null) {
      return true;
    }
    trackedRunningProcess = stopWithEscalation(normalizedAppId, appId, trackedRunningProcess);
    if (trackedRunningProcess == null) {
      return true;
    }
    completeStop(normalizedAppId, appId, trackedRunningProcess);
    return true;
  }

  /**
   * Returns the current live process snapshot, if any.
   *
   * <p>This method refreshes the tracked runtime state before answering, so callers can still
   * observe a recovered descendant after the original launcher process has exited.
   *
   * @param appId stable application identifier
   * @return running snapshot when the host still tracks a live process for the app, or {@link
   *     Optional#empty()} otherwise
   */
  @Override
  public synchronized Optional<RunningAppSnapshot> status(String appId) {
    RunningProcess runningProcess = liveRunningProcess(InstalledAppPaths.normalizeAppId(appId));
    return runningProcess != null ? Optional.of(runningProcess.snapshot()) : Optional.empty();
  }

  /**
   * Lists all live child processes.
   *
   * <p>The returned list is built from the host's refreshed in-memory runtime view and sorted by
   * normalized app id for deterministic display and test assertions.
   *
   * @return immutable list of running snapshots sorted by app id
   */
  @Override
  public synchronized List<RunningAppSnapshot> listRunning() {
    List<RunningAppSnapshot> running = new ArrayList<>();
    List<String> appIds = new ArrayList<>(runningApps.keySet());
    appIds.sort(String::compareTo);
    for (String appId : appIds) {
      RunningProcess runningProcess = liveRunningProcess(appId);
      if (runningProcess != null) {
        running.add(runningProcess.snapshot());
      }
    }
    return List.copyOf(running);
  }

  private AppManifest readInstalledManifest(Path installedRoot) throws IOException {
    Path manifestFile =
        resolveBundleEntry(
            installedRoot, Path.of(AppManifestParser.MANIFEST_FILE_NAME), "installed manifest");
    AppManifest manifest = AppManifestParser.parse(manifestFile);
    String installedDirectoryName = installedDirectoryNameOrThrow(installedRoot);
    if (!installedDirectoryName.equals(manifest.appId())) {
      throw new AppManifestException(
          "installed manifest app.id does not match directory name: " + installedDirectoryName);
    }
    return manifest;
  }

  private AppManifest validateCopiedBundle(Path copiedRoot) throws IOException {
    Path manifestFile =
        resolveBundleEntry(
            copiedRoot, Path.of(AppManifestParser.MANIFEST_FILE_NAME), "copied manifest");
    if (!Files.isRegularFile(manifestFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppManifestException("missing manifest file: " + manifestFile);
    }
    AppManifest manifest = AppManifestParser.parse(manifestFile);
    Path copiedExecutable = resolveBundleEntry(copiedRoot, manifest.execPath(), "copied app.exec");
    if (!Files.isRegularFile(copiedExecutable, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(
          "app.exec does not resolve to a file in copied bundle: " + manifest.execPathText());
    }
    validateLaunchableCopiedExecutable(copiedExecutable, manifest);
    return manifest;
  }

  private static void requireMatchingUpdateTarget(String requestedAppId, AppManifest manifest)
      throws AppManifestException {
    if (!requestedAppId.equals(manifest.appId())) {
      throw new AppManifestException(
          "staged manifest app.id does not match requested app.id: " + requestedAppId);
    }
  }

  private void validateLaunchableCopiedExecutable(Path copiedExecutable, AppManifest manifest)
      throws IOException {
    if (appEnv.isWindows()) {
      if (!isLaunchableWindowsExecutable(copiedExecutable)) {
        throw new AppHostException(
            "app.exec is not launchable on Windows: " + manifest.execPathText());
      }
      return;
    }
    if (!isInterpreterManagedPosixLauncher(copiedExecutable)
        && !Files.isExecutable(copiedExecutable)) {
      throw new AppHostException(
          "app.exec is not launchable on POSIX without execute permission: "
              + manifest.execPathText());
    }
  }

  private RunningProcess liveRunningProcess(String appId) {
    RunningProcess runningProcess = runningApps.get(appId);
    if (runningProcess == null) {
      return null;
    }
    RunningProcess refreshedRunningProcess = runningProcess.refresh();
    if (refreshedRunningProcess == null) {
      refreshedRunningProcess = recoverTrackedRunningProcess(runningProcess);
    }
    if (refreshedRunningProcess != null) {
      runningApps.replace(appId, runningProcess, refreshedRunningProcess);
      return refreshedRunningProcess;
    }
    runningProcess.exitCleanup().join();
    runningApps.remove(appId, runningProcess);
    return null;
  }

  private static Path normalizeExistingDirectory(Path directory) throws IOException {
    Objects.requireNonNull(directory, "stagedAppDirectory");
    Path normalized = directory.toAbsolutePath().normalize();
    if (!Files.isDirectory(normalized)) {
      throw new AppHostException("stagedAppDirectory must be an existing directory: " + normalized);
    }
    if (Files.isSymbolicLink(normalized) || isAliasedPathEntry(normalized)) {
      throw new AppHostException(
          "stagedAppDirectory must not be a symlink, reparse point, or alias: " + normalized);
    }
    return normalized;
  }

  private static void rejectOverlappingInstallTree(Path stagingRoot, Path installedAppsDir)
      throws IOException {
    if (pathsOverlap(stagingRoot, installedAppsDir)) {
      throw new AppHostException(
          "stagedAppDirectory must not overlap the installed app tree: " + stagingRoot);
    }
  }

  private static void rejectOverlappingMutableAppDirectories(
      Path stagingRoot, InstalledAppPaths paths) throws IOException {
    rejectOverlappingManagedAppDirectory(stagingRoot, paths.dataDir(), "dataDir");
    rejectOverlappingManagedAppDirectory(stagingRoot, paths.cacheDir(), "cacheDir");
    rejectOverlappingManagedAppDirectory(stagingRoot, paths.runDir(), "runDir");
  }

  private static void rejectOverlappingManagedAppDirectory(
      Path stagingRoot, Path managedDirectory, String label) throws IOException {
    if (pathsOverlap(stagingRoot, managedDirectory)) {
      throw new AppHostException(
          "stagedAppDirectory must not overlap " + label + ": " + stagingRoot);
    }
  }

  private static boolean pathsOverlap(Path firstPath, Path secondPath) throws IOException {
    Path firstComparablePath = comparablePath(firstPath);
    Path secondComparablePath = comparablePath(secondPath);
    return firstComparablePath.startsWith(secondComparablePath)
        || secondComparablePath.startsWith(firstComparablePath);
  }

  private static void ensureManagedDirectory(Path baseDirectory, Path directory)
      throws IOException {
    Path normalized = directory.toAbsolutePath().normalize();
    validateManagedPathPrefixes(baseDirectory, normalized, INSTALLED_APPS_DIR_LABEL);
    Deque<Path> missingSegments = new ArrayDeque<>();
    Path current = normalized;
    while (current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      Path fileName = current.getFileName();
      if (fileName != null) {
        missingSegments.push(fileName);
      }
      current = current.getParent();
    }
    if (current == null) {
      throw new AppHostException(
          INSTALLED_APPS_DIR_LABEL + " must resolve beneath an existing filesystem root");
    }
    validateManagedDirectoryEntry(current, INSTALLED_APPS_DIR_LABEL);
    while (!missingSegments.isEmpty()) {
      current = current.resolve(missingSegments.pop());
      Files.createDirectory(current);
    }
    validateManagedDirectoryEntry(normalized, INSTALLED_APPS_DIR_LABEL);
    if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(INSTALLED_APPS_DIR_LABEL + " must be a directory: " + normalized);
    }
  }

  private Path validateInstalledAppsDirectory() throws IOException {
    Path installedAppsDir = layout.installedAppsDir().toAbsolutePath().normalize();
    validateManagedPathPrefixes(layout.dataDir(), installedAppsDir, INSTALLED_APPS_DIR_LABEL);
    if (!Files.exists(installedAppsDir, LinkOption.NOFOLLOW_LINKS)) {
      return installedAppsDir;
    }
    validateManagedDirectoryEntry(installedAppsDir, INSTALLED_APPS_DIR_LABEL);
    if (!Files.isDirectory(installedAppsDir, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(
          INSTALLED_APPS_DIR_LABEL + " must be a directory: " + installedAppsDir);
    }
    return installedAppsDir;
  }

  private static void validateManagedDirectoryEntry(Path entry, String label) throws IOException {
    if (Files.exists(entry, LinkOption.NOFOLLOW_LINKS)
        && (Files.isSymbolicLink(entry) || isAliasedPathEntry(entry))) {
      throw new AppHostException(
          label + " must not be a symlink, reparse point, or alias: " + entry);
    }
  }

  private void validateManagedMutableDirectories(InstalledAppPaths paths) throws IOException {
    validateManagedPathPrefixes(layout.dataDir(), paths.dataDir(), "dataDir");
    validateManagedPathPrefixes(layout.cacheDir(), paths.cacheDir(), "cacheDir");
    validateManagedPathPrefixes(layout.runDir(), paths.runDir(), "runDir");
  }

  private static void validateManagedPathPrefixes(Path baseDirectory, Path target, String label)
      throws IOException {
    Path normalizedBase = baseDirectory.toAbsolutePath().normalize();
    Path normalizedTarget = target.toAbsolutePath().normalize();
    if (!normalizedTarget.startsWith(normalizedBase)) {
      throw new AppHostException(label + " must stay under the managed base directory");
    }
    Path current = normalizedBase;
    if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      validateManagedDirectoryEntry(current, label);
    }
    for (Path segment : normalizedBase.relativize(normalizedTarget)) {
      current = current.resolve(segment);
      if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
        break;
      }
      validateManagedDirectoryEntry(current, label);
    }
  }

  private static boolean shouldSkipInstalledEntry(Path appRoot) {
    if (!Files.isDirectory(appRoot, LinkOption.NOFOLLOW_LINKS)) {
      return true;
    }
    if (isTemporaryInstallDirectory(appRoot)) {
      return true;
    }
    return !Files.isRegularFile(
        appRoot.resolve(AppManifestParser.MANIFEST_FILE_NAME), LinkOption.NOFOLLOW_LINKS);
  }

  private static boolean isTemporaryInstallDirectory(Path appRoot) {
    return fileNameText(appRoot).startsWith(TEMP_INSTALL_PREFIX);
  }

  private static Path comparablePath(Path path) throws IOException {
    Path normalized = path.toAbsolutePath().normalize();
    Deque<Path> missingSegments = new ArrayDeque<>();
    Path current = normalized;
    while (current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      Path fileName = current.getFileName();
      if (fileName != null) {
        missingSegments.push(fileName);
      }
      current = current.getParent();
    }
    if (current == null) {
      return normalized;
    }
    Path comparable = current.toRealPath();
    while (!missingSegments.isEmpty()) {
      comparable = comparable.resolve(missingSegments.pop());
    }
    return comparable.normalize();
  }

  private static Path resolveBundleEntry(Path bundleRoot, Path relativePath, String label)
      throws IOException {
    Path resolvedRoot = bundleRoot.toAbsolutePath().normalize();
    validateBundleEntry(resolvedRoot, label);
    Path current = resolvedRoot;
    for (Path segment : relativePath) {
      current = current.resolve(segment).normalize();
      validateBundleEntry(current, label);
    }
    return current;
  }

  private static void validateBundleEntry(Path entry, String label) throws IOException {
    if (Files.exists(entry, LinkOption.NOFOLLOW_LINKS)
        && (Files.isSymbolicLink(entry) || isAliasedPathEntry(entry))) {
      throw new AppHostException(
          label + " must not resolve through symlinks or reparse points: " + entry);
    }
  }

  private String generateToken() {
    byte[] tokenBytes = new byte[TOKEN_BYTES];
    secureRandom.nextBytes(tokenBytes);
    return HexFormat.of().formatHex(tokenBytes);
  }

  private List<ProcessHandle> observeStartupProcessTree(Process process, String appId)
      throws AppHostException {
    ProcessHandle rootHandle = process.toHandle();
    List<ProcessHandle> observedHandles = new ArrayList<>();
    long deadline = System.nanoTime() + timing.startupExitGracePeriod().toNanos();
    long captureDeadline = System.nanoTime() + timing.startupProcessCaptureWindow().toNanos();
    long handoffDeadline =
        captureDeadline + timing.startupPostCaptureHandoffGracePeriod().toNanos();
    while (System.nanoTime() < deadline) {
      observedHandles.addAll(snapshotProcessTree(startupSeedHandles(rootHandle, observedHandles)));
      long now = System.nanoTime();
      if (shouldStopStartupObservation(rootHandle, now, handoffDeadline)) {
        break;
      }
      waitForStartupObservation(process, appId, deadline, captureDeadline, now);
    }
    capturePostExitProcessTree(rootHandle, observedHandles, appId);
    observedHandles.addAll(snapshotProcessTree(List.of(rootHandle)));
    return aliveHandles(observedHandles);
  }

  private static boolean shouldStopStartupObservation(
      ProcessHandle rootHandle, long now, long handoffDeadline) {
    return !rootHandle.isAlive() || now >= handoffDeadline;
  }

  private void waitForStartupObservation(
      Process process, String appId, long deadline, long captureDeadline, long now)
      throws AppHostException {
    long remainingNanos = deadline - now;
    if (remainingNanos <= 0L) {
      return;
    }
    long pollIntervalNanos =
        now >= captureDeadline
            ? timing.startupHandoffPollInterval().toNanos()
            : timing.startupProcessPollInterval().toNanos();
    waitForProcess(process, Math.min(remainingNanos, pollIntervalNanos), appId);
  }

  private void waitForProcess(Process process, long timeoutNanos, String appId)
      throws AppHostException {
    try {
      process.waitFor(timeoutNanos, TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AppHostException("interrupted while starting app: " + appId, e);
    }
  }

  private static void waitForProcessExit(Process process, Duration timeout)
      throws InterruptedException {
    process.waitFor(timeout.toNanos(), TimeUnit.NANOSECONDS);
  }

  private static void discardChildInput(Process process, String appId) throws IOException {
    try {
      process.getOutputStream().close();
    } catch (IOException e) {
      process.destroyForcibly();
      throw new AppHostException("failed to close stdin for app: " + appId, e);
    }
  }

  private static AppHostException startupFailure(String appId, Process process) {
    return new AppHostException(
        "app exited during startup: " + appId + " (exitCode=" + process.exitValue() + ")");
  }

  private void startTrackedProcessTreeObserver(
      String appId, Process process, CompletableFuture<Void> exitCleanup) {
    Thread.ofVirtual()
        .name("apphost-process-observer-", 0)
        .start(
            () -> {
              try {
                observeTrackedProcessTreeUntilExit(appId, process);
              } finally {
                try {
                  runningApps.computeIfPresent(
                      appId,
                      (ignoredAppId, activeProcess) ->
                          activeProcess.process() == process && !activeProcess.isAlive()
                              ? null
                              : activeProcess);
                } finally {
                  exitCleanup.complete(null);
                }
              }
            });
  }

  private void observeTrackedProcessTreeUntilExit(String appId, Process process) {
    long startupTrackingDeadline = System.nanoTime() + timing.startupExitGracePeriod().toNanos();
    try {
      while (true) {
        refreshObservedProcessTree(appId, process);
        boolean exited =
            process.waitFor(
                trackedProcessRefreshIntervalNanos(startupTrackingDeadline), TimeUnit.NANOSECONDS);
        if (exited) {
          capturePostExitProcessTreeHandoff(appId, process);
          break;
        }
      }
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    } finally {
      refreshObservedProcessTree(appId, process);
    }
  }

  private void capturePostExitProcessTreeHandoff(String appId, Process process)
      throws InterruptedException {
    long deadline = System.nanoTime() + timing.trackedProcessPostExitCaptureGracePeriod().toNanos();
    while (System.nanoTime() < deadline) {
      refreshObservedProcessTree(appId, process);
      TimeUnit.NANOSECONDS.sleep(timing.startupProcessPollInterval().toNanos());
    }
  }

  private void capturePostExitProcessTree(
      ProcessHandle rootHandle, List<ProcessHandle> observedHandles, String appId)
      throws AppHostException {
    if (rootHandle.isAlive()) {
      return;
    }
    long deadline = System.nanoTime() + timing.trackedProcessPostExitCaptureGracePeriod().toNanos();
    while (System.nanoTime() < deadline) {
      observedHandles.addAll(snapshotProcessTree(startupSeedHandles(rootHandle, observedHandles)));
      try {
        TimeUnit.NANOSECONDS.sleep(timing.startupProcessPollInterval().toNanos());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AppHostException("interrupted while starting app: " + appId, e);
      }
    }
  }

  private static List<ProcessHandle> startupSeedHandles(
      ProcessHandle rootHandle, List<ProcessHandle> observedHandles) {
    ArrayList<ProcessHandle> seedHandles = new ArrayList<>(observedHandles.size() + 1);
    seedHandles.add(rootHandle);
    seedHandles.addAll(observedHandles);
    return seedHandles;
  }

  private long trackedProcessRefreshIntervalNanos(long startupTrackingDeadline) {
    if (System.nanoTime() < startupTrackingDeadline) {
      return timing.startupProcessPollInterval().toNanos();
    }
    return timing.trackedProcessRefreshInterval().toNanos();
  }

  private void refreshObservedProcessTree(String appId, Process process) {
    runningApps.computeIfPresent(
        appId,
        (ignoredAppId, activeProcess) -> {
          if (activeProcess.process() != process) {
            return activeProcess;
          }
          RunningProcess refreshed = activeProcess.refresh();
          if (refreshed == null) {
            refreshed = recoverTrackedRunningProcess(activeProcess);
          }
          return refreshed != null ? refreshed : activeProcess;
        });
  }

  static void populateEnvironment(
      Map<String, String> environment,
      AppManifest manifest,
      InstalledAppPaths paths,
      String token,
      AppEnv appEnv) {
    environment.clear();
    populateBaseEnvironment(environment, appEnv);
    environment.put("CRYPTAD_APP_ID", manifest.appId());
    environment.put("CRYPTAD_APP_NAME", manifest.appName());
    environment.put("CRYPTAD_APP_VERSION", manifest.appVersion());
    environment.put("CRYPTAD_APP_DATA_DIR", paths.dataDir().toString());
    environment.put("CRYPTAD_APP_CACHE_DIR", paths.cacheDir().toString());
    environment.put("CRYPTAD_APP_RUN_DIR", paths.runDir().toString());
    environment.put("CRYPTAD_APP_TOKEN", token);
    environment.put("CRYPTAD_APP_PERMISSIONS", manifest.permissionsCsv());
    if (manifest.uiEntry() != null) {
      environment.put("CRYPTAD_APP_UI_ENTRY", manifest.uiEntry());
    }
  }

  private static void populateBaseEnvironment(Map<String, String> environment, AppEnv appEnv) {
    switch (appEnv.osKind()) {
      case WINDOWS -> populateWindowsBaseEnvironment(environment);
      case MAC, LINUX, OTHER -> environment.put("PATH", safeUnixPath(appEnv));
    }
  }

  private static void populateWindowsBaseEnvironment(Map<String, String> environment) {
    String systemRoot = resolveWindowsRoot();
    environment.put("SystemRoot", systemRoot);
    environment.put("SYSTEMROOT", systemRoot);
    environment.put("WINDIR", systemRoot);
    environment.put("ComSpec", windowsCommandInterpreter());
    environment.put("COMSPEC", windowsCommandInterpreter());
    environment.put(
        "PATH",
        String.join(
            ";",
            Path.of(systemRoot, WINDOWS_SYSTEM32_DIRECTORY).toString(),
            Path.of(systemRoot, WINDOWS_SYSTEM32_DIRECTORY, "WindowsPowerShell", "v1.0").toString(),
            systemRoot));
    copyHostEnvironmentValue(environment, "TEMP");
    copyHostEnvironmentValue(environment, "TMP");
  }

  static List<String> launchCommand(Path executable, AppEnv appEnv) throws IOException {
    return launchCommand(executable, appEnv, DEFAULT_TIMING);
  }

  private List<String> launchCommand(Path executable) throws IOException {
    return launchCommand(executable, appEnv, timing);
  }

  private static List<String> launchCommand(Path executable, AppEnv appEnv, TimingConfig timing)
      throws IOException {
    String executableText = executable.toString();
    if (appEnv.isWindows() && isWindowsBatchScript(executable)) {
      return List.of(
          windowsCommandInterpreter(), "/d", "/c", quoteWindowsBatchCommand(executableText));
    }
    if (!appEnv.isWindows()) {
      PosixLauncher posixLauncher = classifyPosixLauncher(executable);
      if (posixLauncher != null) {
        return posixLauncher.command(executable, timing);
      }
    }
    return List.of(executableText);
  }

  private static List<String> posixShellLaunchCommand(
      Path executable, List<String> interpreter, TimingConfig timing) {
    List<String> command = new ArrayList<>(interpreter);
    command.add("-c");
    command.add(
        "trap 'sleep %s' EXIT%nset --%n. \"$0\"%n"
            .formatted(posixShellExitTrapDelaySeconds(timing)));
    command.add(executable.toString());
    return List.copyOf(command);
  }

  private static List<String> directInterpreterLaunchCommand(
      Path executable, List<String> interpreter) {
    List<String> command = new ArrayList<>(interpreter);
    command.add(executable.toString());
    return List.copyOf(command);
  }

  private static boolean isWindowsBatchScript(Path executable) {
    String fileName = fileNameLowercase(executable);
    return fileName.endsWith(".cmd") || fileName.endsWith(".bat");
  }

  private static boolean isLaunchableWindowsExecutable(Path executable) throws IOException {
    return isWindowsBatchScript(executable)
        || hasWindowsComExecutableSuffix(executable)
        || hasLaunchablePortableExecutable(executable);
  }

  private static boolean hasWindowsComExecutableSuffix(Path executable) {
    String fileName = fileNameLowercase(executable);
    return fileName.endsWith(".com");
  }

  private static boolean hasLaunchablePortableExecutable(Path executable) throws IOException {
    try (SeekableByteChannel channel = Files.newByteChannel(executable)) {
      if (channel.size() < DOS_HEADER_SIZE) {
        return false;
      }
      ByteBuffer dosHeader = ByteBuffer.allocate(DOS_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
      if (channel.read(dosHeader) < DOS_HEADER_SIZE) {
        return false;
      }
      dosHeader.flip();
      if (dosHeader.get() != 'M' || dosHeader.get() != 'Z') {
        return false;
      }

      int peHeaderOffset = dosHeader.getInt(PE_POINTER_OFFSET);
      if (peHeaderOffset < DOS_HEADER_SIZE
          || channel.size() < (long) peHeaderOffset + COFF_HEADER_SIZE) {
        return false;
      }

      ByteBuffer coffHeader = ByteBuffer.allocate(COFF_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
      channel.position(peHeaderOffset);
      if (channel.read(coffHeader) < COFF_HEADER_SIZE) {
        return false;
      }
      coffHeader.flip();
      if (coffHeader.get() != 'P'
          || coffHeader.get() != 'E'
          || coffHeader.get() != 0
          || coffHeader.get() != 0) {
        return false;
      }
      coffHeader.position(22);
      int characteristics = Short.toUnsignedInt(coffHeader.getShort());
      return (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0
          && (characteristics & IMAGE_FILE_DLL) == 0;
    }
  }

  private static String quoteWindowsBatchCommand(String executableText) {
    return "\"" + executableText + "\"";
  }

  private static boolean hasPosixShellScriptSuffix(Path executable) {
    String fileName = fileNameLowercase(executable);
    return fileName.endsWith(".sh");
  }

  private static PosixLauncher classifyPosixLauncher(Path executable) throws IOException {
    String shebang = readShebang(executable);
    if (shebang.isBlank()) {
      return hasPosixShellScriptSuffix(executable)
          ? new PosixLauncher(List.of(posixShellInterpreter()), true)
          : null;
    }
    List<String> interpreter = parseShebangInterpreter(shebang);
    return new PosixLauncher(interpreter, isPosixShellInterpreter(interpreter));
  }

  private static String readShebang(Path executable) throws IOException {
    try (var input = Files.newInputStream(executable)) {
      if (input.read() != '#' || input.read() != '!') {
        return "";
      }
      var shebangBytes = new ByteArrayOutputStream();
      for (int bytesRead = 2; bytesRead < MAX_SHEBANG_PROBE_BYTES; bytesRead++) {
        int nextByte = input.read();
        if (nextByte < 0 || nextByte == '\n' || nextByte == '\r') {
          break;
        }
        shebangBytes.write(nextByte);
      }
      return shebangBytes.toString(StandardCharsets.UTF_8).trim();
    }
  }

  private static List<String> parseShebangInterpreter(String shebang) throws AppHostException {
    int argumentOffset = firstWhitespaceOffset(shebang);
    if (argumentOffset < 0) {
      validateShebangInterpreter(shebang);
      return List.of(shebang);
    }
    String interpreter = shebang.substring(0, argumentOffset);
    validateShebangInterpreter(interpreter);
    String interpreterArgument = shebang.substring(argumentOffset).trim();
    if (interpreterArgument.isEmpty()) {
      return List.of(interpreter);
    }
    return List.of(interpreter, interpreterArgument);
  }

  private static boolean isInterpreterManagedPosixLauncher(Path executable) throws IOException {
    return classifyPosixLauncher(executable) != null;
  }

  private static boolean isPosixShellInterpreter(List<String> interpreter) {
    if (interpreter.isEmpty()) {
      return false;
    }
    String interpreterName = commandBasename(interpreter.getFirst());
    if (isKnownPosixShellName(interpreterName)) {
      return true;
    }
    if (!interpreterName.equals("env") || interpreter.size() < 2) {
      return false;
    }
    return envInvokesPosixShell(interpreter.get(1));
  }

  private static boolean envInvokesPosixShell(String argumentText) {
    String trimmed = argumentText.trim();
    if (trimmed.isEmpty()) {
      return false;
    }
    if (trimmed.startsWith("-S ")) {
      trimmed = trimmed.substring(3).trim();
    }
    return isKnownPosixShellName(commandBasename(firstToken(trimmed)));
  }

  private static boolean isKnownPosixShellName(String commandName) {
    return switch (commandName) {
      case "sh", "ash", "bash", "dash", "ksh", "mksh", "zsh" -> true;
      default -> false;
    };
  }

  private static String firstToken(String text) {
    int offset = firstWhitespaceOffset(text);
    return offset < 0 ? text : text.substring(0, offset);
  }

  private static void validateShebangInterpreter(String interpreter) throws AppHostException {
    if (commandBasename(interpreter).isEmpty()) {
      throw new AppHostException("invalid shebang interpreter: " + interpreter);
    }
  }

  private static String commandBasename(String command) {
    if (command.isBlank()) {
      return "";
    }
    Path fileName = Path.of(command).getFileName();
    if (fileName == null) {
      return "";
    }
    return fileName.toString().toLowerCase(Locale.ROOT);
  }

  private static String fileNameLowercase(Path path) {
    return fileNameText(path).toLowerCase(Locale.ROOT);
  }

  private static String fileNameText(Path path) {
    Path fileName = path.getFileName();
    return fileName == null ? "" : fileName.toString();
  }

  private static String installedDirectoryNameOrThrow(Path path) throws AppHostException {
    String fileName = fileNameText(path);
    if (fileName.isEmpty()) {
      throw new AppHostException("installed manifest root must not be a filesystem root: " + path);
    }
    return fileName;
  }

  private static int firstWhitespaceOffset(String text) {
    for (int i = 0; i < text.length(); i++) {
      if (Character.isWhitespace(text.charAt(i))) {
        return i;
      }
    }
    return -1;
  }

  private static String posixShellInterpreter() {
    return Path.of("/bin", "sh").toString();
  }

  private static String posixShellExitTrapDelaySeconds(TimingConfig timing) {
    return String.format(
        Locale.ROOT, "%.3f", timing.startupProcessCaptureWindow().toMillis() / 1000.0d);
  }

  private static String windowsCommandInterpreter() {
    return Path.of(resolveWindowsRoot(), WINDOWS_SYSTEM32_DIRECTORY, "cmd.exe").toString();
  }

  private static String safeUnixPath(AppEnv appEnv) {
    ArrayList<String> entries = new ArrayList<>(BASE_UNIX_PATH_ENTRIES);
    switch (appEnv.osKind()) {
      case MAC -> entries.addAll(MAC_UNIX_PATH_ENTRIES);
      case LINUX -> entries.addAll(LINUX_UNIX_PATH_ENTRIES);
      case OTHER -> {
        entries.addAll(MAC_UNIX_PATH_ENTRIES);
        entries.addAll(LINUX_UNIX_PATH_ENTRIES);
      }
      case WINDOWS -> throw new IllegalArgumentException("windows does not use a Unix PATH");
    }
    return String.join(":", entries);
  }

  private static String resolveWindowsRoot() {
    String systemRoot = firstNonBlankWindowsRootEnvironmentValue();
    return systemRoot != null ? systemRoot : "C:\\Windows";
  }

  private static String firstNonBlankWindowsRootEnvironmentValue() {
    for (String name : WINDOWS_ROOT_ENVIRONMENT_NAMES) {
      String value = System.getenv(name);
      if (value != null && !value.isBlank()) {
        return value;
      }
    }
    return null;
  }

  private static void copyHostEnvironmentValue(Map<String, String> environment, String name) {
    String value = System.getenv(name);
    if (value != null && !value.isBlank()) {
      environment.put(name, value);
    }
  }

  private Path temporaryManagedPath(Path parent, String prefix) throws IOException {
    for (int attempt = 0; attempt < 8; attempt++) {
      Path candidate = parent.resolve(prefix + generateToken());
      if (!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
        return candidate;
      }
    }
    throw new AppHostException("failed to allocate temporary managed path under: " + parent);
  }

  private void replaceInstalledBundle(Path installedRoot, Path replacementRoot, Path backupRoot)
      throws IOException {
    moveIntoPlace(installedRoot, backupRoot);
    try {
      moveIntoPlace(replacementRoot, installedRoot);
    } catch (IOException updateFailure) {
      restoreInstalledBundle(installedRoot, backupRoot, updateFailure);
      throw updateFailure;
    }
    deleteBackupAfterSuccessfulReplacement(backupRoot);
  }

  private void deleteBackupAfterSuccessfulReplacement(Path backupRoot) {
    try {
      managedTreeDeleter.deleteRecursively(backupRoot);
    } catch (IOException _) {
      // The replacement is already committed; a skipped temp backup is safer than a false failure.
    }
  }

  private static void restoreInstalledBundle(
      Path installedRoot, Path backupRoot, IOException updateFailure) {
    try {
      deleteScratchTreeIfPresent(installedRoot);
    } catch (IOException cleanupFailure) {
      updateFailure.addSuppressed(cleanupFailure);
    }
    try {
      moveIntoPlace(backupRoot, installedRoot);
    } catch (IOException restoreFailure) {
      updateFailure.addSuppressed(restoreFailure);
    }
  }

  private static void moveIntoPlace(Path source, Path destination) throws IOException {
    try {
      Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, destination);
    }
  }

  private static void copyDirectoryTree(Path sourceRoot, Path targetRoot) throws IOException {
    Path sourceRealRoot = sourceRoot.toRealPath();
    Set<Path> visitedRealDirectories = ConcurrentHashMap.newKeySet();
    Files.walkFileTree(
        sourceRoot,
        new SimpleFileVisitor<>() {
          @Override
          public @NotNull FileVisitResult preVisitDirectory(
              @NotNull Path dir, @NotNull BasicFileAttributes attrs) throws IOException {
            Path realDirectory = validateStagingEntry(sourceRoot, sourceRealRoot, dir);
            if (!visitedRealDirectories.add(realDirectory)) {
              throw new AppHostException(
                  "staging directory must not revisit directories via links or reparse points: "
                      + dir);
            }
            Files.createDirectories(targetRoot.resolve(sourceRoot.relativize(dir)));
            return FileVisitResult.CONTINUE;
          }

          @Override
          public @NotNull FileVisitResult visitFile(
              @NotNull Path file, @NotNull BasicFileAttributes attrs) throws IOException {
            validateStagingEntry(sourceRoot, sourceRealRoot, file);
            if (!attrs.isRegularFile()) {
              throw new AppHostException(
                  "staging directory must contain only regular files: " + file);
            }
            Files.copy(
                file,
                targetRoot.resolve(sourceRoot.relativize(file)),
                StandardCopyOption.COPY_ATTRIBUTES,
                StandardCopyOption.REPLACE_EXISTING);
            return FileVisitResult.CONTINUE;
          }
        });
  }

  private static Path validateStagingEntry(Path sourceRoot, Path sourceRealRoot, Path entry)
      throws IOException {
    if (entry.equals(sourceRoot)) {
      return sourceRealRoot;
    }
    if (Files.isSymbolicLink(entry)) {
      throw new AppHostException("staging directory must not contain symlinks: " + entry);
    }
    Path expectedRealPath = sourceRealRoot.resolve(sourceRoot.relativize(entry)).normalize();
    Path actualRealPath = entry.toRealPath();
    if (!actualRealPath.equals(expectedRealPath)) {
      throw new AppHostException(
          "staging directory must not contain links or reparse points: " + entry);
    }
    return actualRealPath;
  }

  private static void deleteScratchTreeIfPresent(Path root) throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    deleteRecursively(root);
  }

  private static void deleteRecursively(Path root) throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    Files.walkFileTree(
        root,
        new SimpleFileVisitor<>() {
          @Override
          public @NotNull FileVisitResult preVisitDirectory(
              @NotNull Path dir, @NotNull BasicFileAttributes attrs) throws IOException {
            if (isAliasedPathEntry(dir)) {
              Files.deleteIfExists(dir);
              return FileVisitResult.SKIP_SUBTREE;
            }
            return FileVisitResult.CONTINUE;
          }

          @Override
          public @NotNull FileVisitResult visitFile(
              @NotNull Path file, @NotNull BasicFileAttributes attrs) throws IOException {
            Files.deleteIfExists(file);
            return FileVisitResult.CONTINUE;
          }

          @Override
          public @NotNull FileVisitResult visitFileFailed(
              @NotNull Path file, @NotNull IOException exc) throws IOException {
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS) && isAliasedPathEntry(file)) {
              Files.deleteIfExists(file);
              return FileVisitResult.CONTINUE;
            }
            throw exc;
          }

          @Override
          public @NotNull FileVisitResult postVisitDirectory(@NotNull Path dir, IOException exc)
              throws IOException {
            if (exc != null) {
              throw exc;
            }
            Files.deleteIfExists(dir);
            return FileVisitResult.CONTINUE;
          }
        });
  }

  private static boolean isAliasedPathEntry(Path entry) throws IOException {
    if (Files.isSymbolicLink(entry)) {
      return true;
    }
    Path parent = entry.getParent();
    if (parent == null) {
      return false;
    }
    Path expectedRealPath = parent.toRealPath().resolve(entry.getFileName()).normalize();
    Path actualRealPath = entry.toRealPath();
    return !actualRealPath.equals(expectedRealPath);
  }

  private static void destroyProcessHandles(List<ProcessHandle> processHandles) {
    for (int i = processHandles.size() - 1; i >= 0; i--) {
      ProcessHandle processHandle = processHandles.get(i);
      if (processHandle.isAlive()) {
        processHandle.destroy();
      }
    }
  }

  private static void destroyProcessHandlesForcibly(List<ProcessHandle> processHandles) {
    for (int i = processHandles.size() - 1; i >= 0; i--) {
      ProcessHandle processHandle = processHandles.get(i);
      if (processHandle.isAlive()) {
        processHandle.destroyForcibly();
      }
    }
  }

  private static void destroyRootProcess(RunningProcess runningProcess) {
    if (runningProcess.process().isAlive()) {
      runningProcess.process().destroy();
    }
  }

  private static void destroyRootProcessForcibly(RunningProcess runningProcess) {
    if (runningProcess.process().isAlive()) {
      runningProcess.process().destroyForcibly();
    }
  }

  private static boolean waitForProcessTreeExit(List<ProcessHandle> processTree, Duration timeout)
      throws InterruptedException {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      if (aliveHandles(processTree).isEmpty()) {
        return true;
      }
      TimeUnit.MILLISECONDS.sleep(10);
    }
    return aliveHandles(processTree).isEmpty();
  }

  private RunningProcess stopWithEscalation(
      String normalizedAppId, String appId, RunningProcess trackedRunningProcess)
      throws IOException {
    RunningProcess current = trackedRunningProcess;
    try {
      if (destroyDescendantsAndWaitForExit(current, descendantReapGracePeriod())) {
        return current;
      }
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null || destroyRootAndWaitForExit(current, stopTimeout)) {
        return current;
      }
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null || destroyDescendantsForciblyAndWaitForExit(current, stopTimeout)) {
        return current;
      }
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null) {
        return null;
      }
      return destroyRootForciblyAndWaitForExit(normalizedAppId, appId, current);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      boolean preserved = preserveRunningState(normalizedAppId, current);
      if (!preserved) {
        return null;
      }
      throw new AppHostException("interrupted while stopping app: " + appId, e);
    }
  }

  private Duration descendantReapGracePeriod() {
    return stopTimeout.compareTo(timing.descendantReapGracePeriodLimit()) > 0
        ? timing.descendantReapGracePeriodLimit()
        : stopTimeout;
  }

  private static boolean destroyDescendantsAndWaitForExit(
      RunningProcess runningProcess, Duration timeout) throws InterruptedException {
    destroyProcessHandles(descendantHandles(runningProcess));
    return waitForProcessTreeExit(runningProcess.processTree(), timeout);
  }

  private static boolean destroyRootAndWaitForExit(RunningProcess runningProcess, Duration timeout)
      throws InterruptedException {
    destroyRootProcess(runningProcess);
    return waitForProcessTreeExit(runningProcess.processTree(), timeout);
  }

  private static boolean destroyDescendantsForciblyAndWaitForExit(
      RunningProcess runningProcess, Duration timeout) throws InterruptedException {
    destroyProcessHandlesForcibly(descendantHandles(runningProcess));
    return waitForProcessTreeExit(runningProcess.processTree(), timeout);
  }

  private RunningProcess destroyRootForciblyAndWaitForExit(
      String normalizedAppId, String appId, RunningProcess runningProcess)
      throws IOException, InterruptedException {
    destroyRootProcessForcibly(runningProcess);
    waitForProcessExit(runningProcess.process(), stopTimeout);
    if (waitForProcessTreeExit(runningProcess.processTree(), stopTimeout)) {
      return runningProcess;
    }
    boolean preserved = preserveRunningState(normalizedAppId, runningProcess);
    if (!preserved) {
      return null;
    }
    throw new AppHostException("timed out stopping app: " + appId);
  }

  private void completeStop(
      String normalizedAppId, String appId, RunningProcess trackedRunningProcess)
      throws IOException {
    if (awaitTrackedProcessExit(normalizedAppId, appId, trackedRunningProcess) != null) {
      throw new AppHostException("timed out stopping app: " + appId);
    }
    trackedRunningProcess.exitCleanup().join();
    runningApps.remove(normalizedAppId, trackedRunningProcess);
  }

  private RunningProcess awaitTrackedProcessExit(
      String normalizedAppId, String appId, RunningProcess runningProcess) throws IOException {
    long deadline = System.nanoTime() + stopTimeout.toNanos();
    RunningProcess current = runningProcess;
    while (current != null) {
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null || System.nanoTime() >= deadline) {
        return current;
      }
      try {
        TimeUnit.NANOSECONDS.sleep(finalStopRefreshIntervalNanos(deadline));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        boolean preserved = preserveRunningState(normalizedAppId, current);
        if (!preserved) {
          return null;
        }
        throw new AppHostException("interrupted while stopping app: " + appId, e);
      }
    }
    return null;
  }

  private long finalStopRefreshIntervalNanos(long deadline) {
    long remainingNanos = deadline - System.nanoTime();
    if (remainingNanos <= 0) {
      return 0;
    }
    return Math.min(remainingNanos, timing.trackedProcessRefreshInterval().toNanos());
  }

  private boolean preserveRunningState(String appId, RunningProcess runningProcess) {
    RunningProcess refreshedRunningProcess = runningProcess.refresh();
    if (refreshedRunningProcess == null) {
      runningApps.remove(appId, runningProcess);
      return false;
    }
    runningApps.put(appId, refreshedRunningProcess);
    return true;
  }

  private RunningProcess trackRunningProcessForStop(String appId, RunningProcess runningProcess) {
    List<ProcessHandle> processTree = runningProcess.processTree();
    RunningProcess trackedRunningProcess = runningProcess.tryWithProcessTree(processTree);
    if (trackedRunningProcess == null) {
      runningProcess.exitCleanup().join();
      runningApps.remove(appId, runningProcess);
      return null;
    }
    runningApps.replace(appId, runningProcess, trackedRunningProcess);
    return trackedRunningProcess;
  }

  private RunningProcess refreshTrackedRunningProcess(String appId, RunningProcess runningProcess) {
    RunningProcess refreshedRunningProcess = runningProcess.refresh();
    if (refreshedRunningProcess == null) {
      refreshedRunningProcess = recoverTrackedRunningProcess(runningProcess);
    }
    if (refreshedRunningProcess != null) {
      runningApps.put(appId, refreshedRunningProcess);
      return refreshedRunningProcess;
    }
    runningProcess.exitCleanup().join();
    runningApps.remove(appId, runningProcess);
    return null;
  }

  private static List<ProcessHandle> snapshotProcessTree(List<ProcessHandle> seedHandles) {
    List<ProcessHandle> processTree = new ArrayList<>();
    for (ProcessHandle seedHandle : deduplicateHandles(seedHandles)) {
      processTree.add(seedHandle);
      seedHandle.descendants().forEach(processTree::add);
    }
    return deduplicateHandles(processTree);
  }

  private static List<ProcessHandle> aliveHandles(List<ProcessHandle> processHandles) {
    return deduplicateHandles(
        processHandles.stream().filter(LocalProcessAppHost::isEffectivelyAlive).toList());
  }

  private RunningProcess recoverTrackedRunningProcess(RunningProcess runningProcess) {
    List<ProcessHandle> recoveredHandles =
        new ArrayList<>(
            recoverTrackedProcesses(
                runningProcess.snapshot().manifest(),
                runningProcess.snapshot().paths(),
                runningProcess.snapshot().token(),
                runningProcess.snapshot().startedAt(),
                runningProcess.seedHandles(),
                ProcessHandle.allProcesses().toList()));
    recoveredHandles = aliveHandles(recoveredHandles);
    if (recoveredHandles.isEmpty()) {
      return null;
    }
    return runningProcess.tryWithProcessTree(recoveredHandles);
  }

  private List<ProcessHandle> recoverTrackedProcesses(
      AppManifest manifest,
      InstalledAppPaths paths,
      String token,
      Instant startedAt,
      List<ProcessHandle> trackedHandles,
      List<ProcessHandle> processCandidates) {
    List<ProcessHandle> recoveredHandles =
        new ArrayList<>(recoverTrackedDescendantProcesses(trackedHandles, processCandidates));
    recoveredHandles.addAll(findTokenTrackedProcesses(token, manifest.appId()));
    if (recoveredHandles.isEmpty() && appEnv.isWindows()) {
      recoveredHandles.addAll(
          recoverWindowsBundleProcesses(
              paths,
              manifest,
              startedAt,
              trackedHandles,
              processCandidates,
              timing.windowsBundleRecoveryWindow()));
    }
    return deduplicateHandles(recoveredHandles);
  }

  static List<ProcessHandle> recoverTrackedDescendantProcesses(
      List<ProcessHandle> trackedHandles, List<ProcessHandle> processCandidates) {
    List<Long> trackedPids =
        deduplicateHandles(trackedHandles).stream().map(ProcessHandle::pid).sorted().toList();
    if (trackedPids.isEmpty()) {
      return List.of();
    }
    Map<Long, List<ProcessHandle>> childrenByParentPid = new LinkedHashMap<>();
    for (ProcessHandle candidate : deduplicateHandles(processCandidates)) {
      if (!isEffectivelyAlive(candidate)) {
        continue;
      }
      candidate
          .parent()
          .ifPresent(
              parent ->
                  childrenByParentPid
                      .computeIfAbsent(parent.pid(), ignoredPid -> new ArrayList<>())
                      .add(candidate));
    }
    Deque<Long> pendingParentPids = new ArrayDeque<>(trackedPids);
    LinkedHashMap<Long, ProcessHandle> recoveredHandlesByPid = new LinkedHashMap<>();
    while (!pendingParentPids.isEmpty()) {
      long parentPid = pendingParentPids.removeFirst();
      for (ProcessHandle child : childrenByParentPid.getOrDefault(parentPid, List.of())) {
        if (recoveredHandlesByPid.putIfAbsent(child.pid(), child) == null) {
          pendingParentPids.addLast(child.pid());
        }
      }
    }
    return recoveredHandlesByPid.values().stream()
        .sorted(Comparator.comparingLong(ProcessHandle::pid))
        .toList();
  }

  static List<ProcessHandle> recoverWindowsBundleProcesses(
      InstalledAppPaths paths,
      AppManifest manifest,
      Instant startedAt,
      List<ProcessHandle> trackedHandles,
      List<ProcessHandle> processCandidates) {
    return recoverWindowsBundleProcesses(
        paths,
        manifest,
        startedAt,
        trackedHandles,
        processCandidates,
        DEFAULT_TIMING.windowsBundleRecoveryWindow());
  }

  private static List<ProcessHandle> recoverWindowsBundleProcesses(
      InstalledAppPaths paths,
      AppManifest manifest,
      Instant startedAt,
      List<ProcessHandle> trackedHandles,
      List<ProcessHandle> processCandidates,
      Duration windowsBundleRecoveryWindow) {
    Path installedRoot = paths.installedRoot().toAbsolutePath().normalize();
    Path executablePath = paths.executablePath(manifest).toAbsolutePath().normalize();
    List<Long> trackedPids =
        deduplicateHandles(trackedHandles).stream().map(ProcessHandle::pid).sorted().toList();
    return deduplicateHandles(
        processCandidates.stream()
            .filter(LocalProcessAppHost::isEffectivelyAlive)
            .filter(processHandle -> !trackedPids.contains(processHandle.pid()))
            .filter(
                processHandle ->
                    startedWithinWindowsRecoveryWindow(
                            processHandle, startedAt, windowsBundleRecoveryWindow)
                        && referencesInstalledBundle(processHandle, installedRoot, executablePath))
            .sorted(Comparator.comparingLong(ProcessHandle::pid))
            .toList());
  }

  private List<ProcessHandle> findTokenTrackedProcesses(String token, String appId) {
    List<ProcessHandle> procMatches = List.of();
    if (supportsProcEnvironmentScan()) {
      procMatches = findTokenTrackedProcessesFromProc(token, appId);
    }
    List<ProcessHandle> psMatches =
        appEnv.isWindows() || !procMatches.isEmpty()
            ? List.of()
            : findTokenTrackedProcessesWithPs(token, appId);
    return mergeTokenTrackedProcesses(procMatches, psMatches, appEnv);
  }

  private static List<ProcessHandle> findTokenTrackedProcessesFromProc(String token, String appId) {
    return ProcessHandle.allProcesses()
        .filter(LocalProcessAppHost::isEffectivelyAlive)
        .filter(processHandle -> hasAppHostToken(processHandle.pid(), token, appId))
        .sorted(Comparator.comparingLong(ProcessHandle::pid))
        .toList();
  }

  static List<ProcessHandle> mergeTokenTrackedProcesses(
      List<ProcessHandle> procMatches, List<ProcessHandle> psMatches, AppEnv appEnv) {
    List<ProcessHandle> deduplicatedProcMatches = deduplicateHandles(procMatches);
    if (!deduplicatedProcMatches.isEmpty() || appEnv.isWindows()) {
      return deduplicatedProcMatches;
    }
    return deduplicateHandles(psMatches);
  }

  private static List<ProcessHandle> findTokenTrackedProcessesWithPs(String token, String appId) {
    String psCommand = resolveTrustedPsCommand();
    if (psCommand == null) {
      return List.of();
    }
    for (List<String> command :
        List.of(
            List.of(psCommand, "eww", "-e", "-o", "pid=", "-o", "command="),
            List.of(psCommand, "eww", "-ax", "-o", "pid=", "-o", "command="))) {
      List<ProcessHandle> processes = findTokenTrackedProcessesWithPsCommand(command, token, appId);
      if (!processes.isEmpty()) {
        return processes;
      }
    }
    return List.of();
  }

  private static List<ProcessHandle> findTokenTrackedProcessesWithPsCommand(
      List<String> command, String token, String appId) {
    Process process;
    try {
      process = new ProcessBuilder(command).redirectErrorStream(true).start();
    } catch (IOException _) {
      return List.of();
    }
    try {
      List<ProcessHandle> processes = parseTokenTrackedProcesses(process, token, appId);
      if (!process.waitFor(5, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        return List.of();
      }
      if (process.exitValue() != 0) {
        return List.of();
      }
      return processes;
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      process.destroyForcibly();
      return List.of();
    }
  }

  private static List<ProcessHandle> parseTokenTrackedProcesses(
      Process process, String token, String appId) throws IOException {
    List<ProcessHandle> processes = new ArrayList<>();
    try (var reader = process.inputReader(StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        String trimmed = line.trim();
        if (trimmed.isEmpty()) {
          continue;
        }
        parsePsProcessHandle(trimmed, token, appId)
            .filter(LocalProcessAppHost::isEffectivelyAlive)
            .ifPresent(processes::add);
      }
    }
    processes.sort(Comparator.comparingLong(ProcessHandle::pid));
    return List.copyOf(processes);
  }

  private static Optional<ProcessHandle> parsePsProcessHandle(
      String line, String token, String appId) {
    int separator = firstWhitespaceOffset(line);
    if (separator < 0) {
      return Optional.empty();
    }
    String pidText = line.substring(0, separator).trim();
    String commandAndEnvironment = line.substring(separator).trim();
    if (!commandAndEnvironment.contains("CRYPTAD_APP_TOKEN=" + token)
        || !commandAndEnvironment.contains("CRYPTAD_APP_ID=" + appId)) {
      return Optional.empty();
    }
    try {
      long pid = Long.parseLong(pidText);
      return ProcessHandle.of(pid);
    } catch (NumberFormatException _) {
      return Optional.empty();
    }
  }

  private static String resolveTrustedPsCommand() {
    for (Path trustedDir :
        List.of(Path.of("/usr/bin"), Path.of("/bin"), Path.of("/usr/sbin"), Path.of("/sbin"))) {
      Path candidate = trustedDir.resolve("ps");
      if (Files.isExecutable(candidate)) {
        return candidate.toString();
      }
    }
    return null;
  }

  private static boolean startedWithinWindowsRecoveryWindow(
      ProcessHandle processHandle, Instant startedAt, Duration windowsBundleRecoveryWindow) {
    return processHandle
        .info()
        .startInstant()
        .map(
            candidateStartedAt ->
                !candidateStartedAt.isBefore(startedAt.minusSeconds(1))
                    && !candidateStartedAt.isAfter(startedAt.plus(windowsBundleRecoveryWindow)))
        .orElse(false);
  }

  private static boolean referencesInstalledBundle(
      ProcessHandle processHandle, Path installedRoot, Path executablePath) {
    String normalizedInstalledRoot = installedRoot.toString().toLowerCase(Locale.ROOT);
    String normalizedExecutablePath = executablePath.toString().toLowerCase(Locale.ROOT);
    ProcessHandle.Info info = processHandle.info();
    String normalizedCommand =
        info.command().map(command -> command.toLowerCase(Locale.ROOT)).orElse("");
    if (!normalizedCommand.isEmpty()
        && (normalizedCommand.equals(normalizedExecutablePath)
            || normalizedCommand.startsWith(normalizedInstalledRoot + "\\")
            || normalizedCommand.startsWith(normalizedInstalledRoot + "/"))) {
      return true;
    }
    String normalizedCommandLine =
        info.commandLine().map(commandLine -> commandLine.toLowerCase(Locale.ROOT)).orElse("");
    return !normalizedCommandLine.isEmpty()
        && (normalizedCommandLine.contains(normalizedExecutablePath)
            || normalizedCommandLine.contains(normalizedInstalledRoot));
  }

  private static boolean supportsProcEnvironmentScan() {
    return Files.isReadable(Path.of(PROC_ROOT, "self", "environ"));
  }

  private static boolean hasAppHostToken(long pid, String token, String appId) {
    Path environmentFile = Path.of(PROC_ROOT, Long.toString(pid), "environ");
    if (!Files.isReadable(environmentFile)) {
      return false;
    }
    try {
      String environment = Files.readString(environmentFile, StandardCharsets.UTF_8);
      return hasEnvironmentEntry(environment, "CRYPTAD_APP_TOKEN", token)
          && hasEnvironmentEntry(environment, "CRYPTAD_APP_ID", appId);
    } catch (IOException | RuntimeException _) {
      return false;
    }
  }

  private static boolean hasEnvironmentEntry(String environment, String name, String value) {
    String expectedEntry = name + "=" + value;
    int start = 0;
    while (start <= environment.length()) {
      int end = environment.indexOf('\0', start);
      if (end < 0) {
        end = environment.length();
      }
      if (end - start == expectedEntry.length()
          && environment.regionMatches(start, expectedEntry, 0, expectedEntry.length())) {
        return true;
      }
      if (end == environment.length()) {
        break;
      }
      start = end + 1;
    }
    return false;
  }

  private static List<ProcessHandle> descendantHandles(RunningProcess runningProcess) {
    long rootPid = runningProcess.process().pid();
    return aliveHandles(runningProcess.processTree()).stream()
        .filter(processHandle -> processHandle.pid() != rootPid)
        .toList();
  }

  private static List<ProcessHandle> deduplicateHandles(List<ProcessHandle> processHandles) {
    LinkedHashMap<Long, ProcessHandle> handlesByPid = new LinkedHashMap<>();
    for (ProcessHandle processHandle : processHandles) {
      handlesByPid.putIfAbsent(processHandle.pid(), processHandle);
    }
    return List.copyOf(handlesByPid.values());
  }

  private static boolean isEffectivelyAlive(ProcessHandle processHandle) {
    return processHandle.isAlive() && !isZombieProcess(processHandle);
  }

  private static boolean isZombieProcess(ProcessHandle processHandle) {
    Path statFile = Path.of(PROC_ROOT, Long.toString(processHandle.pid()), "stat");
    if (!Files.isReadable(statFile)) {
      return false;
    }
    try {
      String stat = Files.readString(statFile);
      int commandEnd = stat.lastIndexOf(')');
      return commandEnd >= 0
          && commandEnd + 2 < stat.length()
          && stat.charAt(commandEnd + 2) == 'Z';
    } catch (IOException _) {
      return false;
    }
  }

  private static boolean preferDescendantPid(Path executable, List<ProcessHandle> processTree) {
    if (!(isInterpreterManagedPosixLauncherUnchecked(executable)
        || isWindowsBatchScript(executable))) {
      return false;
    }
    return processTree.size() > 1;
  }

  private static boolean isInterpreterManagedPosixLauncherUnchecked(Path executable) {
    try {
      return isInterpreterManagedPosixLauncher(executable);
    } catch (IOException _) {
      return false;
    }
  }

  private record PosixLauncher(List<String> interpreter, boolean shellInterpreter) {
    private PosixLauncher {
      interpreter = List.copyOf(interpreter);
    }

    private List<String> command(Path executable, TimingConfig timing) {
      return shellInterpreter
          ? posixShellLaunchCommand(executable, interpreter, timing)
          : directInterpreterLaunchCommand(executable, interpreter);
    }
  }

  @FunctionalInterface
  interface ManagedTreeDeleter {
    void deleteRecursively(Path root) throws IOException;
  }

  record TimingConfig(
      Duration startupExitGracePeriod,
      Duration startupProcessCaptureWindow,
      Duration startupPostCaptureHandoffGracePeriod,
      Duration trackedProcessPostExitCaptureGracePeriod,
      Duration trackedProcessRefreshInterval,
      Duration startupProcessPollInterval,
      Duration startupHandoffPollInterval,
      Duration descendantReapGracePeriodLimit) {
    TimingConfig {
      Objects.requireNonNull(startupExitGracePeriod, "startupExitGracePeriod");
      Objects.requireNonNull(startupProcessCaptureWindow, "startupProcessCaptureWindow");
      Objects.requireNonNull(
          startupPostCaptureHandoffGracePeriod, "startupPostCaptureHandoffGracePeriod");
      Objects.requireNonNull(
          trackedProcessPostExitCaptureGracePeriod, "trackedProcessPostExitCaptureGracePeriod");
      Objects.requireNonNull(trackedProcessRefreshInterval, "trackedProcessRefreshInterval");
      Objects.requireNonNull(startupProcessPollInterval, "startupProcessPollInterval");
      Objects.requireNonNull(startupHandoffPollInterval, "startupHandoffPollInterval");
      Objects.requireNonNull(descendantReapGracePeriodLimit, "descendantReapGracePeriodLimit");
    }

    private Duration windowsBundleRecoveryWindow() {
      return startupExitGracePeriod.plus(trackedProcessPostExitCaptureGracePeriod);
    }
  }

  private static long representativePid(
      List<ProcessHandle> processTree, long preferredPid, boolean preferDescendantPid) {
    if (preferDescendantPid) {
      OptionalLong descendantPid =
          processTree.stream()
              .mapToLong(ProcessHandle::pid)
              .filter(pid -> pid != preferredPid)
              .min();
      if (descendantPid.isPresent()) {
        return descendantPid.orElseThrow();
      }
    }
    return processTree.stream()
        .filter(processHandle -> processHandle.pid() == preferredPid)
        .findFirst()
        .or(() -> processTree.stream().min(Comparator.comparingLong(ProcessHandle::pid)))
        .orElseThrow(() -> new IllegalArgumentException("processTree must not be empty"))
        .pid();
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class RunningProcess {
    private final Process process;
    private final RunningAppSnapshot snapshot;
    private final CompletableFuture<Void> exitCleanup;
    private final List<ProcessHandle> trackedHandles;

    private RunningProcess(
        Process process,
        RunningAppSnapshot snapshot,
        CompletableFuture<Void> exitCleanup,
        List<ProcessHandle> trackedHandles) {
      this.process = Objects.requireNonNull(process, "process");
      this.snapshot = Objects.requireNonNull(snapshot, "snapshot");
      this.exitCleanup = Objects.requireNonNull(exitCleanup, "exitCleanup");
      this.trackedHandles = List.copyOf(Objects.requireNonNull(trackedHandles, "trackedHandles"));
    }

    private Process process() {
      return process;
    }

    private RunningAppSnapshot snapshot() {
      return snapshot;
    }

    private CompletableFuture<Void> exitCleanup() {
      return exitCleanup;
    }

    private boolean isAlive() {
      return !aliveHandles(processTree()).isEmpty();
    }

    private List<ProcessHandle> processTree() {
      return snapshotProcessTree(seedHandles());
    }

    private List<ProcessHandle> seedHandles() {
      List<ProcessHandle> seedHandles = new ArrayList<>();
      seedHandles.add(process.toHandle());
      seedHandles.addAll(trackedHandles);
      return deduplicateHandles(seedHandles);
    }

    private RunningProcess refresh() {
      List<ProcessHandle> currentProcessTree = aliveHandles(processTree());
      if (currentProcessTree.isEmpty()) {
        return null;
      }
      return tryWithProcessTree(currentProcessTree);
    }

    private RunningProcess tryWithProcessTree(List<ProcessHandle> newProcessTree) {
      List<ProcessHandle> aliveProcessTree = aliveHandles(newProcessTree);
      if (aliveProcessTree.isEmpty()) {
        return null;
      }
      long updatedPid = representativePid(aliveProcessTree, snapshot.pid(), false);
      RunningAppSnapshot updatedSnapshot =
          updatedPid == snapshot.pid()
              ? snapshot
              : new RunningAppSnapshot(
                  snapshot.manifest(),
                  snapshot.paths(),
                  snapshot.token(),
                  updatedPid,
                  snapshot.startedAt());
      if (trackedHandlePids().equals(handlePids(aliveProcessTree))
          && updatedPid == snapshot.pid()) {
        return this;
      }
      return new RunningProcess(process, updatedSnapshot, exitCleanup, aliveProcessTree);
    }

    private List<Long> trackedHandlePids() {
      return handlePids(trackedHandles);
    }

    private static List<Long> handlePids(List<ProcessHandle> processHandles) {
      return processHandles.stream().map(ProcessHandle::pid).sorted().toList();
    }
  }
}
