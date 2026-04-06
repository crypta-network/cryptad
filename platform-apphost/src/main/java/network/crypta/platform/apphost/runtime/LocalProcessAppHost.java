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
 * <p>The runtime state remains in memory only. This v1 host does not attempt to restart recovery,
 * sandboxing, or hard quota enforcement.
 */
public final class LocalProcessAppHost implements AppHost {
  private static final Duration DEFAULT_STOP_TIMEOUT = Duration.ofSeconds(5);
  private static final String TEMP_INSTALL_PREFIX = "app-install-";
  private static final int MAX_SHEBANG_PROBE_BYTES = 4096;
  private static final int DOS_HEADER_SIZE = 64;
  private static final int PE_POINTER_OFFSET = 0x3C;
  private static final int COFF_HEADER_SIZE = 24;
  private static final int IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
  private static final int IMAGE_FILE_DLL = 0x2000;
  private static final Duration STARTUP_EXIT_GRACE_PERIOD = Duration.ofSeconds(2);
  private static final Duration STARTUP_PROCESS_CAPTURE_WINDOW = Duration.ofMillis(500);
  private static final Duration STARTUP_POST_CAPTURE_HANDOFF_GRACE_PERIOD = Duration.ofMillis(200);
  private static final Duration TRACKED_PROCESS_POST_EXIT_CAPTURE_GRACE_PERIOD =
      Duration.ofMillis(200);
  private static final Duration WINDOWS_BUNDLE_RECOVERY_WINDOW =
      STARTUP_EXIT_GRACE_PERIOD.plus(TRACKED_PROCESS_POST_EXIT_CAPTURE_GRACE_PERIOD);
  private static final Duration TRACKED_PROCESS_REFRESH_INTERVAL = Duration.ofMillis(100);
  private static final long STARTUP_PROCESS_POLL_INTERVAL_NANOS =
      TimeUnit.MICROSECONDS.toNanos(100);
  private static final long STARTUP_HANDOFF_POLL_INTERVAL_NANOS = TimeUnit.MILLISECONDS.toNanos(5);
  private static final List<String> BASE_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/usr", "bin").toString(),
          Path.of("/bin").toString(),
          Path.of("/usr", "sbin").toString(),
          Path.of("/sbin").toString(),
          Path.of("/usr", "local", "bin").toString(),
          Path.of("/usr", "local", "sbin").toString());
  private static final List<String> MAC_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/opt", "homebrew", "bin").toString(),
          Path.of("/opt", "homebrew", "sbin").toString(),
          Path.of("/opt", "local", "bin").toString(),
          Path.of("/opt", "local", "sbin").toString());
  private static final List<String> LINUX_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/home", "linuxbrew", ".linuxbrew", "bin").toString(),
          Path.of("/home", "linuxbrew", ".linuxbrew", "sbin").toString());
  private static final int TOKEN_BYTES = 32;

  private final AppHostLayout layout;
  private final Duration stopTimeout;
  private final SecureRandom secureRandom;
  private final AppEnv appEnv;
  private final Map<String, RunningProcess> runningApps = new ConcurrentHashMap<>();

  /**
   * Creates a host bound to the supplied layout.
   *
   * @param layout filesystem layout managed by the host
   */
  public LocalProcessAppHost(AppHostLayout layout) {
    this(layout, DEFAULT_STOP_TIMEOUT, new SecureRandom(), new AppEnv());
  }

  /**
   * Creates a host with an explicit stop timeout and token generator.
   *
   * @param layout filesystem layout managed by the host
   * @param stopTimeout bounded timeout used before the force-killing a child process
   * @param secureRandom secure token generator
   */
  public LocalProcessAppHost(
      AppHostLayout layout, Duration stopTimeout, SecureRandom secureRandom) {
    this(layout, stopTimeout, secureRandom, new AppEnv());
  }

  LocalProcessAppHost(
      AppHostLayout layout, Duration stopTimeout, SecureRandom secureRandom, AppEnv appEnv) {
    this.layout = Objects.requireNonNull(layout, "layout");
    this.stopTimeout = Objects.requireNonNull(stopTimeout, "stopTimeout");
    this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
    this.appEnv = Objects.requireNonNull(appEnv, "appEnv");
    if (stopTimeout.isZero() || stopTimeout.isNegative()) {
      throw new IllegalArgumentException("stopTimeout must be positive");
    }
  }

  @Override
  public synchronized InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory)
      throws IOException {
    Path stagingRoot = normalizeExistingDirectory(stagedAppDirectory);
    rejectOverlappingInstallTree(stagingRoot, layout.installedAppsDir());
    Path installedAppsDir = layout.installedAppsDir();
    ensureManagedDirectory(layout.dataDir(), installedAppsDir, "installedAppsDir");
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
    List<String> command = launchCommand(executable, appEnv);
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
    List<ProcessHandle> processTree = trackedRunningProcess.processTree();
    try {
      Duration reapGracePeriod =
          stopTimeout.compareTo(Duration.ofMillis(100)) > 0 ? Duration.ofMillis(100) : stopTimeout;

      destroyProcessHandles(descendantHandles(trackedRunningProcess));
      if (!waitForProcessTreeExit(processTree, reapGracePeriod)) {
        trackedRunningProcess =
            refreshTrackedRunningProcess(normalizedAppId, trackedRunningProcess);
        if (trackedRunningProcess == null) {
          return true;
        }
        processTree = trackedRunningProcess.processTree();
        destroyRootProcess(trackedRunningProcess);
        if (!waitForProcessTreeExit(processTree, stopTimeout)) {
          trackedRunningProcess =
              refreshTrackedRunningProcess(normalizedAppId, trackedRunningProcess);
          if (trackedRunningProcess == null) {
            return true;
          }
          processTree = trackedRunningProcess.processTree();
          destroyProcessHandlesForcibly(descendantHandles(trackedRunningProcess));
          if (!waitForProcessTreeExit(processTree, stopTimeout)) {
            trackedRunningProcess =
                refreshTrackedRunningProcess(normalizedAppId, trackedRunningProcess);
            if (trackedRunningProcess == null) {
              return true;
            }
            processTree = trackedRunningProcess.processTree();
            destroyRootProcessForcibly(trackedRunningProcess);
            waitForProcessExit(trackedRunningProcess.process(), stopTimeout);
            if (!waitForProcessTreeExit(processTree, stopTimeout)) {
              if (!preserveRunningState(normalizedAppId, trackedRunningProcess)) {
                return true;
              }
              throw new AppHostException("timed out stopping app: " + appId);
            }
          }
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      if (!preserveRunningState(normalizedAppId, trackedRunningProcess)) {
        return true;
      }
      throw new AppHostException("interrupted while stopping app: " + appId, e);
    }
    if (refreshTrackedRunningProcess(normalizedAppId, trackedRunningProcess) != null) {
      throw new AppHostException("timed out stopping app: " + appId);
    }
    trackedRunningProcess.exitCleanup().join();
    runningApps.remove(normalizedAppId, trackedRunningProcess);
    return true;
  }

  @Override
  public synchronized Optional<RunningAppSnapshot> status(String appId) {
    RunningProcess runningProcess = liveRunningProcess(InstalledAppPaths.normalizeAppId(appId));
    return runningProcess != null ? Optional.of(runningProcess.snapshot()) : Optional.empty();
  }

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
    if (!installedRoot.getFileName().toString().equals(manifest.appId())) {
      throw new AppManifestException(
          "installed manifest app.id does not match directory name: "
              + installedRoot.getFileName());
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

  private static void ensureManagedDirectory(Path baseDirectory, Path directory, String label)
      throws IOException {
    Path normalized = directory.toAbsolutePath().normalize();
    validateManagedPathPrefixes(baseDirectory, normalized, label);
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
      throw new AppHostException(label + " must resolve beneath an existing filesystem root");
    }
    validateManagedDirectoryEntry(current, label);
    while (!missingSegments.isEmpty()) {
      current = current.resolve(missingSegments.pop());
      Files.createDirectory(current);
    }
    validateManagedDirectoryEntry(normalized, label);
    if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(label + " must be a directory: " + normalized);
    }
  }

  private Path validateInstalledAppsDirectory() throws IOException {
    Path installedAppsDir = layout.installedAppsDir().toAbsolutePath().normalize();
    validateManagedPathPrefixes(layout.dataDir(), installedAppsDir, "installedAppsDir");
    if (!Files.exists(installedAppsDir, LinkOption.NOFOLLOW_LINKS)) {
      return installedAppsDir;
    }
    validateManagedDirectoryEntry(installedAppsDir, "installedAppsDir");
    if (!Files.isDirectory(installedAppsDir, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException("installedAppsDir must be a directory: " + installedAppsDir);
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

  private static boolean shouldSkipInstalledEntry(Path appRoot) throws IOException {
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
    Path fileName = appRoot.getFileName();
    return fileName != null && fileName.toString().startsWith(TEMP_INSTALL_PREFIX);
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
    long deadline = System.nanoTime() + STARTUP_EXIT_GRACE_PERIOD.toNanos();
    long captureDeadline = System.nanoTime() + STARTUP_PROCESS_CAPTURE_WINDOW.toNanos();
    long handoffDeadline = captureDeadline + STARTUP_POST_CAPTURE_HANDOFF_GRACE_PERIOD.toNanos();
    while (System.nanoTime() < deadline) {
      observedHandles.addAll(snapshotProcessTree(startupSeedHandles(rootHandle, observedHandles)));
      if (!rootHandle.isAlive()) {
        break;
      }
      long now = System.nanoTime();
      if (now >= handoffDeadline) {
        break;
      }
      long remainingNanos = deadline - now;
      if (remainingNanos <= 0L) {
        break;
      }
      long pollIntervalNanos =
          now >= captureDeadline
              ? STARTUP_HANDOFF_POLL_INTERVAL_NANOS
              : STARTUP_PROCESS_POLL_INTERVAL_NANOS;
      long pollNanos = Math.min(remainingNanos, pollIntervalNanos);
      boolean exited = waitForProcess(process, pollNanos, appId);
      if (!exited && System.nanoTime() >= handoffDeadline) {
        break;
      }
    }
    capturePostExitProcessTree(rootHandle, observedHandles, appId);
    observedHandles.addAll(snapshotProcessTree(List.of(rootHandle)));
    return aliveHandles(observedHandles);
  }

  private boolean waitForProcess(Process process, long timeoutNanos, String appId)
      throws AppHostException {
    try {
      return process.waitFor(timeoutNanos, TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AppHostException("interrupted while starting app: " + appId, e);
    }
  }

  private static boolean waitForProcessExit(Process process, Duration timeout)
      throws InterruptedException {
    return process.waitFor(timeout.toNanos(), TimeUnit.NANOSECONDS);
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
    long startupTrackingDeadline = System.nanoTime() + STARTUP_EXIT_GRACE_PERIOD.toNanos();
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
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } finally {
      refreshObservedProcessTree(appId, process);
    }
  }

  private void capturePostExitProcessTreeHandoff(String appId, Process process)
      throws InterruptedException {
    long deadline = System.nanoTime() + TRACKED_PROCESS_POST_EXIT_CAPTURE_GRACE_PERIOD.toNanos();
    while (System.nanoTime() < deadline) {
      refreshObservedProcessTree(appId, process);
      TimeUnit.NANOSECONDS.sleep(STARTUP_PROCESS_POLL_INTERVAL_NANOS);
    }
  }

  private void capturePostExitProcessTree(
      ProcessHandle rootHandle, List<ProcessHandle> observedHandles, String appId)
      throws AppHostException {
    if (rootHandle.isAlive()) {
      return;
    }
    long deadline = System.nanoTime() + TRACKED_PROCESS_POST_EXIT_CAPTURE_GRACE_PERIOD.toNanos();
    while (System.nanoTime() < deadline) {
      observedHandles.addAll(snapshotProcessTree(startupSeedHandles(rootHandle, observedHandles)));
      try {
        TimeUnit.NANOSECONDS.sleep(STARTUP_PROCESS_POLL_INTERVAL_NANOS);
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

  private static long trackedProcessRefreshIntervalNanos(long startupTrackingDeadline) {
    if (System.nanoTime() < startupTrackingDeadline) {
      return STARTUP_PROCESS_POLL_INTERVAL_NANOS;
    }
    return TRACKED_PROCESS_REFRESH_INTERVAL.toNanos();
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
            Path.of(systemRoot, "System32").toString(),
            Path.of(systemRoot, "System32", "WindowsPowerShell", "v1.0").toString(),
            systemRoot));
    copyHostEnvironmentValue(environment, "TEMP");
    copyHostEnvironmentValue(environment, "TMP");
  }

  static List<String> launchCommand(Path executable, AppEnv appEnv) throws IOException {
    String executableText = executable.toString();
    if (appEnv.isWindows() && isWindowsBatchScript(executable)) {
      return List.of(
          windowsCommandInterpreter(), "/d", "/c", quoteWindowsBatchCommand(executableText));
    }
    if (!appEnv.isWindows()) {
      PosixLauncher posixLauncher = classifyPosixLauncher(executable);
      if (posixLauncher != null) {
        return posixLauncher.command(executable);
      }
    }
    return List.of(executableText);
  }

  private static List<String> posixShellLaunchCommand(Path executable, List<String> interpreter) {
    List<String> command = new ArrayList<>(interpreter);
    command.add("-c");
    command.add(
        """
        trap 'sleep %s' EXIT
        set --
        . "$0"
        """
            .formatted(posixShellExitTrapDelaySeconds()));
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
    String fileName = executable.getFileName().toString().toLowerCase(Locale.ROOT);
    return fileName.endsWith(".cmd") || fileName.endsWith(".bat");
  }

  private static boolean isLaunchableWindowsExecutable(Path executable) throws IOException {
    return isWindowsBatchScript(executable)
        || hasWindowsComExecutableSuffix(executable)
        || hasLaunchablePortableExecutable(executable);
  }

  private static boolean hasWindowsComExecutableSuffix(Path executable) {
    String fileName = executable.getFileName().toString().toLowerCase(Locale.ROOT);
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
    String fileName = executable.getFileName().toString().toLowerCase(Locale.ROOT);
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

  private static String posixShellExitTrapDelaySeconds() {
    return String.format(Locale.ROOT, "%.3f", STARTUP_PROCESS_CAPTURE_WINDOW.toMillis() / 1000.0d);
  }

  private static String windowsCommandInterpreter() {
    return Path.of(resolveWindowsRoot(), "System32", "cmd.exe").toString();
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
    String systemRoot = firstNonBlankEnvironmentValue("SystemRoot", "SYSTEMROOT", "WINDIR");
    return systemRoot != null ? systemRoot : "C:\\Windows";
  }

  private static String firstNonBlankEnvironmentValue(String... names) {
    for (String name : names) {
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
          public @NotNull FileVisitResult visitFileFailed(@NotNull Path file, IOException exc)
              throws IOException {
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
    try {
      RunningProcess trackedRunningProcess = runningProcess.withProcessTree(processTree);
      runningApps.replace(appId, runningProcess, trackedRunningProcess);
      return trackedRunningProcess;
    } catch (IllegalArgumentException e) {
      runningProcess.exitCleanup().join();
      runningApps.remove(appId, runningProcess);
      return null;
    }
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
    return runningProcess.withProcessTree(recoveredHandles);
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
              paths, manifest, startedAt, trackedHandles, processCandidates));
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
                    startedWithinWindowsRecoveryWindow(processHandle, startedAt)
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
    String psCommand = resolveTrustedUnixCommand("ps");
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
    } catch (IOException e) {
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
    } catch (NumberFormatException e) {
      return Optional.empty();
    }
  }

  private static String resolveTrustedUnixCommand(String command) {
    for (Path trustedDir :
        List.of(Path.of("/usr/bin"), Path.of("/bin"), Path.of("/usr/sbin"), Path.of("/sbin"))) {
      Path candidate = trustedDir.resolve(command);
      if (Files.isExecutable(candidate)) {
        return candidate.toString();
      }
    }
    return null;
  }

  private static boolean startedWithinWindowsRecoveryWindow(
      ProcessHandle processHandle, Instant startedAt) {
    return processHandle
        .info()
        .startInstant()
        .map(
            candidateStartedAt ->
                !candidateStartedAt.isBefore(startedAt.minusSeconds(1))
                    && !candidateStartedAt.isAfter(startedAt.plus(WINDOWS_BUNDLE_RECOVERY_WINDOW)))
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
    return Files.isReadable(Path.of("/proc", "self", "environ"));
  }

  private static boolean hasAppHostToken(long pid, String token, String appId) {
    Path environmentFile = Path.of("/proc", Long.toString(pid), "environ");
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
    Path statFile = Path.of("/proc", Long.toString(processHandle.pid()), "stat");
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
    } catch (IOException e) {
      return false;
    }
  }

  private record PosixLauncher(List<String> interpreter, boolean shellInterpreter) {
    private PosixLauncher {
      interpreter = List.copyOf(interpreter);
    }

    private List<String> command(Path executable) {
      return shellInterpreter
          ? posixShellLaunchCommand(executable, interpreter)
          : directInterpreterLaunchCommand(executable, interpreter);
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
      return withProcessTree(currentProcessTree);
    }

    private RunningProcess withProcessTree(List<ProcessHandle> newProcessTree) {
      List<ProcessHandle> aliveProcessTree = aliveHandles(newProcessTree);
      if (aliveProcessTree.isEmpty()) {
        throw new IllegalArgumentException("newProcessTree must contain a live process");
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
