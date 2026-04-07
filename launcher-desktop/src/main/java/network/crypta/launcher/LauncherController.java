package network.crypta.launcher;

import java.awt.Desktop;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import network.crypta.fs.AppEnv;
import network.crypta.fs.readiness.LauncherReadinessFiles;
import network.crypta.fs.readiness.LauncherReadinessInfo;

import static network.crypta.launcher.LauncherLog.logDebug;

/**
 * Coordinates launcher process lifecycle and UI-facing state/log notifications.
 *
 * <p>This controller is the orchestration layer between the Swing launcher frame and the managed
 * {@code cryptad} process. It handles start/stop/shutdown transitions, tails process output,
 * extracts runtime metadata (such as detected browser port), and emits immutable state snapshots to
 * registered listeners. Long-running and blocking work executes on a dedicated single-thread
 * executor pool to keep UI interactions responsive while allowing concurrent lifecycle tasks.
 *
 * <p>Notable behavior:
 *
 * <ul>
 *   <li>Runs process lifecycle, browser launch, and log tailing tasks asynchronously.
 *   <li>Tracks shutdown intent to prevent restarts during the termination flow.
 *   <li>Publishes both structured state updates and raw log lines for view rendering.
 * </ul>
 */
public class LauncherController {
  private record TrackedReadinessFile(
      Path path,
      boolean existedWhenTracked,
      long lastModifiedWhenTracked,
      Object fileKeyWhenTracked,
      LauncherReadinessInfo infoWhenTracked,
      boolean trackedAfterLaunch,
      boolean retargetedAfterLaunch) {
    private TrackedReadinessFile {
      Objects.requireNonNull(path);
    }
  }

  private static final ThreadFactory IO_THREAD_FACTORY =
      runnable -> {
        Thread thread = new Thread(runnable, "launcher-io");
        thread.setDaemon(true);
        return thread;
      };
  private final ExecutorService io = Executors.newCachedThreadPool(IO_THREAD_FACTORY);
  private final Path cwd;
  private final List<Consumer<String>> logListeners = new CopyOnWriteArrayList<>();
  private final List<Consumer<AppState>> stateListeners = new CopyOnWriteArrayList<>();

  private final AtomicReference<Process> process = new AtomicReference<>();
  private final AtomicReference<AppState> state = new AtomicReference<>(new AppState());
  private final AtomicReference<Path> wrapperConfPath = new AtomicReference<>();
  private final AtomicReference<TrackedReadinessFile> readinessTarget = new AtomicReference<>();
  private final AtomicLong launchStartedAtMillis = new AtomicLong();
  private final Object browserAutoOpenStateLock = new Object();
  private final AtomicBoolean autoOpenedBrowser = new AtomicBoolean();
  private final AtomicBoolean defaultStructuredAutoOpenedBrowser = new AtomicBoolean();
  private final AtomicBoolean legacyFallbackAutoOpenedBrowser = new AtomicBoolean();
  private final AtomicReference<Integer> pendingLegacyPort = new AtomicReference<>();
  private final AtomicBoolean startupCompletionObserved = new AtomicBoolean();
  private final AtomicBoolean logFallbackEnabled = new AtomicBoolean();
  private final AtomicReference<Thread> tailThread = new AtomicReference<>();
  private static final String UNIX_KILL_EXECUTABLE = "/bin/kill";
  private static final String WINDOWS_TASKKILL_EXECUTABLE =
      Path.of(System.getenv().getOrDefault("SystemRoot", "C:\\Windows"), "System32", "taskkill.exe")
          .toString();
  private static final String WINDOWS_RUNDLL32_EXECUTABLE =
      Path.of(System.getenv().getOrDefault("SystemRoot", "C:\\Windows"), "System32", "rundll32.exe")
          .toString();
  private static final String MAC_OPEN_EXECUTABLE = "/usr/bin/open";
  private static final String LINUX_XDG_OPEN_EXECUTABLE = "/usr/bin/xdg-open";
  private static final String LINUX_XDG_OPEN_EXECUTABLE_FALLBACK = "/bin/xdg-open";
  private static final long TAIL_BASE_DELAY_MS = 200L;
  private static final long TAIL_MAX_DELAY_MS = 1500L;
  private static final long TAIL_CANCEL_POLL_MS = 50L;
  private static final int TAIL_READ_CHUNK = 64 * 1024;
  private static final long READINESS_POLL_MS = 100L;
  private static final String NODE_INITIALIZATION_COMPLETED_MARKER =
      "Node initialization completed";
  private final Supplier<Path> readinessFileResolver;
  private final Supplier<Path> daemonLogFileResolver;

  /**
   * Creates a controller rooted at the current working directory.
   *
   * <p>The working directory is resolved from {@code user.dir} and used to locate the launcher
   * script and related files.
   */
  public LauncherController() {
    this(Path.of(System.getProperty("user.dir")));
  }

  /**
   * Creates a controller that resolves launcher resources relative to the given directory.
   *
   * @param cwd working directory used to locate the {@code cryptad} executable and wrapper files
   */
  public LauncherController(Path cwd) {
    this(
        cwd,
        LauncherUtils::resolveConfiguredLauncherReadinessFile,
        LauncherUtils::resolveConfiguredLauncherDaemonLogFile);
  }

  LauncherController(Path cwd, Supplier<Path> readinessFileResolver) {
    this(cwd, readinessFileResolver, LauncherUtils::resolveConfiguredLauncherDaemonLogFile);
  }

  LauncherController(
      Path cwd, Supplier<Path> readinessFileResolver, Supplier<Path> daemonLogFileResolver) {
    this.cwd = Objects.requireNonNull(cwd);
    this.readinessFileResolver = Objects.requireNonNull(readinessFileResolver);
    this.daemonLogFileResolver = Objects.requireNonNull(daemonLogFileResolver);
  }

  /**
   * Returns the latest immutable launcher state snapshot.
   *
   * @return current application state representing process and shutdown flags
   */
  public AppState getState() {
    return state.get();
  }

  /**
   * Registers a listener that receives emitted process log lines.
   *
   * <p>A {@code null} listener is ignored. Listeners are invoked synchronously on the emitting
   * thread.
   *
   * @param listener log consumer that receives one line per callback
   */
  public void addLogListener(Consumer<String> listener) {
    if (listener != null) {
      logListeners.add(listener);
    }
  }

  /**
   * Unregisters a previously added log listener.
   *
   * <p>If the listener is not present, this method has no effect.
   *
   * @param listener log consumer to remove from callback dispatch
   */
  @SuppressWarnings("unused")
  public void removeLogListener(Consumer<String> listener) {
    logListeners.remove(listener);
  }

  /**
   * Registers a listener for state updates and immediately emits the current state.
   *
   * <p>A {@code null} listener is ignored.
   *
   * @param listener state consumer that receives current and future state snapshots
   */
  public void addStateListener(Consumer<AppState> listener) {
    if (listener != null) {
      stateListeners.add(listener);
      listener.accept(state.get());
    }
  }

  /**
   * Unregisters a previously added state listener.
   *
   * <p>If the listener is not present, this method has no effect.
   *
   * @param listener state consumer to remove from callback dispatch
   */
  @SuppressWarnings("unused")
  public void removeStateListener(Consumer<AppState> listener) {
    stateListeners.remove(listener);
  }

  /**
   * Starts the managed {@code cryptad} process when not already running.
   *
   * <p>This method validates executable availability, updates launcher state, then schedules
   * process start, and output monitoring on the controller executor. If startup fails, an error
   * line is emitted and state is restored to non-running.
   */
  public synchronized void start() {
    Process currentProcess = process.get();
    if (state.get().isRunning() || (currentProcess != null && currentProcess.isAlive())) {
      return;
    }

    io.execute(this::startProcessAndWatch);
  }

  private void startProcessAndWatch() {
    Path cryptadPath = LauncherUtils.resolveCryptadPath(cwd);
    AppEnv env = new AppEnv();
    boolean launchable =
        Files.isRegularFile(cryptadPath) && (env.isWindows() || Files.isExecutable(cryptadPath));
    if (!launchable) {
      emitLog(ts() + " ERROR: Cannot find executable 'cryptad' at " + cryptadPath);
      return;
    }

    emitLog(ts() + " Starting '" + cryptadPath.getFileName() + "' ...");
    updateState(
        s ->
            s.withRunning(true)
                .withKnownPort(null)
                .withKnownUiRoot(LauncherReadinessInfo.DEFAULT_UI_ROOT));

    tryEnableConsoleFlush(cryptadPath);
    readinessTarget.set(null);
    launchStartedAtMillis.set(0);
    resetStructuredAutoOpenState();
    pendingLegacyPort.set(null);
    startupCompletionObserved.set(false);
    TrackedReadinessFile initialReadinessTarget = prepareStructuredReadinessFile();
    readinessTarget.set(initialReadinessTarget);
    logFallbackEnabled.set(true);
    Path configuredDaemonLogFile = resolveConfiguredDaemonLogFile();
    long configuredDaemonLogOffset = currentFileLength(configuredDaemonLogFile);
    Path wrapperConf = LauncherUtils.guessWrapperConfPathForCryptadScript(cryptadPath);
    Path wrapperLogFile = resolveWrapperLogFile(wrapperConf);
    long wrapperLogOffset = currentFileLength(wrapperLogFile);

    List<String> command = LauncherUtils.buildCryptadCommand(cryptadPath);
    emitLog(
        ts() + " exec: " + formatCommandForLog(command) + " (cwd=" + cwd.toAbsolutePath() + ")");
    ProcessBuilder pb = new ProcessBuilder(command);
    pb.directory(cwd.toFile());
    pb.redirectErrorStream(true);

    Process started;
    long currentLaunchStartedAtMillis = System.currentTimeMillis();
    try {
      started = pb.start();
      launchStartedAtMillis.set(currentLaunchStartedAtMillis);
    } catch (Exception e) {
      logDebug("Launcher process start failed", e);
      emitLog(ts() + " ERROR: " + e.getMessage());
      updateState(s -> s.withRunning(false));
      return;
    }

    process.set(started);
    wrapperConfPath.set(wrapperConf);
    startTailingWrapperLogIfAvailable(wrapperLogFile, wrapperLogOffset);
    startWatchingConfiguredDaemonLog(started, configuredDaemonLogFile, configuredDaemonLogOffset);
    io.execute(() -> waitForStructuredReadiness(started));
    io.execute(() -> readProcessOutput(started));
    io.execute(() -> watchProcess(started));
  }

  private void readProcessOutput(Process started) {
    try (BufferedReader reader =
        new BufferedReader(
            new InputStreamReader(started.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        emitLog(line);
        processStartupDiscoveryLine(line);
        Integer detectedPort = LauncherUtils.parseFProxyPortFromLine(line);
        if (detectedPort != null) {
          handleLegacyDetectedPort(detectedPort, logFallbackEnabled.get());
        }
      }
    } catch (Exception e) {
      logDebug("Launcher process output reader failed", e);
    }
  }

  private void waitForStructuredReadiness(Process started) {
    LauncherReadinessFiles.ReadinessSnapshot lastHandledReadiness = null;
    while (true) {
      lastHandledReadiness = pollStructuredReadiness(lastHandledReadiness);
      if (!started.isAlive() || !sleepForReadinessPoll()) {
        return;
      }
    }
  }

  private LauncherReadinessFiles.ReadinessSnapshot pollStructuredReadiness(
      LauncherReadinessFiles.ReadinessSnapshot lastHandledReadiness) {
    TrackedReadinessFile currentReadinessTarget = readinessTarget.get();
    Path currentReadinessFile = currentReadinessFile(currentReadinessTarget);
    try {
      return handleAvailableStructuredReadiness(
          currentReadinessTarget, currentReadinessFile, lastHandledReadiness);
    } catch (IOException e) {
      logDebug("Launcher readiness-file reader failed for " + currentReadinessFile, e);
      fallbackToLegacyReadiness();
      return null;
    }
  }

  private LauncherReadinessFiles.ReadinessSnapshot handleAvailableStructuredReadiness(
      TrackedReadinessFile currentReadinessTarget,
      Path currentReadinessFile,
      LauncherReadinessFiles.ReadinessSnapshot lastHandledReadiness)
      throws IOException {
    if (currentReadinessFile == null) {
      return lastHandledReadiness;
    }
    var readiness = readStructuredReadinessSnapshot(currentReadinessFile);
    if (readiness.isEmpty()
        || !canConsumeCurrentLaunchReadiness(currentReadinessTarget, readiness.get())) {
      return lastHandledReadiness;
    }
    return handleNewStructuredReadiness(readiness.get(), lastHandledReadiness);
  }

  private LauncherReadinessFiles.ReadinessSnapshot handleNewStructuredReadiness(
      LauncherReadinessFiles.ReadinessSnapshot currentReadiness,
      LauncherReadinessFiles.ReadinessSnapshot lastHandledReadiness) {
    if (currentReadiness.equals(lastHandledReadiness)) {
      return lastHandledReadiness;
    }
    handleStructuredReadiness(currentReadiness.info());
    return currentReadiness;
  }

  private static Path currentReadinessFile(TrackedReadinessFile currentReadinessTarget) {
    return currentReadinessTarget != null ? currentReadinessTarget.path() : null;
  }

  private boolean sleepForReadinessPoll() {
    try {
      TimeUnit.MILLISECONDS.sleep(READINESS_POLL_MS);
      return true;
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  Optional<LauncherReadinessFiles.ReadinessSnapshot> readStructuredReadinessSnapshot(
      Path readinessFile) throws IOException {
    return LauncherReadinessFiles.readSnapshot(readinessFile);
  }

  private void handleLegacyDetectedPort(int port, boolean allowAutoLaunch) {
    if (readinessTarget.get() != null) {
      pendingLegacyPort.set(port);
      if (startupCompletionObserved.get()) {
        fallbackToLegacyReadiness();
      }
      return;
    }
    publishLegacyPort(port, allowAutoLaunch);
  }

  private void publishLegacyPort(int port, boolean allowAutoLaunch) {
    AppState currentState = state.get();
    if (!Objects.equals(currentState.knownPort(), port)
        || !Objects.equals(currentState.knownUiRoot(), LauncherReadinessInfo.DEFAULT_UI_ROOT)) {
      updateState(
          s -> s.withKnownUiRoot(LauncherReadinessInfo.DEFAULT_UI_ROOT).withKnownPort(port));
    }
    if (!allowAutoLaunch) {
      return;
    }
    if (readinessTarget.get() == null) {
      if (startupCompletionObserved.get()) {
        launchBrowserOnce();
      } else {
        launchBrowserOnceIfProcessAlive();
      }
    }
  }

  private void handleStructuredReadiness(LauncherReadinessInfo readinessInfo) {
    logFallbackEnabled.set(false);
    pendingLegacyPort.set(null);
    AppState currentState = state.get();
    if (!Objects.equals(currentState.knownPort(), readinessInfo.uiPort())
        || !Objects.equals(currentState.knownUiRoot(), readinessInfo.uiRoot())) {
      updateState(
          s -> s.withKnownPort(readinessInfo.uiPort()).withKnownUiRoot(readinessInfo.uiRoot()));
    }
    if (markStructuredBrowserAutoOpened(readinessInfo)) {
      launchBrowser();
      return;
    }
    if (consumeLegacyFallbackPromotion(readinessInfo)) {
      launchBrowser();
      return;
    }
    if (shouldRelaunchAfterDefaultStructuredPromotion(currentState, readinessInfo)) {
      launchBrowser();
    }
  }

  private boolean shouldRelaunchAfterDefaultStructuredPromotion(
      AppState currentState, LauncherReadinessInfo readinessInfo) {
    synchronized (browserAutoOpenStateLock) {
      return LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(currentState.knownUiRoot())
          && !LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(readinessInfo.uiRoot())
          && defaultStructuredAutoOpenedBrowser.compareAndSet(true, false);
    }
  }

  private void watchProcess(Process started) {
    int exitCode;
    try {
      exitCode = started.waitFor();
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return;
    }
    emitLog(ts() + " cryptad exited with code " + exitCode);
    clearTrackedProcess(started);
    finishTailThreadAfterProcessExit();
    readinessTarget.set(null);
    launchStartedAtMillis.set(0);
    resetStructuredAutoOpenState();
    pendingLegacyPort.set(null);
    startupCompletionObserved.set(false);
    logFallbackEnabled.set(false);
    updateState(s -> s.withRunning(false));
  }

  /**
   * Requests graceful process termination and escalates to forced termination when needed.
   *
   * <p>If no process is active, the state is normalized to non-running immediately.
   */
  public synchronized void stop() {
    Process current = process.get();
    if (current == null) {
      return;
    }

    if (!current.isAlive()) {
      updateState(s -> s.withRunning(false));
      return;
    }

    updateState(s -> s.withStopping(true));
    io.execute(
        () -> {
          try {
            stopManagedProcess(current);
          } finally {
            updateState(s -> s.withStopping(false));
          }
        });
  }

  private void stopManagedProcess(Process current) {
    try {
      long rootPid = current.pid();
      List<Long> trackedPids = snapshotProcessTreePids(rootPid);
      if (trackedPids.isEmpty()) {
        trackedPids = List.of(rootPid);
      }
      AppEnv env = new AppEnv();
      if (env.isWindows()) {
        stopProcessTreeWindows(rootPid, trackedPids);
      } else {
        stopProcessTreeUnix(trackedPids);
      }
      if (current.isAlive()) {
        current.destroyForcibly();
      }
      if (!current.isAlive()) {
        clearTrackedProcess(current);
        interruptTailThread();
        updateState(s -> s.withRunning(false));
      }
    } catch (Exception e) {
      emitLog(ts() + " ERROR: Failed to stop process: " + e.getMessage());
      logDebug("Failed to stop process gracefully", e);
    }
  }

  private void stopProcessTreeUnix(List<Long> pids) {
    if (!pids.isEmpty()) {
      emitLog(ts() + " Sending SIGINT to wrapper tree (root PID " + pids.getFirst() + ") ...");
    }
    sendSignalToPids(pids, "INT");
    if (waitForPidsToExit(pids, 20)) {
      return;
    }

    emitLog(ts() + " Escalating: sending SIGTERM to remaining processes ...");
    List<Long> alive = alivePids(pids);
    sendSignalToPids(alive, "TERM");
    if (waitForPidsToExit(pids, 5)) {
      return;
    }

    emitLog(ts() + " Escalating: sending SIGKILL to remaining processes ...");
    sendSignalToPids(alivePids(pids), "KILL");
    waitForPidsToExit(pids, 2);
  }

  private void stopProcessTreeWindows(long rootPid, List<Long> pids) {
    if (!tryWindowsGracefulStopViaAnchor(pids)) {
      runTaskkill(rootPid, false);
      if (waitForPidsToExit(pids, 20)) {
        return;
      }
      runTaskkill(rootPid, true);
      waitForPidsToExit(pids, 5);
    }
  }

  private List<Long> snapshotProcessTreePids(long rootPid) {
    List<Long> pids = new ArrayList<>();
    pids.add(rootPid);
    try {
      ProcessHandle.of(rootPid)
          .ifPresent(root -> root.descendants().map(ProcessHandle::pid).forEach(pids::add));
    } catch (Exception e) {
      logDebug("Failed to snapshot descendants for pid=" + rootPid, e);
    }
    return pids;
  }

  private void sendSignalToPids(List<Long> pids, String signal) {
    for (long pid : pids) {
      if (isPidAlive(pid)) {
        runUnixKill(pid, signal);
      }
    }
  }

  private void runUnixKill(long pid, String signal) {
    Process kill = null;
    try {
      kill = new ProcessBuilder(UNIX_KILL_EXECUTABLE, "-" + signal, Long.toString(pid)).start();
      if (!kill.waitFor(2, TimeUnit.SECONDS)) {
        kill.destroyForcibly();
      }
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      kill.destroyForcibly();
    } catch (Exception e) {
      logDebug("Failed sending signal " + signal + " to pid=" + pid, e);
      if (kill != null) {
        kill.destroyForcibly();
      }
    }
  }

  private void runTaskkill(long pid, boolean force) {
    Process taskkill = null;
    try {
      List<String> command =
          new ArrayList<>(List.of(WINDOWS_TASKKILL_EXECUTABLE, "/PID", Long.toString(pid), "/T"));
      if (force) {
        command.add("/F");
      }
      taskkill = new ProcessBuilder(command).start();
      if (!taskkill.waitFor(5, TimeUnit.SECONDS)) {
        taskkill.destroyForcibly();
      }
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      taskkill.destroyForcibly();
    } catch (Exception e) {
      logDebug("Failed running taskkill for pid=" + pid + " force=" + force, e);
      if (taskkill != null) {
        taskkill.destroyForcibly();
      }
    }
  }

  private boolean waitForPidsToExit(List<Long> pids, long timeoutSeconds) {
    List<CompletableFuture<ProcessHandle>> exitFutures =
        pids.stream()
            .map(ProcessHandle::of)
            .flatMap(java.util.Optional::stream)
            .map(ProcessHandle::onExit)
            .toList();
    if (exitFutures.isEmpty()) {
      return pids.stream().noneMatch(this::isPidAlive);
    }

    CompletableFuture<Void> allExited =
        CompletableFuture.allOf(exitFutures.toArray(CompletableFuture[]::new));
    try {
      allExited.get(timeoutSeconds, TimeUnit.SECONDS);
      return true;
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return false;
    } catch (TimeoutException _) {
      return pids.stream().noneMatch(this::isPidAlive);
    } catch (ExecutionException e) {
      logDebug("Failed waiting for process exit futures", e);
      return pids.stream().noneMatch(this::isPidAlive);
    }
  }

  private List<Long> alivePids(List<Long> pids) {
    List<Long> alive = new ArrayList<>(pids.size());
    for (long pid : pids) {
      if (isPidAlive(pid)) {
        alive.add(pid);
      }
    }
    return alive;
  }

  private boolean isPidAlive(long pid) {
    try {
      return ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false);
    } catch (Exception e) {
      logDebug("Failed checking pid liveness for pid=" + pid, e);
      return false;
    }
  }

  private void clearTrackedProcess(Process expected) {
    if (expected != null) {
      process.compareAndSet(expected, null);
    } else {
      process.set(null);
    }
  }

  private Path resolveConfiguredDaemonLogFile() {
    try {
      return daemonLogFileResolver.get();
    } catch (RuntimeException e) {
      logDebug("Launcher daemon-log resolution failed", e);
      return null;
    }
  }

  private Path resolveWrapperLogFile(Path wrapperConf) {
    if (wrapperConf == null) {
      return null;
    }
    String logSpec = readWrapperProperty(wrapperConf, "wrapper.logfile");
    return LauncherUtils.computeWrapperLogPath(wrapperConf, logSpec);
  }

  private long currentFileLength(Path path) {
    if (path == null || !Files.isRegularFile(path)) {
      return 0L;
    }
    try {
      return Files.size(path);
    } catch (IOException e) {
      logDebug("Launcher daemon-log length lookup failed for " + path, e);
      return 0L;
    }
  }

  private void startWatchingConfiguredDaemonLog(Process started, Path logFile, long initialOffset) {
    if (logFile == null) {
      return;
    }
    io.execute(() -> watchConfiguredDaemonLogForRunDir(started, logFile, initialOffset));
  }

  private void watchConfiguredDaemonLogForRunDir(
      Process started, Path logFile, long initialOffset) {
    long position = initialOffset;
    StringBuilder leftover = new StringBuilder();
    while (started.isAlive()) {
      try {
        if (Files.isRegularFile(logFile)) {
          position = readDaemonLogDelta(logFile, position, leftover);
        }
      } catch (IOException e) {
        logDebug("Launcher daemon-log reader failed for " + logFile, e);
        return;
      }

      if (!started.isAlive()) {
        return;
      }

      try {
        TimeUnit.MILLISECONDS.sleep(READINESS_POLL_MS);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        return;
      }
    }
  }

  private long readDaemonLogDelta(Path logFile, long position, StringBuilder leftover)
      throws IOException {
    long length = Files.size(logFile);
    if (length < position) {
      position = 0L;
      leftover.setLength(0);
    }
    if (length <= position) {
      return position;
    }

    try (RandomAccessFile handle = new RandomAccessFile(logFile.toFile(), "r")) {
      handle.seek(position);
      int toRead = (int) Math.min(length - position, TAIL_READ_CHUNK);
      byte[] buffer = new byte[toRead];
      int read = handle.read(buffer);
      if (read <= 0) {
        return position;
      }
      emitDiscoveryText(leftover, new String(buffer, 0, read, StandardCharsets.UTF_8));
      return position + read;
    }
  }

  private void emitDiscoveryText(StringBuilder leftover, String text) {
    String[] parts = text.split("\n", -1);
    if (parts.length == 1) {
      leftover.append(parts[0]);
      return;
    }

    String first = leftover.append(parts[0]).toString();
    if (!first.isEmpty()) {
      processStartupDiscoveryLine(first);
    }
    leftover.setLength(0);

    for (int i = 1; i < parts.length - 1; i++) {
      processStartupDiscoveryLine(parts[i]);
    }
    String last = parts[parts.length - 1];
    if (text.endsWith("\n")) {
      if (!last.isEmpty()) {
        processStartupDiscoveryLine(last);
      }
    } else {
      leftover.append(last);
    }
  }

  private void processStartupDiscoveryLine(String line) {
    Path detectedRunDir = LauncherUtils.parseResolvedRunDirFromLine(line);
    if (detectedRunDir != null) {
      updateStructuredReadinessFile(detectedRunDir);
    }
    if (line.contains(NODE_INITIALIZATION_COMPLETED_MARKER)) {
      handleStartupCompletionSignal();
    }
  }

  private void handleStartupCompletionSignal() {
    startupCompletionObserved.set(true);
    TrackedReadinessFile currentReadinessTarget = readinessTarget.get();
    Path currentReadinessFile =
        currentReadinessTarget != null ? currentReadinessTarget.path() : null;
    if (currentReadinessFile == null) {
      return;
    }
    try {
      var readiness = LauncherReadinessFiles.readSnapshot(currentReadinessFile);
      if (readiness.isPresent()
          && canConsumeCurrentLaunchReadiness(currentReadinessTarget, readiness.get())) {
        handleStructuredReadiness(readiness.get().info());
        return;
      }
    } catch (IOException e) {
      logDebug("Launcher readiness-file reader failed for " + currentReadinessFile, e);
    }
    if (pendingLegacyPort.get() != null) {
      fallbackToLegacyReadiness();
    }
  }

  private TrackedReadinessFile prepareStructuredReadinessFile() {
    Path readinessFile;
    try {
      readinessFile = readinessFileResolver.get();
    } catch (RuntimeException e) {
      logDebug("Launcher readiness-file resolution failed", e);
      return null;
    }
    if (readinessFile == null) {
      return null;
    }
    return captureReadinessTarget(readinessFile);
  }

  private void updateStructuredReadinessFile(Path runDir) {
    Path nextReadinessFile = LauncherReadinessFiles.resolve(runDir);
    TrackedReadinessFile currentReadinessTarget = readinessTarget.get();
    Path currentReadinessFile =
        currentReadinessTarget != null ? currentReadinessTarget.path() : null;
    if (Objects.equals(currentReadinessFile, nextReadinessFile)) {
      return;
    }
    readinessTarget.set(captureRetargetedReadinessTarget(nextReadinessFile));
  }

  private TrackedReadinessFile captureReadinessTarget(Path readinessFile) {
    return captureReadinessTarget(readinessFile, false, false);
  }

  private TrackedReadinessFile captureRetargetedReadinessTarget(Path readinessFile) {
    return captureReadinessTarget(readinessFile, true, true);
  }

  private TrackedReadinessFile captureReadinessTarget(
      Path readinessFile, boolean trackedAfterLaunch, boolean retargetedAfterLaunch) {
    boolean existedWhenTracked = Files.isRegularFile(readinessFile);
    long lastModifiedWhenTracked = Long.MIN_VALUE;
    Object fileKeyWhenTracked = null;
    if (existedWhenTracked) {
      try {
        lastModifiedWhenTracked = Files.getLastModifiedTime(readinessFile).toMillis();
      } catch (IOException e) {
        logDebug("Launcher readiness-file baseline lookup failed for " + readinessFile, e);
      }
      fileKeyWhenTracked = readFileKey(readinessFile);
    }
    LauncherReadinessInfo infoWhenTracked =
        readTrackedReadinessInfo(readinessFile, existedWhenTracked);
    return new TrackedReadinessFile(
        readinessFile,
        existedWhenTracked,
        lastModifiedWhenTracked,
        fileKeyWhenTracked,
        infoWhenTracked,
        trackedAfterLaunch,
        retargetedAfterLaunch);
  }

  private LauncherReadinessInfo readTrackedReadinessInfo(
      Path readinessFile, boolean existedWhenTracked) {
    if (!existedWhenTracked) {
      return null;
    }
    try {
      return LauncherReadinessFiles.readSnapshot(readinessFile)
          .map(LauncherReadinessFiles.ReadinessSnapshot::info)
          .orElse(null);
    } catch (IOException e) {
      logDebug("Launcher readiness-file baseline read failed for " + readinessFile, e);
      return null;
    }
  }

  boolean isCurrentLaunchReadinessFile(Path readinessFile) throws IOException {
    if (!Files.isRegularFile(readinessFile)) {
      return false;
    }
    var readiness = LauncherReadinessFiles.readSnapshot(readinessFile);
    if (readiness.isEmpty()) {
      return false;
    }
    TrackedReadinessFile trackedReadinessFile = readinessTarget.get();
    if (trackedReadinessFile == null
        || !Objects.equals(trackedReadinessFile.path(), readinessFile)) {
      trackedReadinessFile = captureReadinessTarget(readinessFile);
    }
    return isPotentialCurrentLaunchReadiness(trackedReadinessFile, readiness.get());
  }

  private boolean canConsumeCurrentLaunchReadiness(
      TrackedReadinessFile trackedReadinessFile,
      LauncherReadinessFiles.ReadinessSnapshot readiness) {
    if (trackedReadinessFile == null
        || !isPotentialCurrentLaunchReadiness(trackedReadinessFile, readiness)) {
      return false;
    }
    return readiness.lastModifiedTime() > launchStartedAtMillis.get()
        || hasReadinessFileChangedSinceTracking(
            trackedReadinessFile, readiness.lastModifiedTime(), readiness.fileKey())
        || startupCompletionObserved.get();
  }

  private boolean isPotentialCurrentLaunchReadiness(
      TrackedReadinessFile trackedReadinessFile,
      LauncherReadinessFiles.ReadinessSnapshot readiness) {
    long currentLaunchStartedAtMillis = launchStartedAtMillis.get();
    if (currentLaunchStartedAtMillis <= 0) {
      return false;
    }
    long lastModifiedTime = readiness.lastModifiedTime();
    if (lastModifiedTime > currentLaunchStartedAtMillis) {
      return true;
    }
    boolean changedSinceTracking =
        hasReadinessFileChangedSinceTracking(
            trackedReadinessFile, lastModifiedTime, readiness.fileKey());
    if (changedSinceTracking) {
      return true;
    }
    Integer deferredLegacyPort = pendingLegacyPort.get();
    boolean corroboratedByLegacyPort =
        deferredLegacyPort != null && deferredLegacyPort == readiness.info().uiPort();
    if (trackedReadinessFile.existedWhenTracked()) {
      return trackedReadinessFile.trackedAfterLaunch()
          && startupCompletionObserved.get()
          && corroboratedByLegacyPort
          && !(trackedReadinessFile.retargetedAfterLaunch()
              && matchesTrackedReadinessInfo(trackedReadinessFile, readiness));
    }
    if (lastModifiedTime < currentLaunchStartedAtMillis) {
      return startupCompletionObserved.get() && corroboratedByLegacyPort;
    }
    return corroboratedByLegacyPort;
  }

  private boolean hasReadinessFileChangedSinceTracking(
      TrackedReadinessFile trackedReadinessFile, long lastModifiedTime, Object currentFileKey) {
    if (!trackedReadinessFile.existedWhenTracked()) {
      return true;
    }
    Object trackedFileKey = trackedReadinessFile.fileKeyWhenTracked();
    if (trackedFileKey != null && currentFileKey != null) {
      return !trackedFileKey.equals(currentFileKey);
    }
    long trackedLastModifiedTime = trackedReadinessFile.lastModifiedWhenTracked();
    return trackedLastModifiedTime != Long.MIN_VALUE && lastModifiedTime != trackedLastModifiedTime;
  }

  private boolean matchesTrackedReadinessInfo(
      TrackedReadinessFile trackedReadinessFile,
      LauncherReadinessFiles.ReadinessSnapshot readiness) {
    LauncherReadinessInfo trackedInfo = trackedReadinessFile.infoWhenTracked();
    return trackedInfo != null && trackedInfo.equals(readiness.info());
  }

  private void fallbackToLegacyReadiness() {
    updateState(s -> s.withKnownUiRoot(LauncherReadinessInfo.DEFAULT_UI_ROOT));
    sanitizeStructuredReadinessTrackingAfterFallback();
    Integer deferredLegacyPort = pendingLegacyPort.get();
    if (deferredLegacyPort != null) {
      publishLegacyPort(deferredLegacyPort, false);
      if (logFallbackEnabled.get()) {
        if (startupCompletionObserved.get()) {
          launchLegacyFallbackBrowserOnce();
        } else {
          launchLegacyFallbackBrowserOnceIfProcessAlive();
        }
      }
    }
  }

  private void sanitizeStructuredReadinessTrackingAfterFallback() {
    TrackedReadinessFile currentReadinessTarget = readinessTarget.get();
    if (currentReadinessTarget == null || !currentReadinessTarget.trackedAfterLaunch()) {
      return;
    }
    readinessTarget.compareAndSet(
        currentReadinessTarget, captureReadinessTarget(currentReadinessTarget.path()));
  }

  private void launchBrowserOnceIfProcessAlive() {
    Process current = process.get();
    if (current == null || !current.isAlive()) {
      return;
    }
    launchBrowserOnce();
  }

  private void launchLegacyFallbackBrowserOnceIfProcessAlive() {
    Process current = process.get();
    if (current == null || !current.isAlive()) {
      return;
    }
    launchLegacyFallbackBrowserOnce();
  }

  private void launchBrowserOnce() {
    if (!autoOpenedBrowser.compareAndSet(false, true)) {
      return;
    }
    launchBrowser();
  }

  private void launchLegacyFallbackBrowserOnce() {
    synchronized (browserAutoOpenStateLock) {
      if (!autoOpenedBrowser.compareAndSet(false, true)) {
        return;
      }
      defaultStructuredAutoOpenedBrowser.set(false);
      legacyFallbackAutoOpenedBrowser.set(true);
    }
    launchBrowser();
  }

  private boolean markStructuredBrowserAutoOpened(LauncherReadinessInfo readinessInfo) {
    synchronized (browserAutoOpenStateLock) {
      if (!autoOpenedBrowser.compareAndSet(false, true)) {
        return false;
      }
      defaultStructuredAutoOpenedBrowser.set(
          LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(readinessInfo.uiRoot()));
      legacyFallbackAutoOpenedBrowser.set(false);
      return true;
    }
  }

  private boolean consumeLegacyFallbackPromotion(LauncherReadinessInfo readinessInfo) {
    synchronized (browserAutoOpenStateLock) {
      return !LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(readinessInfo.uiRoot())
          && legacyFallbackAutoOpenedBrowser.compareAndSet(true, false);
    }
  }

  private void resetStructuredAutoOpenState() {
    synchronized (browserAutoOpenStateLock) {
      defaultStructuredAutoOpenedBrowser.set(false);
      legacyFallbackAutoOpenedBrowser.set(false);
    }
  }

  private boolean tryWindowsGracefulStopViaAnchor(List<Long> pids) {
    Path anchorPath = resolveWindowsAnchorPath();
    if (anchorPath == null) {
      return false;
    }

    try {
      boolean deleted = Files.deleteIfExists(anchorPath);
      if (!deleted) {
        emitLog(
            ts()
                + " Anchor file not found or not deleted at "
                + anchorPath
                + "; skipping anchor stop.");
        return false;
      }
      emitLog(
          ts() + " Requested graceful shutdown via anchor: " + anchorPath.getFileName() + " ...");
      return waitForPidsToExit(pids, 25);
    } catch (Exception e) {
      emitLog(
          ts() + " WARN: Failed to delete anchor file at " + anchorPath + ": " + e.getMessage());
      logDebug("Failed to use wrapper.anchorfile for graceful stop", e);
      return false;
    }
  }

  private Path resolveWindowsAnchorPath() {
    Path conf = wrapperConfPath.get();
    if (conf != null && Files.isRegularFile(conf)) {
      String anchorSpec = readWrapperProperty(conf, "wrapper.anchorfile");
      String workingDir = readWrapperProperty(conf, "wrapper.working.dir");
      Path resolved = LauncherUtils.computeWrapperFilePath(conf, anchorSpec, workingDir);
      if (resolved != null) {
        return resolved;
      }
    }

    String localAppData = System.getenv("LOCALAPPDATA");
    if (localAppData != null && !localAppData.isBlank()) {
      return Path.of(localAppData).resolve("Cryptad.anchor").normalize();
    }
    return null;
  }

  private String readWrapperProperty(Path conf, String key) {
    try {
      for (String raw : Files.readAllLines(conf, StandardCharsets.UTF_8)) {
        String line = raw.trim();
        int idx = line.indexOf('=');
        boolean isCandidate = !line.isEmpty() && !line.startsWith("#") && idx > 0;
        if (isCandidate) {
          String foundKey = line.substring(0, idx).trim();
          if (foundKey.equals(key)) {
            return line.substring(idx + 1).trim();
          }
        }
      }
      return null;
    } catch (Exception e) {
      logDebug("Failed to read " + key + " from " + conf, e);
      return null;
    }
  }

  private void startTailingWrapperLogIfAvailable(Path logPath, long initialOffset) {
    interruptTailThread();
    if (logPath == null) {
      return;
    }
    Thread tailer =
        Thread.ofPlatform()
            .name("launcher-log-tail")
            .daemon(true)
            .unstarted(() -> tailFileWhileAlive(logPath, initialOffset, Thread.currentThread()));
    tailThread.set(tailer);
    tailer.start();
  }

  private void interruptTailThread() {
    Thread tailer = tailThread.getAndSet(null);
    if (tailer != null) {
      tailer.interrupt();
    }
  }

  private void finishTailThreadAfterProcessExit() {
    Thread tailer = tailThread.getAndSet(null);
    if (tailer == null) {
      return;
    }
    try {
      tailer.join(TAIL_MAX_DELAY_MS + TAIL_BASE_DELAY_MS);
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
    if (tailer.isAlive()) {
      tailer.interrupt();
    }
  }

  private void tailFileWhileAlive(Path path, long initialOffset, Thread tailingThread) {
    TailState tailState = new TailState();
    tailState.pos = initialOffset;
    try {
      while (!tailingThread.isInterrupted()) {
        boolean processAlive = isTrackedProcessAlive();
        try {
          boolean madeProgress = tailOnce(path, tailState);
          if (!processAlive && !madeProgress) {
            return;
          }
          tailState.idleCount = madeProgress ? 0 : tailState.idleCount + 1;
        } catch (Exception _) {
          resetTailOnError(tailState);
        }
        if (!processAlive) {
          continue;
        }
        if (!sleepWhileThreadActive(tailingThread, calcTailDelayMs(tailState.idleCount))) {
          return;
        }
      }
    } finally {
      closeTailFile(tailState);
    }
  }

  private boolean isTrackedProcessAlive() {
    Process tracked = process.get();
    return tracked != null && tracked.isAlive();
  }

  private boolean sleepWhileThreadActive(Thread worker, long delayMs) {
    long remaining = delayMs;
    while (remaining > 0) {
      if (worker.isInterrupted()) {
        return false;
      }
      long chunk = Math.min(remaining, TAIL_CANCEL_POLL_MS);
      try {
        Thread.sleep(chunk);
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        return false;
      }
      remaining -= chunk;
    }
    return !worker.isInterrupted();
  }

  private long calcTailDelayMs(int idleCount) {
    int shifts = Math.min(idleCount, 3);
    long delay = TAIL_BASE_DELAY_MS << shifts;
    return Math.min(delay, TAIL_MAX_DELAY_MS);
  }

  private void resetTailOnError(TailState state) {
    closeTailFile(state);
    state.currentKey = null;
    state.idleCount++;
  }

  private void closeTailFile(TailState state) {
    RandomAccessFile raf = state.raf;
    state.raf = null;
    if (raf != null) {
      try {
        raf.close();
      } catch (Exception _) {
        // Best-effort close.
      }
    }
  }

  private boolean tailOnce(Path path, TailState state) throws IOException {
    if (!Files.exists(path)) {
      closeTailFile(state);
      state.currentKey = null;
      return false;
    }

    Object newKey = readFileKey(path);
    openTailFileIfNeeded(path, newKey, state);
    RandomAccessFile handle = state.raf;
    if (handle == null) {
      return false;
    }

    long length = handle.length();
    if (length < state.pos) {
      state.pos = 0;
    }
    if (length <= state.pos) {
      return false;
    }

    handle.seek(state.pos);
    int toRead = (int) Math.min(length - state.pos, TAIL_READ_CHUNK);
    byte[] buffer = new byte[toRead];
    int read = handle.read(buffer);
    if (read <= 0) {
      return false;
    }

    state.pos += read;
    emitTailText(state, new String(buffer, 0, read, StandardCharsets.UTF_8));
    return true;
  }

  private Object readFileKey(Path path) {
    try {
      return Files.readAttributes(path, BasicFileAttributes.class).fileKey();
    } catch (Exception _) {
      return null;
    }
  }

  private void openTailFileIfNeeded(Path path, Object newKey, TailState state) throws IOException {
    if (state.raf == null
        || (state.currentKey != null && newKey != null && !state.currentKey.equals(newKey))) {
      closeTailFile(state);
      RandomAccessFile opened = new RandomAccessFile(path.toFile(), "r");
      state.raf = opened;
      state.currentKey = newKey;
      state.pos = Math.min(state.pos, opened.length());
    }
  }

  private void emitTailText(TailState state, String text) {
    String[] parts = text.split("\n", -1);
    if (parts.length == 1) {
      state.leftover.append(parts[0]);
      return;
    }

    String first = state.leftover.append(parts[0]).toString();
    if (!first.isEmpty()) {
      processStartupDiscoveryLine(first);
      emitLog(first);
    }
    state.leftover = new StringBuilder();

    for (int i = 1; i < parts.length - 1; i++) {
      processStartupDiscoveryLine(parts[i]);
      emitLog(parts[i]);
    }
    String last = parts[parts.length - 1];
    if (text.endsWith("\n")) {
      processStartupDiscoveryLine(last);
      emitLog(last);
    } else {
      state.leftover.append(last);
    }
  }

  private String formatCommandForLog(List<String> command) {
    boolean isWindows = new AppEnv().isWindows();
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < command.size(); i++) {
      if (i > 0) {
        out.append(' ');
      }
      out.append(formatCommandArgument(command.get(i), isWindows));
    }
    return out.toString();
  }

  private String formatCommandArgument(String arg, boolean isWindows) {
    if (isWindows) {
      if (arg.chars().anyMatch(ch -> Character.isWhitespace(ch) || ch == '"')) {
        return "\"" + arg.replace("\"", "\\\"") + "\"";
      }
      return arg;
    }

    if (arg.chars()
        .anyMatch(ch -> Character.isWhitespace(ch) || ch == '\'' || ch == '"' || ch == '\\')) {
      return LauncherUtils.shellQuote(arg);
    }
    return arg;
  }

  private static final class TailState {
    private RandomAccessFile raf;
    private Object currentKey;
    private long pos;
    private StringBuilder leftover = new StringBuilder();
    private int idleCount;
  }

  /**
   * Attempts to open the node web UI in the system browser using the known local port.
   *
   * <p>If no port is known or desktop browse integration is unavailable, the method returns without
   * throwing and may emit warning log lines.
   */
  public void launchBrowser() {
    AppState currentState = state.get();
    Integer port = currentState.knownPort();
    if (port == null) {
      return;
    }
    URI uri = buildBrowserUri(port, currentState.knownUiRoot());

    io.execute(
        () -> {
          try {
            if (!Desktop.isDesktopSupported()) {
              launchBrowserFallback(uri);
              return;
            }
            Desktop desktop = Desktop.getDesktop();
            if (desktop.isSupported(Desktop.Action.BROWSE)) {
              desktop.browse(uri);
            } else {
              launchBrowserFallback(uri);
            }
          } catch (Exception e) {
            emitLog(ts() + " ERROR: Failed to launch browser: " + e.getMessage());
            logDebug("Browser launch failure", e);
          }
        });
  }

  private void launchBrowserFallback(URI uri) throws IOException {
    AppEnv env = new AppEnv();
    if (env.isMac()) {
      new ProcessBuilder(MAC_OPEN_EXECUTABLE, uri.toString()).start();
      return;
    }
    if (env.isWindows()) {
      new ProcessBuilder(WINDOWS_RUNDLL32_EXECUTABLE, "url.dll,FileProtocolHandler", uri.toString())
          .start();
      return;
    }
    String xdgOpenExecutable =
        Files.isExecutable(Path.of(LINUX_XDG_OPEN_EXECUTABLE))
            ? LINUX_XDG_OPEN_EXECUTABLE
            : LINUX_XDG_OPEN_EXECUTABLE_FALLBACK;
    new ProcessBuilder(xdgOpenExecutable, uri.toString()).start();
  }

  static URI buildBrowserUri(int port, String uiRoot) {
    return URI.create("http://localhost:" + port + normalizeUiRoot(uiRoot));
  }

  static String describeBrowserTarget(Integer port, String uiRoot) {
    String normalizedUiRoot = normalizeUiRoot(uiRoot);
    if (port == null) {
      return "http://localhost:<port>" + normalizedUiRoot;
    }
    return buildBrowserUri(port, normalizedUiRoot).toString();
  }

  static String normalizeUiRoot(String uiRoot) {
    if (!LauncherReadinessInfo.isValidUiRoot(uiRoot)) {
      return LauncherReadinessInfo.DEFAULT_UI_ROOT;
    }
    return uiRoot.endsWith("/") ? uiRoot : uiRoot + "/";
  }

  /**
   * Initiates controller shutdown, process stop, and executor termination.
   *
   * <p>Subsequent start requests are ignored after shutdown begins.
   */
  public synchronized void shutdown() {
    if (state.get().isShuttingDown()) {
      return;
    }
    updateState(s -> s.withShuttingDown(true));
    io.execute(
        () -> {
          Process current = process.get();
          if (current != null && current.isAlive()) {
            stopManagedProcess(current);
          }
        });
  }

  /**
   * Initiates shutdown and waits for background executor termination.
   *
   * <p>The wait is bounded to ten seconds; timeout is logged at debug level.
   */
  public void shutdownAndWait() {
    if (!state.get().isShuttingDown()) {
      updateState(s -> s.withShuttingDown(true));
    }
    Process current = process.get();
    if (current != null && current.isAlive()) {
      stopManagedProcess(current);
    }
    interruptTailThread();
  }

  private void tryEnableConsoleFlush(Path cryptadPath) {
    try {
      Path conf = LauncherUtils.guessWrapperConfPathForCryptadScript(cryptadPath);
      if (conf == null || !Files.isRegularFile(conf)) {
        return;
      }
      List<String> lines = Files.readAllLines(conf, StandardCharsets.UTF_8);
      List<String> updated =
          LauncherUtils.upsertWrapperProperty(lines, "wrapper.console.flush", "TRUE");
      if (!updated.equals(lines)) {
        Files.write(conf, updated, StandardCharsets.UTF_8);
      }
    } catch (Exception e) {
      logDebug("Failed to update wrapper.console.flush in wrapper.conf", e);
    }
  }

  private void updateState(UnaryOperator<AppState> updater) {
    AppState newState = state.updateAndGet(updater);
    notifyStateListeners(newState);
  }

  private void notifyStateListeners(AppState newState) {
    for (Consumer<AppState> listener : stateListeners) {
      try {
        listener.accept(newState);
      } catch (Exception e) {
        logDebug("State listener failed", e);
      }
    }
  }

  private void emitLog(String line) {
    for (Consumer<String> listener : logListeners) {
      try {
        listener.accept(line);
      } catch (Exception e) {
        logDebug("Log listener failed", e);
      }
    }
  }

  private static String ts() {
    return java.time.LocalDateTime.now(java.time.ZoneId.systemDefault())
        .format(java.time.format.DateTimeFormatter.ISO_LOCAL_TIME);
  }
}
