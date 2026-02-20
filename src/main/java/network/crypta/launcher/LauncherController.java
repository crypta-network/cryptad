package network.crypta.launcher;

import java.awt.Desktop;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static network.crypta.launcher.LauncherLog.logDebug;

/**
 * Coordinates launcher process lifecycle and UI-facing state/log notifications.
 *
 * <p>This controller is the orchestration layer between the Swing launcher frame and the managed
 * {@code cryptad} process. It handles start/stop/shutdown transitions, tails process output,
 * extracts runtime metadata (such as detected browser port), and emits immutable state snapshots to
 * registered listeners. Long-running and blocking work executes on a dedicated single-thread
 * executor to keep UI interactions responsive while preserving operation ordering.
 *
 * <p>Notable behavior:
 *
 * <ul>
 *   <li>Serializes process lifecycle operations through a single worker thread.
 *   <li>Tracks shutdown intent to prevent restarts during the termination flow.
 *   <li>Publishes both structured state updates and raw log lines for view rendering.
 * </ul>
 */
public class LauncherController {
  private final ExecutorService io = Executors.newSingleThreadExecutor();
  private final Path cwd;
  private final List<Consumer<String>> logListeners = new CopyOnWriteArrayList<>();
  private final List<Consumer<AppState>> stateListeners = new CopyOnWriteArrayList<>();

  private Process process;
  private AppState state = new AppState();
  private volatile boolean shuttingDown;

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
    this.cwd = Objects.requireNonNull(cwd);
  }

  /**
   * Returns the latest immutable launcher state snapshot.
   *
   * @return current application state representing process and shutdown flags
   */
  public AppState getState() {
    return state;
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
      listener.accept(state);
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
    AppState currentState = state;
    if (shuttingDown) {
      return;
    }
    if (currentState.isRunning()) {
      return;
    }

    Path cryptadPath = LauncherUtils.resolveCryptadPath(cwd);
    if (!Files.isRegularFile(cryptadPath) || !Files.isExecutable(cryptadPath)) {
      emitLog(ts() + " ERROR: Cannot find executable 'cryptad' at " + cryptadPath);
      return;
    }

    setState(currentState.withStopping(false).withShuttingDown(false));
    emitLog(ts() + " Starting '" + cryptadPath.getFileName() + "' ...");

    io.execute(
        () -> {
          try {
            maybeEnableWrapperConsoleFlush(cryptadPath);
            List<String> command = LauncherUtils.buildCryptadCommand(cryptadPath);
            emitLog(
                ts()
                    + " exec: "
                    + String.join(" ", command)
                    + " (cwd="
                    + cwd.toAbsolutePath()
                    + ")");

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(cwd.toFile());
            pb.redirectErrorStream(true);
            Process started = pb.start();
            process = started;
            setState(state.withRunning(true).withStopping(false));

            try (var reader =
                new java.io.BufferedReader(
                    new java.io.InputStreamReader(
                        started.getInputStream(), StandardCharsets.UTF_8))) {
              String line;
              while ((line = reader.readLine()) != null) {
                emitLog(line);
                Integer parsedPort = LauncherUtils.parseFProxyPortFromLine(line);
                if (parsedPort != null) {
                  setState(state.withKnownPort(parsedPort));
                }
              }
            }

            started.waitFor();
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logDebug("Launcher process start/watch failed", e);
            emitLog(ts() + " ERROR: " + e.getMessage());
          } catch (Exception e) {
            logDebug("Launcher process start/watch failed", e);
            emitLog(ts() + " ERROR: " + e.getMessage());
          } finally {
            process = null;
            setState(state.withRunning(false).withStopping(false));
          }
        });
  }

  /**
   * Requests graceful process termination and escalates to forced termination when needed.
   *
   * <p>If no process is active, the state is normalized to non-running immediately.
   */
  public synchronized void stop() {
    Process current = process;
    if (current == null) {
      setState(state.withRunning(false).withStopping(false));
      return;
    }

    setState(state.withStopping(true));
    io.execute(
        () -> {
          try {
            current.destroy();
            if (!current.waitFor(5, TimeUnit.SECONDS)) {
              current.destroyForcibly();
            }
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
          } finally {
            setState(state.withRunning(false).withStopping(false));
          }
        });
  }

  /**
   * Attempts to open the node web UI in the system browser using the known local port.
   *
   * <p>If no port is known or desktop browse integration is unavailable, the method returns without
   * throwing and may emit warning log lines.
   */
  public void launchBrowser() {
    Integer port = state.knownPort();
    if (port == null) {
      return;
    }

    io.execute(
        () -> {
          try {
            if (!Desktop.isDesktopSupported()) {
              emitLog(ts() + " WARN: Desktop integration is not available");
              return;
            }
            Desktop desktop = Desktop.getDesktop();
            if (!desktop.isSupported(Desktop.Action.BROWSE)) {
              emitLog(ts() + " WARN: Desktop browser action is not available");
              return;
            }
            desktop.browse(URI.create("http://localhost:" + port + "/"));
          } catch (Exception e) {
            emitLog(ts() + " WARN: Failed to open browser: " + e.getMessage());
            logDebug("Browser launch failure", e);
          }
        });
  }

  /**
   * Initiates controller shutdown, process stop, and executor termination.
   *
   * <p>Subsequent start requests are ignored after shutdown begins.
   */
  public synchronized void shutdown() {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    setState(state.withShuttingDown(true));
    stop();
    io.shutdown();
  }

  /**
   * Initiates shutdown and waits for background executor termination.
   *
   * <p>The wait is bounded to ten seconds; timeout is logged at debug level.
   */
  public void shutdownAndWait() {
    shutdown();
    try {
      boolean terminated = io.awaitTermination(10, TimeUnit.SECONDS);
      if (!terminated) {
        logDebug("Timed out waiting for launcher IO executor to terminate");
      }
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    }
  }

  private void maybeEnableWrapperConsoleFlush(Path cryptadPath) {
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

  private void setState(AppState newState) {
    state = newState;
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
    return java.time.LocalTime.now().toString();
  }
}
