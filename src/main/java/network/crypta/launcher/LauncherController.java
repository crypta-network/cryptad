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
 * Lightweight Java launcher controller.
 *
 * <p>Owns daemon process lifecycle and emits state/log updates to listeners used by the Swing UI.
 */
public class LauncherController {
  private final ExecutorService io = Executors.newSingleThreadExecutor();
  private final Path cwd;
  private final List<Consumer<String>> logListeners = new CopyOnWriteArrayList<>();
  private final List<Consumer<AppState>> stateListeners = new CopyOnWriteArrayList<>();

  private volatile Process process;
  private volatile AppState state = new AppState();
  private volatile boolean shuttingDown;

  public LauncherController() {
    this(Path.of(System.getProperty("user.dir")));
  }

  public LauncherController(Path cwd) {
    this.cwd = Objects.requireNonNull(cwd);
  }

  public AppState getState() {
    return state;
  }

  public void addLogListener(Consumer<String> listener) {
    if (listener != null) {
      logListeners.add(listener);
    }
  }

  public void removeLogListener(Consumer<String> listener) {
    logListeners.remove(listener);
  }

  public void addStateListener(Consumer<AppState> listener) {
    if (listener != null) {
      stateListeners.add(listener);
      listener.accept(state);
    }
  }

  public void removeStateListener(Consumer<AppState> listener) {
    stateListeners.remove(listener);
  }

  public synchronized void start() {
    if (shuttingDown) {
      return;
    }
    if (state.isRunning()) {
      return;
    }

    Path cryptadPath = LauncherUtils.resolveCryptadPath(cwd);
    if (!Files.isRegularFile(cryptadPath) || !Files.isExecutable(cryptadPath)) {
      emitLog(ts() + " ERROR: Cannot find executable 'cryptad' at " + cryptadPath);
      return;
    }

    setState(state.withStopping(false).withShuttingDown(false));
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
          } catch (Exception e) {
            logDebug("Launcher process start/watch failed", e);
            emitLog(ts() + " ERROR: " + e.getMessage());
          } finally {
            process = null;
            setState(state.withRunning(false).withStopping(false));
          }
        });
  }

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
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          } finally {
            setState(state.withRunning(false).withStopping(false));
          }
        });
  }

  public void launchBrowser() {
    Integer port = state.getKnownPort();
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

  public synchronized void shutdown() {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    setState(state.withShuttingDown(true));
    stop();
    io.shutdown();
  }

  public void shutdownAndWait() {
    shutdown();
    try {
      io.awaitTermination(10, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
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
