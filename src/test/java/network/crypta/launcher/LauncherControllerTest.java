package network.crypta.launcher;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100"})
@ExtendWith(MockitoExtension.class)
class LauncherControllerTest {
  private static final int TEST_PORT = 8888;

  @TempDir Path tempDir;

  @Test
  void start_whenCryptadMissing_logsErrorAndDoesNotRun() {
    LauncherController controller = new LauncherController(tempDir);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    controller.start();

    String line = awaitLog(logs, l -> l.contains("Cannot find executable 'cryptad'"));
    assertTrue(line.contains("ERROR: Cannot find executable 'cryptad'"));
    assertFalse(controller.getState().isRunning());
    controller.shutdownAndWait();
  }

  @Test
  void start_whenScriptRuns_updatesStateAndReadsPort() throws Exception {
    LauncherController controller = new LauncherController(tempDir);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    Path wrapperConf = writeWrapperConf(tempDir);
    writeCryptadScript(tempDir);

    controller.start();

    awaitState(controller, AppState::isRunning);
    AppState stateWithPort =
        awaitState(controller, s -> s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(TEST_PORT, stateWithPort.knownPort());

    AppState stopped =
        awaitState(
            controller, s -> !s.isRunning() && s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertFalse(stopped.isRunning());

    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    assertTrue(logs.stream().anyMatch(l -> l.contains("Starting 'cryptad'")));
    assertTrue(logs.stream().anyMatch(l -> l.contains("exec:")));

    var confLines = Files.readAllLines(wrapperConf, StandardCharsets.UTF_8);
    assertTrue(confLines.stream().anyMatch(l -> l.trim().equals("wrapper.console.flush=TRUE")));

    controller.shutdownAndWait();
  }

  @Test
  void stop_whenProcessNotAlive_clearsRunningState() throws Exception {
    LauncherController controller = new LauncherController(tempDir);

    Process process = mock(Process.class);
    when(process.waitFor(anyLong(), any(TimeUnit.class))).thenReturn(true);
    setPrivateField(controller, "process", process);
    setPrivateField(controller, "state", new AppState(true, null, false, false));

    controller.stop();

    AppState state = awaitState(controller, s -> !s.isRunning() && !s.isStopping());
    assertFalse(state.isRunning());
    assertFalse(state.isStopping());

    controller.shutdownAndWait();
  }

  @Test
  void launchBrowser_whenPortMissing_noop() throws Exception {
    LauncherController controller = new LauncherController(tempDir);
    AppState initial = new AppState(false, null, false, false);
    setPrivateField(controller, "state", initial);

    controller.launchBrowser();

    assertEquals(initial, controller.getState());
    controller.shutdownAndWait();
  }

  @Test
  void shutdown_setsShuttingDownFlagAndIsIdempotent() {
    LauncherController controller = new LauncherController(tempDir);

    controller.shutdown();
    assertTrue(controller.getState().isShuttingDown());

    controller.shutdown();
    assertTrue(controller.getState().isShuttingDown());

    controller.shutdownAndWait();
  }

  @Test
  void shutdownAndWait_whenNoProcess_setsShuttingDownFlag() {
    LauncherController controller = new LauncherController(tempDir);

    controller.shutdownAndWait();

    assertTrue(controller.getState().isShuttingDown());
  }

  private static String awaitLog(
      CopyOnWriteArrayList<String> lines, java.util.function.Predicate<String> predicate) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      for (String line : lines) {
        if (predicate.test(line)) {
          return line;
        }
      }
      sleepShort();
    }
    throw new AssertionError("Timed out waiting for expected launcher log line");
  }

  private static AppState awaitState(
      LauncherController controller, java.util.function.Predicate<AppState> predicate) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      AppState state = controller.getState();
      if (predicate.test(state)) {
        return state;
      }
      sleepShort();
    }
    throw new AssertionError("Timed out waiting for launcher state");
  }

  private static void sleepShort() {
    LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(10));
    if (Thread.currentThread().isInterrupted()) {
      Thread.currentThread().interrupt();
      throw new AssertionError("Interrupted while waiting");
    }
  }

  private static void setPrivateField(Object target, String fieldName, Object value)
      throws Exception {
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static void writeCryptadScript(Path baseDir) throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "echo READY",
              "ping -n 2 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "echo \"READY\"",
              "sleep 0.2");
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static Path writeWrapperConf(Path baseDir) throws Exception {
    Path confDir = baseDir.resolve("conf");
    Path logsDir = baseDir.resolve("logs");
    Files.createDirectories(confDir);
    Files.createDirectories(logsDir);
    Path conf = confDir.resolve("wrapper.conf");
    Files.write(
        conf,
        java.util.List.of("# wrapper.conf", "wrapper.logfile=../logs/wrapper.log"),
        StandardCharsets.UTF_8);
    Files.writeString(logsDir.resolve("wrapper.log"), "", StandardCharsets.UTF_8);
    return conf;
  }
}
