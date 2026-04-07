package network.crypta.launcher;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Supplier;
import network.crypta.fs.AppEnv;
import network.crypta.fs.readiness.LauncherReadinessFiles;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100"})
@ExtendWith(MockitoExtension.class)
class LauncherControllerTest {
  private static final long POST_STARTUP_SETTLE_MS = 100L;
  private static final Duration HEARTBEAT_STABLE_FOR = Duration.ofMillis(500);
  private static final String SHELL_SLEEP_SHORT = "0.05";
  private static final String SHELL_SLEEP_MEDIUM = "0.10";
  private static final String SHELL_SLEEP_LONG = "0.20";
  private static final String SHELL_SLEEP_LOOP = "0.05";
  private static final LauncherController.TimingConfig TEST_TIMING =
      new LauncherController.TimingConfig(
          50L,
          300L,
          10L,
          25L,
          Duration.ofMillis(300),
          Duration.ofMillis(300),
          Duration.ofMillis(100),
          Duration.ofMillis(50));
  private static final int TEST_PORT = 8888;
  private static final String SHELL_UI_ROOT = "/app/node/";

  @TempDir Path tempDir;

  private LauncherController controller() {
    return controller(LauncherUtils::resolveConfiguredLauncherReadinessFile);
  }

  private LauncherController controller(Supplier<Path> readinessFileResolver) {
    return controller(readinessFileResolver, LauncherUtils::resolveConfiguredLauncherDaemonLogFile);
  }

  private LauncherController controller(
      Supplier<Path> readinessFileResolver, Supplier<Path> daemonLogFileResolver) {
    return new LauncherController(
        tempDir, readinessFileResolver, daemonLogFileResolver, TEST_TIMING);
  }

  @Test
  void start_whenCryptadMissing_logsErrorAndDoesNotRun() {
    LauncherController controller = controller();
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
    Path initialReadinessFile = createReadinessFilePath(tempDir, "default-runtime");
    Path actualReadinessFile = createReadinessFilePath(tempDir, "configured-runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    Path legacyDetectedMarker = tempDir.resolve("legacy-detected.marker");
    LauncherController controller = controller(() -> initialReadinessFile, () -> daemonLogFile);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    Path wrapperConf = writeWrapperConf(tempDir);
    writeStructuredReadinessCryptadScript(
        tempDir, actualReadinessFile, daemonLogFile, legacyDetectedMarker);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    awaitCondition(
        () -> Files.exists(legacyDetectedMarker),
        "legacy FProxy marker before structured readiness");
    assertFalse(isBrowserAutoOpened(controller));
    assertNull(controller.getState().knownPort());
    assertFalse(isBrowserAutoOpened(controller));
    awaitCondition(() -> Files.exists(actualReadinessFile), "structured readiness file");
    AppState stateWithPort =
        awaitState(controller, s -> s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(TEST_PORT, stateWithPort.knownPort());
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, stateWithPort.knownUiRoot());
    awaitCondition(() -> isBrowserAutoOpened(controller), "browser auto-open after readiness");
    assertTrue(isBrowserAutoOpened(controller));

    AppState stopped =
        awaitState(
            controller, s -> !s.isRunning() && s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertFalse(stopped.isRunning());

    awaitLog(logs, l -> l.contains("READY"));
    assertFalse(logs.stream().anyMatch(l -> l.contains("Run dir:")));
    assertTrue(logs.stream().anyMatch(l -> l.contains("Starting 'cryptad")));
    assertTrue(logs.stream().anyMatch(l -> l.contains("exec:")));

    var confLines = Files.readAllLines(wrapperConf, StandardCharsets.UTF_8);
    assertTrue(confLines.stream().anyMatch(l -> l.trim().equals("wrapper.console.flush=TRUE")));

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessUsesShellRoot_tracksAndUsesNonDefaultUiRoot() throws Exception {
    Path initialReadinessFile = createReadinessFilePath(tempDir, "default-runtime");
    Path actualReadinessFile = createReadinessFilePath(tempDir, "configured-runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    Path legacyDetectedMarker = tempDir.resolve("legacy-detected.marker");
    LauncherController controller = controller(() -> initialReadinessFile, () -> daemonLogFile);

    writeWrapperConf(tempDir);
    writeStructuredReadinessCryptadScript(
        tempDir, actualReadinessFile, daemonLogFile, legacyDetectedMarker, "/app/node/");

    controller.start();

    awaitState(controller, AppState::isRunning);
    AppState stateWithShellRoot =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && "/app/node/".equals(s.knownUiRoot()));
    assertEquals(
        "http://localhost:8888/app/node/",
        LauncherController.buildBrowserUri(TEST_PORT, stateWithShellRoot.knownUiRoot()).toString());
    awaitCondition(
        () -> isBrowserAutoOpened(controller), "browser auto-open after shell readiness");
    assertTrue(isBrowserAutoOpened(controller));

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessUsesShellRoot_autoOpensShellRouteOnce() throws Exception {
    Path initialReadinessFile = createReadinessFilePath(tempDir, "default-runtime");
    Path actualReadinessFile = createReadinessFilePath(tempDir, "configured-runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    Path legacyDetectedMarker = tempDir.resolve("legacy-detected.marker");
    RecordingLauncherController controller =
        new RecordingLauncherController(tempDir, () -> initialReadinessFile, () -> daemonLogFile);

    writeWrapperConf(tempDir);
    writeStructuredReadinessCryptadScript(
        tempDir, actualReadinessFile, daemonLogFile, legacyDetectedMarker, "/app/node/");

    controller.start();

    awaitState(
        controller,
        s ->
            s.knownPort() != null
                && s.knownPort() == TEST_PORT
                && "/app/node/".equals(s.knownUiRoot()));
    awaitCondition(
        () -> controller.launchedUris().size() == 1,
        "single browser auto-open for structured shell readiness");

    assertEquals(List.of(URI.create("http://localhost:8888/app/node/")), controller.launchedUris());
    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessPromotesFromDefaultRootToShellRoot_updatesUiRootToShellRoot()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherController controller = controller(() -> readinessFile, () -> null);

    writeWrapperConf(tempDir);
    writeStructuredReadinessPromotionCryptadScript(
        tempDir, readinessFile, LauncherReadinessInfo.DEFAULT_UI_ROOT, "/app/node/");

    controller.start();

    awaitState(controller, AppState::isRunning);
    AppState defaultRootState =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(s.knownUiRoot()));
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, defaultRootState.knownUiRoot());

    AppState shellRootState =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && "/app/node/".equals(s.knownUiRoot()));
    assertEquals(
        "http://localhost:8888/app/node/",
        LauncherController.buildBrowserUri(TEST_PORT, shellRootState.knownUiRoot()).toString());

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessPromotesFromDefaultRootToShellRoot_reopensBrowserAtShellRoot()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    RecordingLauncherController controller =
        new RecordingLauncherController(tempDir, () -> readinessFile, () -> null);

    writeWrapperConf(tempDir);
    writeStructuredReadinessPromotionCryptadScript(
        tempDir, readinessFile, LauncherReadinessInfo.DEFAULT_UI_ROOT, "/app/node/");

    controller.start();

    awaitState(
        controller,
        s ->
            s.knownPort() != null
                && s.knownPort() == TEST_PORT
                && "/app/node/".equals(s.knownUiRoot()));
    awaitCondition(
        () -> controller.launchedUris().size() == 2,
        "browser relaunch after structured readiness promotes to shell root");

    assertEquals(
        List.of(
            URI.create("http://localhost:8888/"), URI.create("http://localhost:8888/app/node/")),
        controller.launchedUris());
    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessDemotesFromShellRootToDefaultRoot_updatesUiRootToDefaultRoot()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    RecordingLauncherController controller =
        new RecordingLauncherController(tempDir, () -> readinessFile, () -> null);

    writeWrapperConf(tempDir);
    writeStructuredReadinessPromotionCryptadScript(
        tempDir, readinessFile, "/app/node/", LauncherReadinessInfo.DEFAULT_UI_ROOT);

    controller.start();

    awaitState(
        controller,
        s ->
            s.knownPort() != null
                && s.knownPort() == TEST_PORT
                && "/app/node/".equals(s.knownUiRoot()));
    AppState defaultRootState =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(s.knownUiRoot()));

    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, defaultRootState.knownUiRoot());
    awaitCondition(
        () -> controller.launchedUris().size() == 1,
        "single browser auto-open after structured readiness demotes to the legacy root");
    assertEquals(List.of(URI.create("http://localhost:8888/app/node/")), controller.launchedUris());
    controller.shutdownAndWait();
  }

  @Test
  void start_whenPreexistingReadinessExists_preservesItWhileIgnoringIt() throws Exception {
    Path initialReadinessFile = createReadinessFilePath(tempDir, "default-runtime");
    Path actualReadinessFile = createReadinessFilePath(tempDir, "configured-runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    LauncherReadinessInfo existingReadiness =
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, 4321, "/");
    LauncherReadinessFiles.write(actualReadinessFile, existingReadiness);
    LauncherController controller = controller(() -> initialReadinessFile, () -> daemonLogFile);

    writeWrapperConf(tempDir);
    writeNoReadinessCryptadScript(tempDir, parentOrThrow(actualReadinessFile), daemonLogFile);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitCondition(() -> Files.exists(actualReadinessFile), "pre-existing readiness preservation");
    assertEquals(existingReadiness, LauncherReadinessFiles.read(actualReadinessFile).orElseThrow());
    assertNull(controller.getState().knownPort());

    AppState stopped = awaitState(controller, s -> !s.isRunning());
    assertFalse(stopped.isRunning());
    assertNull(stopped.knownPort());
    assertEquals(existingReadiness, LauncherReadinessFiles.read(actualReadinessFile).orElseThrow());

    controller.shutdownAndWait();
  }

  @Test
  void stop_whenNoTrackedProcess_noop() throws Exception {
    LauncherController controller = controller();
    AppState initial = new AppState(true, null, false, false);
    setPrivateStateField(controller, initial);

    controller.stop();

    assertEquals(initial, controller.getState());

    controller.shutdownAndWait();
  }

  @Test
  void launchBrowser_whenPortMissing_noop() throws Exception {
    LauncherController controller = controller();
    AppState initial = new AppState(false, null, false, false);
    setPrivateStateField(controller, initial);

    controller.launchBrowser();

    assertEquals(initial, controller.getState());
    controller.shutdownAndWait();
  }

  @Test
  void launchBrowser_whenRunningWithoutDetectedPort_noop() throws Exception {
    LauncherController controller = controller();
    AppState initial = new AppState(true, null, false, false);
    setPrivateStateField(controller, initial);

    controller.launchBrowser();

    assertEquals(initial, controller.getState());
    controller.shutdownAndWait();
  }

  @Test
  void stop_whenScriptRunsLong_processStopsAndStateClears() throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherController controller = controller(() -> readinessFile);

    writeWrapperConf(tempDir);
    Path heartbeat = tempDir.resolve("heartbeat.log");
    writeLongRunningCryptadScript(tempDir, heartbeat);

    controller.start();
    awaitState(controller, AppState::isRunning);
    awaitHeartbeat(heartbeat);

    controller.stop();

    AppState stopped = awaitState(controller, s -> !s.isRunning() && !s.isStopping());
    assertFalse(stopped.isRunning());
    assertFalse(stopped.isStopping());
    awaitFileSizeStable(heartbeat, HEARTBEAT_STABLE_FOR);

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessUnavailable_fallsBackToLegacyLogPortDetection()
      throws Exception {
    LauncherController controller = controller(() -> null, () -> null);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    writeWrapperConf(tempDir);
    writeLegacyPortCryptadScript(tempDir);

    controller.start();

    awaitState(controller, AppState::isRunning);
    AppState stateWithPort =
        awaitState(controller, s -> s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(TEST_PORT, stateWithPort.knownPort());
    awaitCondition(() -> isBrowserAutoOpened(controller), "legacy fallback browser auto-open");
    assertTrue(isBrowserAutoOpened(controller));
    awaitLog(logs, l -> l.contains("Starting FProxy on"));

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessNeverPublishedAfterStartupCompletion_fallsBackToLegacyPort()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    LauncherController controller = controller(() -> readinessFile, () -> daemonLogFile);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    writeWrapperConf(tempDir);
    writeLegacyPortWithoutReadinessCryptadScript(tempDir, daemonLogFile);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    AppState stateWithPort =
        awaitState(controller, s -> s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(TEST_PORT, stateWithPort.knownPort());
    awaitCondition(
        () -> isBrowserAutoOpened(controller),
        "legacy fallback browser auto-open after startup completion");
    assertTrue(isBrowserAutoOpened(controller));

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessPublishedMalformedAfterStartupCompletion_fallsBackToLegacyPort()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    LauncherController controller = controller(() -> readinessFile, () -> daemonLogFile);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    writeWrapperConf(tempDir);
    writeLegacyPortWithMalformedReadinessCryptadScript(tempDir, readinessFile, daemonLogFile);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    awaitCondition(() -> Files.exists(readinessFile), "malformed structured readiness file");
    AppState stateWithPort =
        awaitState(controller, s -> s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(TEST_PORT, stateWithPort.knownPort());
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, stateWithPort.knownUiRoot());
    awaitCondition(
        () -> isBrowserAutoOpened(controller),
        "legacy fallback browser auto-open after malformed readiness");
    assertTrue(isBrowserAutoOpened(controller));
    assertFalse(LauncherReadinessFiles.read(readinessFile).isPresent());

    controller.shutdownAndWait();
  }

  @Test
  void start_whenFallbackRunDirContainsPreexistingReadiness_ignoresStaleStructuredUiRoot()
      throws Exception {
    Path initialReadinessFile = createReadinessFilePath(tempDir, "default-runtime");
    Path actualReadinessFile = createReadinessFilePath(tempDir, "configured-runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    RecordingLauncherController controller =
        new RecordingLauncherController(tempDir, () -> initialReadinessFile, () -> daemonLogFile);
    LauncherReadinessInfo staleReadiness =
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1,
            LauncherReadinessInfo.READY_STATE,
            TEST_PORT,
            "/app/node/");
    LauncherReadinessFiles.write(actualReadinessFile, staleReadiness);

    writeWrapperConf(tempDir);
    writeLegacyPortWithoutReadinessButWithRunDirCryptadScript(
        tempDir, parentOrThrow(actualReadinessFile), daemonLogFile);

    controller.start();

    awaitState(controller, AppState::isRunning);
    AppState fallbackState =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(s.knownUiRoot()));
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, fallbackState.knownUiRoot());
    awaitCondition(
        () -> controller.launchedUris().size() == 1,
        "single browser auto-open for legacy fallback");

    AppState stopped =
        awaitState(
            controller, s -> !s.isRunning() && s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, stopped.knownUiRoot());
    assertEquals(List.of(URI.create("http://localhost:8888/")), controller.launchedUris());
    assertEquals(staleReadiness, LauncherReadinessFiles.read(actualReadinessFile).orElseThrow());

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessArrivesAfterLegacyFallback_updatesUiRootToShellRoot()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    LauncherController controller = controller(() -> readinessFile, () -> daemonLogFile);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    writeWrapperConf(tempDir);
    writeLegacyFallbackThenStructuredReadinessCryptadScript(tempDir, readinessFile, daemonLogFile);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    AppState fallbackState =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(s.knownUiRoot()));
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, fallbackState.knownUiRoot());

    AppState stateWithShellRoot =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && "/app/node/".equals(s.knownUiRoot()));
    assertEquals(
        "http://localhost:8888/app/node/",
        LauncherController.buildBrowserUri(TEST_PORT, stateWithShellRoot.knownUiRoot()).toString());

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessArrivesAfterLegacyFallback_reopensBrowserAtShellRoot()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    Path daemonLogFile = createDaemonLogFilePath(tempDir);
    RecordingLauncherController controller =
        new RecordingLauncherController(tempDir, () -> readinessFile, () -> daemonLogFile);

    writeWrapperConf(tempDir);
    writeLegacyFallbackThenStructuredReadinessCryptadScript(tempDir, readinessFile, daemonLogFile);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitState(
        controller,
        s ->
            s.knownPort() != null
                && s.knownPort() == TEST_PORT
                && "/app/node/".equals(s.knownUiRoot()));
    awaitCondition(
        () -> controller.launchedUris().size() == 2,
        "browser relaunch after structured readiness replaces fallback");

    assertEquals(
        List.of(
            URI.create("http://localhost:8888/"), URI.create("http://localhost:8888/app/node/")),
        controller.launchedUris());
    controller.shutdownAndWait();
  }

  @Test
  void start_whenTransientReadinessReadFailsAfterShellRoot_recoversSameSnapshot() throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    FlakyReadinessLauncherController controller =
        new FlakyReadinessLauncherController(tempDir, () -> readinessFile, () -> null);

    writeWrapperConf(tempDir);
    writeStableStructuredReadinessCryptadScript(tempDir, readinessFile);

    controller.start();

    awaitState(
        controller,
        s ->
            s.knownPort() != null
                && s.knownPort() == TEST_PORT
                && "/app/node/".equals(s.knownUiRoot()));

    controller.failNextRead();
    awaitCondition(controller::failureInjected, "transient readiness read failure");

    AppState fallbackState =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && LauncherReadinessInfo.DEFAULT_UI_ROOT.equals(s.knownUiRoot()));
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, fallbackState.knownUiRoot());

    controller.allowRecovery();

    AppState recoveredState =
        awaitState(
            controller,
            s ->
                s.knownPort() != null
                    && s.knownPort() == TEST_PORT
                    && "/app/node/".equals(s.knownUiRoot()));
    assertEquals("/app/node/", recoveredState.knownUiRoot());
    awaitCondition(
        () -> controller.launchedUris().size() == 1,
        "single browser auto-open after transient readiness read failure");
    assertEquals(List.of(URI.create("http://localhost:8888/app/node/")), controller.launchedUris());

    controller.shutdownAndWait();
  }

  @Test
  void start_whenCompletionInfoLogUnavailable_stdoutCompletionFallsBackToLegacyPort()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherController controller = controller(() -> readinessFile, () -> null);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    writeWrapperConf(tempDir);
    writeLegacyPortWithStdoutCompletionCryptadScript(tempDir);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    AppState stateWithPort =
        awaitState(controller, s -> s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(TEST_PORT, stateWithPort.knownPort());
    awaitCondition(
        () -> isBrowserAutoOpened(controller),
        "legacy fallback browser auto-open after stdout completion");
    assertTrue(isBrowserAutoOpened(controller));

    controller.shutdownAndWait();
  }

  @Test
  void start_whenDaemonLogDiscoveryUnavailable_wrapperLogCompletionFallsBackToLegacyPort()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    Path wrongDaemonLogFile = tempDir.resolve("missing-logs").resolve("crypta-latest.log");
    Path wrapperLogFile = tempDir.resolve("logs").resolve("wrapper.log");
    LauncherController controller = controller(() -> readinessFile, () -> wrongDaemonLogFile);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    writeWrapperConf(tempDir);
    writeLegacyPortWithWrapperLogCompletionCryptadScript(tempDir, wrapperLogFile);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    AppState stateWithPort =
        awaitState(controller, s -> s.knownPort() != null && s.knownPort() == TEST_PORT);
    assertEquals(TEST_PORT, stateWithPort.knownPort());
    awaitCondition(
        () -> isBrowserAutoOpened(controller),
        "legacy fallback browser auto-open after wrapper-log completion");
    assertTrue(isBrowserAutoOpened(controller));

    controller.shutdownAndWait();
  }

  @Test
  void start_whenStructuredReadinessPending_doesNotExposeLegacyPortOrAutoOpen() throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    Path heartbeat = tempDir.resolve("heartbeat.log");
    LauncherController controller = controller(() -> readinessFile);
    CopyOnWriteArrayList<String> logs = new CopyOnWriteArrayList<>();
    controller.addLogListener(logs::add);

    writeWrapperConf(tempDir);
    writeLongRunningCryptadScript(tempDir, heartbeat);

    controller.start();

    awaitState(controller, AppState::isRunning);
    awaitLog(logs, l -> l.contains("Starting FProxy on"));
    awaitHeartbeat(heartbeat);
    sleepMillis(POST_STARTUP_SETTLE_MS);
    assertNull(controller.getState().knownPort());
    assertFalse(isBrowserAutoOpened(controller));

    controller.stop();

    AppState stopped = awaitState(controller, s -> !s.isRunning() && !s.isStopping());
    assertFalse(stopped.isRunning());
    assertNull(stopped.knownPort());

    controller.shutdownAndWait();
  }

  @Test
  void isCurrentLaunchReadinessFile_whenMtimeEqualsLaunchStartAndNoLegacyPortEvidence_returnsFalse()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, TEST_PORT, "/"));
    long launchStartedAtMillis = 17_000L;
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(launchStartedAtMillis));

    LauncherController controller = controller(() -> readinessFile);
    setLaunchStartedAtMillis(controller, launchStartedAtMillis);

    assertFalse(controller.isCurrentLaunchReadinessFile(readinessFile));

    controller.shutdownAndWait();
  }

  @Test
  void isCurrentLaunchReadinessFile_whenMtimeEqualsLaunchStartAndLegacyPortMatches_returnsTrue()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherController controller = controller(() -> readinessFile);
    setLaunchStartedAtMillis(controller, 17_000L);
    setPendingLegacyPort(controller);
    setTrackedReadinessTarget(controller, readinessFile);
    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, TEST_PORT, "/"));
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(17_000L));

    assertTrue(controller.isCurrentLaunchReadinessFile(readinessFile));

    controller.shutdownAndWait();
  }

  @Test
  void isCurrentLaunchReadinessFile_whenFileChangesAfterTrackingButMtimeRoundsDown_returnsTrue()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherController controller = controller(() -> readinessFile);
    setLaunchStartedAtMillis(controller, 17_000L);
    setTrackedReadinessTarget(controller, readinessFile);
    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, TEST_PORT, "/"));
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(16_000L));

    assertTrue(controller.isCurrentLaunchReadinessFile(readinessFile));

    controller.shutdownAndWait();
  }

  @Test
  void canConsumeCurrentLaunchReadiness_whenFileIsReplacedAfterRead_usesReadGeneration()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, 4321, "/"));
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(16_000L));

    LauncherController controller = controller(() -> readinessFile);
    setLaunchStartedAtMillis(controller, 17_000L);
    setTrackedReadinessTarget(controller, readinessFile);
    var staleSnapshot = LauncherReadinessFiles.readSnapshot(readinessFile).orElseThrow();

    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, TEST_PORT, "/"));
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(18_000L));

    assertFalse(invokeCanConsumeCurrentLaunchReadiness(controller, staleSnapshot));

    controller.shutdownAndWait();
  }

  @Test
  void isCurrentLaunchReadinessFile_whenTrackedAfterCurrentFileWriteAndMtimeRoundsDown_returnsTrue()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, TEST_PORT, "/"));
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(16_000L));

    LauncherController controller = controller(() -> readinessFile);
    setLaunchStartedAtMillis(controller, 17_000L);
    setPendingLegacyPort(controller);
    markStartupCompletionObserved(controller);
    setTrackedReadinessTarget(controller, readinessFile, true);

    assertTrue(controller.isCurrentLaunchReadinessFile(readinessFile));

    controller.shutdownAndWait();
  }

  @Test
  void isCurrentLaunchReadinessFile_whenFileIsCreatedAfterTrackingButMtimeRoundsDown_returnsTrue()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    Files.deleteIfExists(readinessFile);

    LauncherController controller = controller(() -> readinessFile);
    setLaunchStartedAtMillis(controller, 17_001L);
    setTrackedReadinessTarget(controller, readinessFile);
    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, TEST_PORT, "/"));
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(17_000L));

    assertTrue(controller.isCurrentLaunchReadinessFile(readinessFile));

    controller.shutdownAndWait();
  }

  @Test
  void isCurrentLaunchReadinessFile_whenTrackedFilePreexistsAndLegacyPortMatches_returnsFalse()
      throws Exception {
    Path readinessFile = createReadinessFilePath(tempDir, "runtime");
    LauncherReadinessFiles.write(
        readinessFile,
        new LauncherReadinessInfo(
            LauncherReadinessInfo.VERSION_1, LauncherReadinessInfo.READY_STATE, TEST_PORT, "/"));
    Files.setLastModifiedTime(readinessFile, FileTime.fromMillis(17_000L));

    LauncherController controller = controller(() -> readinessFile);
    setLaunchStartedAtMillis(controller, 17_000L);
    setPendingLegacyPort(controller);
    setTrackedReadinessTarget(controller, readinessFile);

    assertFalse(controller.isCurrentLaunchReadinessFile(readinessFile));

    controller.shutdownAndWait();
  }

  @Test
  void shutdown_setsShuttingDownFlagAndIsIdempotent() {
    LauncherController controller = controller();

    controller.shutdown();
    assertTrue(controller.getState().isShuttingDown());

    controller.shutdown();
    assertTrue(controller.getState().isShuttingDown());

    controller.shutdownAndWait();
  }

  @Test
  void shutdownAndWait_whenNoProcess_setsShuttingDownFlag() {
    LauncherController controller = controller();

    controller.shutdownAndWait();

    assertTrue(controller.getState().isShuttingDown());
  }

  @Test
  void buildBrowserUri_whenUiRootMissing_expectDefaultRootUsed() {
    assertEquals(
        "http://localhost:8888/", LauncherController.buildBrowserUri(TEST_PORT, null).toString());
    assertEquals(
        "http://localhost:8888/app/node/",
        LauncherController.buildBrowserUri(TEST_PORT, "/app/node").toString());
    assertEquals(
        "http://localhost:<port>/app/node/",
        LauncherController.describeBrowserTarget(null, "/app/node"));
  }

  @Test
  void buildBrowserUri_whenUiRootUnsafe_expectDefaultRootUsed() {
    assertEquals(
        "http://localhost:8888/",
        LauncherController.buildBrowserUri(TEST_PORT, "/app node/").toString());
    assertEquals(
        "http://localhost:<port>/", LauncherController.describeBrowserTarget(null, "/app node/"));
  }

  @Test
  void shouldRelaunchAfterDefaultStructuredPromotion_whenInvokedTwice_expectSingleRelaunch()
      throws Exception {
    RecordingLauncherController controller =
        new RecordingLauncherController(tempDir, () -> null, () -> null);
    LauncherReadinessInfo shellReadiness = LauncherReadinessInfo.ready(TEST_PORT, SHELL_UI_ROOT);
    AppState defaultRootState =
        new AppState(true, TEST_PORT, LauncherReadinessInfo.DEFAULT_UI_ROOT, false, false);

    setDefaultStructuredAutoOpenedBrowser(controller);

    assertTrue(
        invokeShouldRelaunchAfterDefaultStructuredPromotion(
            controller, defaultRootState, shellReadiness));
    assertFalse(
        invokeShouldRelaunchAfterDefaultStructuredPromotion(
            controller, defaultRootState, shellReadiness));

    controller.shutdownAndWait();
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
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(40);
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
    sleepMillis(10L);
  }

  private static void sleepMillis(long millis) {
    LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(millis));
    if (Thread.currentThread().isInterrupted()) {
      Thread.currentThread().interrupt();
      throw new AssertionError("Interrupted while waiting");
    }
  }

  private static void awaitCondition(ThrowingBooleanSupplier condition, String description)
      throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      if (condition.getAsBoolean()) {
        return;
      }
      sleepShort();
    }
    throw new AssertionError("Timed out waiting for " + description);
  }

  private static void setPrivateStateField(Object target, Object value) throws Exception {
    Field field = target.getClass().getDeclaredField("state");
    field.setAccessible(true);
    Object fieldValue = field.get(target);
    if (fieldValue instanceof AtomicReference<?> ref) {
      @SuppressWarnings("unchecked")
      AtomicReference<Object> typed = (AtomicReference<Object>) ref;
      typed.set(value);
      return;
    }
    field.set(target, value);
  }

  private static boolean isBrowserAutoOpened(LauncherController controller) throws Exception {
    Field field = controller.getClass().getDeclaredField("autoOpenedBrowser");
    field.setAccessible(true);
    return ((java.util.concurrent.atomic.AtomicBoolean) field.get(controller)).get();
  }

  private static void setLaunchStartedAtMillis(LauncherController controller, long value)
      throws Exception {
    Field field = LauncherController.class.getDeclaredField("launchStartedAtMillis");
    field.setAccessible(true);
    ((java.util.concurrent.atomic.AtomicLong) field.get(controller)).set(value);
  }

  private static void setPendingLegacyPort(LauncherController controller) throws Exception {
    Field field = LauncherController.class.getDeclaredField("pendingLegacyPort");
    field.setAccessible(true);
    @SuppressWarnings("unchecked")
    AtomicReference<Integer> ref = (AtomicReference<Integer>) field.get(controller);
    ref.set(TEST_PORT);
  }

  private static void markStartupCompletionObserved(LauncherController controller)
      throws Exception {
    Field field = LauncherController.class.getDeclaredField("startupCompletionObserved");
    field.setAccessible(true);
    ((java.util.concurrent.atomic.AtomicBoolean) field.get(controller)).set(true);
  }

  private static void setDefaultStructuredAutoOpenedBrowser(LauncherController controller)
      throws Exception {
    Field field = LauncherController.class.getDeclaredField("defaultStructuredAutoOpenedBrowser");
    field.setAccessible(true);
    ((java.util.concurrent.atomic.AtomicBoolean) field.get(controller)).set(true);
  }

  private static void setTrackedReadinessTarget(LauncherController controller, Path readinessFile)
      throws Exception {
    setTrackedReadinessTarget(controller, readinessFile, false);
  }

  private static void setTrackedReadinessTarget(
      LauncherController controller, Path readinessFile, boolean trackedAfterLaunch)
      throws Exception {
    Object target = invokeCaptureReadinessTarget(controller, readinessFile, trackedAfterLaunch);
    Field field = LauncherController.class.getDeclaredField("readinessTarget");
    field.setAccessible(true);
    @SuppressWarnings("unchecked")
    AtomicReference<Object> ref = (AtomicReference<Object>) field.get(controller);
    ref.set(target);
  }

  private static Object invokeCaptureReadinessTarget(
      LauncherController controller, Path readinessFile, boolean trackedAfterLaunch)
      throws Exception {
    if (!trackedAfterLaunch) {
      Method captureMethod =
          LauncherController.class.getDeclaredMethod("captureReadinessTarget", Path.class);
      captureMethod.setAccessible(true);
      return captureMethod.invoke(controller, readinessFile);
    }
    Method captureMethod =
        LauncherController.class.getDeclaredMethod(
            "captureReadinessTarget", Path.class, boolean.class, boolean.class);
    captureMethod.setAccessible(true);
    return captureMethod.invoke(controller, readinessFile, true, false);
  }

  private static boolean invokeCanConsumeCurrentLaunchReadiness(
      LauncherController controller, LauncherReadinessFiles.ReadinessSnapshot readiness)
      throws Exception {
    Field field = LauncherController.class.getDeclaredField("readinessTarget");
    field.setAccessible(true);
    @SuppressWarnings("unchecked")
    AtomicReference<Object> ref = (AtomicReference<Object>) field.get(controller);
    Object trackedTarget = ref.get();
    Method method = findCanConsumeCurrentLaunchReadinessMethod();
    method.setAccessible(true);
    return (boolean) method.invoke(controller, trackedTarget, readiness);
  }

  private static Method findCanConsumeCurrentLaunchReadinessMethod() {
    for (Method method : LauncherController.class.getDeclaredMethods()) {
      if (method.getName().equals("canConsumeCurrentLaunchReadiness")
          && method.getParameterCount() == 2) {
        return method;
      }
    }
    throw new AssertionError("Missing canConsumeCurrentLaunchReadiness helper");
  }

  private static boolean invokeShouldRelaunchAfterDefaultStructuredPromotion(
      LauncherController controller, AppState currentState, LauncherReadinessInfo readinessInfo)
      throws Exception {
    Method method =
        LauncherController.class.getDeclaredMethod(
            "shouldRelaunchAfterDefaultStructuredPromotion",
            AppState.class,
            LauncherReadinessInfo.class);
    method.setAccessible(true);
    return (boolean) method.invoke(controller, currentState, readinessInfo);
  }

  private static void awaitHeartbeat(Path heartbeat) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      if (Files.isRegularFile(heartbeat) && Files.size(heartbeat) > 0) {
        return;
      }
      sleepShort();
    }
    throw new AssertionError("Timed out waiting for launcher heartbeat output");
  }

  private static void awaitFileSizeStable(Path file, Duration stableFor) throws Exception {
    long stableNs = stableFor.toNanos();
    long stableSince = System.nanoTime();
    long previousSize = Files.exists(file) ? Files.size(file) : 0L;
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (System.nanoTime() < deadline) {
      LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
      long sizeNow = Files.exists(file) ? Files.size(file) : 0L;
      if (sizeNow != previousSize) {
        previousSize = sizeNow;
        stableSince = System.nanoTime();
      }
      if (System.nanoTime() - stableSince >= stableNs) {
        return;
      }
    }
    throw new AssertionError("Heartbeat file kept changing; process still appears alive");
  }

  private static Path createReadinessFilePath(Path baseDir, String runDirName) throws Exception {
    Path runDir = baseDir.resolve(runDirName);
    Files.createDirectories(runDir);
    return LauncherReadinessFiles.resolve(runDir);
  }

  private static Path createDaemonLogFilePath(Path baseDir) throws Exception {
    Path logsDir = baseDir.resolve("logs");
    Files.createDirectories(logsDir);
    Path daemonLogFile = logsDir.resolve("crypta-latest.log");
    Files.writeString(daemonLogFile, "", StandardCharsets.UTF_8);
    return daemonLogFile;
  }

  private static void writeStructuredReadinessCryptadScript(
      Path baseDir, Path readinessFile, Path daemonLogFile, Path legacyDetectedMarker)
      throws Exception {
    writeStructuredReadinessCryptadScript(
        baseDir,
        readinessFile,
        daemonLogFile,
        legacyDetectedMarker,
        LauncherReadinessInfo.DEFAULT_UI_ROOT);
  }

  private static void writeStructuredReadinessCryptadScript(
      Path baseDir,
      Path readinessFile,
      Path daemonLogFile,
      Path legacyDetectedMarker,
      String uiRoot)
      throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    Path readinessDir = parentOrThrow(readinessFile);
    String runDir = readinessDir.toAbsolutePath().toString();
    Files.createDirectories(readinessDir);
    String readinessPath = readinessFile.toAbsolutePath().toString();
    String daemonLogPath = daemonLogFile.toAbsolutePath().toString();
    String markerPath = legacyDetectedMarker.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "echo legacy>\"" + markerPath + "\"",
              "echo   Run dir:      " + runDir + ">>\"" + daemonLogPath + "\"",
              "ping -n 2 127.0.0.1 > nul",
              "(",
              "echo version=" + LauncherReadinessInfo.VERSION_1,
              "echo state=" + LauncherReadinessInfo.READY_STATE,
              "echo ui.port=" + TEST_PORT,
              "echo ui.root=" + uiRoot,
              ") > \"" + readinessPath + "\"",
              "echo READY",
              "ping -n 2 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "printf 'legacy\\n' > \"" + markerPath + "\"",
              "printf '  Run dir:      " + runDir + "\\n' >> \"" + daemonLogPath + "\"",
              "sleep " + SHELL_SLEEP_SHORT,
              "cat <<'EOF' > \"" + readinessPath + "\"",
              "version=" + LauncherReadinessInfo.VERSION_1,
              "state=" + LauncherReadinessInfo.READY_STATE,
              "ui.port=" + TEST_PORT,
              "ui.root=" + uiRoot,
              "EOF",
              "echo \"READY\"",
              "sleep " + SHELL_SLEEP_MEDIUM);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static Path parentOrThrow(Path path) {
    Path parent = path.getParent();
    if (parent == null) {
      throw new AssertionError("Expected parent for path " + path);
    }
    return parent;
  }

  private static void writeStructuredReadinessPromotionCryptadScript(
      Path baseDir, Path readinessFile, String initialUiRoot, String updatedUiRoot)
      throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String readinessPath = readinessFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "ping -n 2 127.0.0.1 > nul",
              "(",
              "echo version=" + LauncherReadinessInfo.VERSION_1,
              "echo state=" + LauncherReadinessInfo.READY_STATE,
              "echo ui.port=" + TEST_PORT,
              "echo ui.root=" + initialUiRoot,
              ") > \"" + readinessPath + "\"",
              "ping -n 3 127.0.0.1 > nul",
              "(",
              "echo version=" + LauncherReadinessInfo.VERSION_1,
              "echo state=" + LauncherReadinessInfo.READY_STATE,
              "echo ui.port=" + TEST_PORT,
              "echo ui.root=" + updatedUiRoot,
              ") > \"" + readinessPath + "\"",
              "ping -n 5 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "sleep " + SHELL_SLEEP_MEDIUM,
              "cat <<'EOF' > \"" + readinessPath + "\"",
              "version=" + LauncherReadinessInfo.VERSION_1,
              "state=" + LauncherReadinessInfo.READY_STATE,
              "ui.port=" + TEST_PORT,
              "ui.root=" + initialUiRoot,
              "EOF",
              "sleep " + SHELL_SLEEP_LONG,
              "cat <<'EOF' > \"" + readinessPath + "\"",
              "version=" + LauncherReadinessInfo.VERSION_1,
              "state=" + LauncherReadinessInfo.READY_STATE,
              "ui.port=" + TEST_PORT,
              "ui.root=" + updatedUiRoot,
              "EOF",
              "sleep " + SHELL_SLEEP_LONG);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeStableStructuredReadinessCryptadScript(Path baseDir, Path readinessFile)
      throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String readinessPath = readinessFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "ping -n 2 127.0.0.1 > nul",
              "(",
              "echo version=" + LauncherReadinessInfo.VERSION_1,
              "echo state=" + LauncherReadinessInfo.READY_STATE,
              "echo ui.port=" + TEST_PORT,
              "echo ui.root=" + SHELL_UI_ROOT,
              ") > \"" + readinessPath + "\"",
              "ping -n 6 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "sleep " + SHELL_SLEEP_SHORT,
              "cat <<'EOF' > \"" + readinessPath + "\"",
              "version=" + LauncherReadinessInfo.VERSION_1,
              "state=" + LauncherReadinessInfo.READY_STATE,
              "ui.port=" + TEST_PORT,
              "ui.root=" + SHELL_UI_ROOT,
              "EOF",
              "sleep " + SHELL_SLEEP_LONG);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLegacyPortCryptadScript(Path baseDir) throws Exception {
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
              "sleep " + SHELL_SLEEP_MEDIUM);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLegacyPortWithoutReadinessCryptadScript(Path baseDir, Path daemonLogFile)
      throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String daemonLogPath = daemonLogFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "echo Node initialization completed>>\"" + daemonLogPath + "\"",
              "ping -n 3 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "printf 'Node initialization completed\\n' >> \"" + daemonLogPath + "\"",
              "sleep " + SHELL_SLEEP_LONG);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLegacyPortWithoutReadinessButWithRunDirCryptadScript(
      Path baseDir, Path runDir, Path daemonLogFile) throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String resolvedRunDir = runDir.toAbsolutePath().toString();
    String daemonLogPath = daemonLogFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "echo   Run dir:      " + resolvedRunDir + ">>\"" + daemonLogPath + "\"",
              "echo Node initialization completed>>\"" + daemonLogPath + "\"",
              "ping -n 6 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "printf '  Run dir:      " + resolvedRunDir + "\\n' >> \"" + daemonLogPath + "\"",
              "printf 'Node initialization completed\\n' >> \"" + daemonLogPath + "\"",
              "sleep " + SHELL_SLEEP_LONG);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLegacyPortWithMalformedReadinessCryptadScript(
      Path baseDir, Path readinessFile, Path daemonLogFile) throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String readinessPath = readinessFile.toAbsolutePath().toString();
    String daemonLogPath = daemonLogFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "(",
              "echo version=2",
              "echo state=ready",
              "echo ui.port=9999",
              ") > \"" + readinessPath + "\"",
              "echo Node initialization completed>>\"" + daemonLogPath + "\"",
              "ping -n 3 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "cat <<'EOF' > \"" + readinessPath + "\"",
              "version=2",
              "state=ready",
              "ui.port=9999",
              "EOF",
              "printf 'Node initialization completed\\n' >> \"" + daemonLogPath + "\"",
              "sleep " + SHELL_SLEEP_LONG);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLegacyFallbackThenStructuredReadinessCryptadScript(
      Path baseDir, Path readinessFile, Path daemonLogFile) throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String readinessPath = readinessFile.toAbsolutePath().toString();
    String daemonLogPath = daemonLogFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "echo Node initialization completed>>\"" + daemonLogPath + "\"",
              "ping -n 3 127.0.0.1 > nul",
              "(",
              "echo version=" + LauncherReadinessInfo.VERSION_1,
              "echo state=" + LauncherReadinessInfo.READY_STATE,
              "echo ui.port=" + TEST_PORT,
              "echo ui.root=" + SHELL_UI_ROOT,
              ") > \"" + readinessPath + "\"",
              "ping -n 5 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "printf 'Node initialization completed\\n' >> \"" + daemonLogPath + "\"",
              "sleep " + SHELL_SLEEP_LONG,
              "cat <<'EOF' > \"" + readinessPath + "\"",
              "version=" + LauncherReadinessInfo.VERSION_1,
              "state=" + LauncherReadinessInfo.READY_STATE,
              "ui.port=" + TEST_PORT,
              "ui.root=" + SHELL_UI_ROOT,
              "EOF",
              "sleep " + SHELL_SLEEP_LONG);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLegacyPortWithWrapperLogCompletionCryptadScript(
      Path baseDir, Path wrapperLogFile) throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String wrapperLogPath = wrapperLogFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              "ping -n 3 127.0.0.1 > nul",
              "echo Node initialization completed>>\"" + wrapperLogPath + "\"",
              "ping -n 2 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "sleep " + SHELL_SLEEP_MEDIUM,
              "printf 'Node initialization completed\\n' >> \"" + wrapperLogPath + "\"",
              "sleep " + SHELL_SLEEP_MEDIUM);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLegacyPortWithStdoutCompletionCryptadScript(Path baseDir)
      throws Exception {
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
              "echo Node initialization completed",
              "ping -n 3 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "echo \"Node initialization completed\"",
              "sleep " + SHELL_SLEEP_LONG);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeNoReadinessCryptadScript(Path baseDir, Path runDir, Path daemonLogFile)
      throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String resolvedRunDir = runDir.toAbsolutePath().toString();
    String daemonLogPath = daemonLogFile.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "echo   Run dir:      " + resolvedRunDir + ">>\"" + daemonLogPath + "\"",
              "echo BOOTING",
              "ping -n 2 127.0.0.1 > nul");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "printf '  Run dir:      " + resolvedRunDir + "\\n' >> \"" + daemonLogPath + "\"",
              "echo \"BOOTING\"",
              "sleep " + SHELL_SLEEP_MEDIUM);
    }
    Files.writeString(script, content, StandardCharsets.UTF_8);

    if (!isWindows && !script.toFile().setExecutable(true)) {
      throw new AssertionError("Failed to mark script executable: " + script);
    }
  }

  private static void writeLongRunningCryptadScript(Path baseDir, Path heartbeat) throws Exception {
    Path binDir = baseDir.resolve("bin");
    Files.createDirectories(binDir);
    boolean isWindows = new AppEnv().isWindows();
    Path script = isWindows ? binDir.resolve("cryptad.bat") : binDir.resolve("cryptad");
    String heartbeatPath = heartbeat.toAbsolutePath().toString();

    String content;
    if (isWindows) {
      content =
          String.join(
              "\n",
              "@echo off",
              "setlocal",
              "set \"HEARTBEAT=" + heartbeatPath + "\"",
              "echo Starting FProxy on 127.0.0.1:" + TEST_PORT,
              ":loop",
              "echo %TIME%>>\"%HEARTBEAT%\"",
              "ping -n 2 127.0.0.1 > nul",
              "goto loop");
    } else {
      content =
          String.join(
              "\n",
              "#!/usr/bin/env sh",
              "HEARTBEAT=\"" + heartbeatPath + "\"",
              "echo \"Starting FProxy on 127.0.0.1:" + TEST_PORT + "\"",
              "while true; do",
              "  date +%s%N >> \"$HEARTBEAT\"",
              "  sleep " + SHELL_SLEEP_LOOP,
              "done");
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

  private static class RecordingLauncherController extends LauncherController {
    private final CopyOnWriteArrayList<URI> launchedUris = new CopyOnWriteArrayList<>();

    RecordingLauncherController(
        Path cwd,
        java.util.function.Supplier<Path> readinessFileResolver,
        java.util.function.Supplier<Path> daemonLogFileResolver) {
      super(cwd, readinessFileResolver, daemonLogFileResolver, TEST_TIMING);
    }

    @Override
    public void launchBrowser() {
      AppState currentState = getState();
      Integer port = currentState.knownPort();
      if (port != null) {
        launchedUris.add(buildBrowserUri(port, currentState.knownUiRoot()));
      }
    }

    List<URI> launchedUris() {
      return List.copyOf(launchedUris);
    }
  }

  private static final class FlakyReadinessLauncherController extends RecordingLauncherController {
    private final AtomicBoolean failNextRead = new AtomicBoolean();
    private final AtomicBoolean failureInjected = new AtomicBoolean();
    private final CountDownLatch allowRecovery = new CountDownLatch(1);

    FlakyReadinessLauncherController(
        Path cwd,
        java.util.function.Supplier<Path> readinessFileResolver,
        java.util.function.Supplier<Path> daemonLogFileResolver) {
      super(cwd, readinessFileResolver, daemonLogFileResolver);
    }

    void failNextRead() {
      failNextRead.set(true);
    }

    boolean failureInjected() {
      return failureInjected.get();
    }

    void allowRecovery() {
      allowRecovery.countDown();
    }

    @Override
    Optional<LauncherReadinessFiles.ReadinessSnapshot> readStructuredReadinessSnapshot(
        Path readinessFile) throws java.io.IOException {
      if (failNextRead.compareAndSet(true, false)) {
        failureInjected.set(true);
        throw new java.io.IOException("transient readiness read failure");
      }
      if (failureInjected.get()) {
        try {
          if (!allowRecovery.await(5, TimeUnit.SECONDS)) {
            throw new AssertionError("Timed out waiting to allow readiness recovery");
          }
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new AssertionError("Interrupted while awaiting readiness recovery", e);
        }
      }
      return super.readStructuredReadinessSnapshot(readinessFile);
    }
  }

  @FunctionalInterface
  private interface ThrowingBooleanSupplier {
    boolean getAsBoolean() throws Exception;
  }
}
