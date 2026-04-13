package network.crypta.platform.apphost.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import network.crypta.fs.AppEnv;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocalProcessAppHostTest {
  private static final String SAMPLE_APP_ID = "sample-app";
  private static final String RUNNER_APP_ID = "runner-app";
  private static final String DUPLICATE_APP_ID = "duplicate-app";
  private static final String MIXED_CASE_APP_ID = "MixedCase-App";
  private static final String NORMALIZED_MIXED_CASE_APP_ID = "mixedcase-app";
  private static final String PYTHON_DAEMON_APP_ID = "python-daemon-app";
  private static final String APP_VERSION = "2.0.0";
  private static final String DEFAULT_TOKEN = "token";
  private static final String CACHE_DIR_NAME = "cache";
  private static final String INSTALLED_DIR_NAME = "installed";
  private static final String INSTALLED_APPS_DIR_SYMLINK_MESSAGE =
      "installedAppsDir must not be a symlink";
  private static final String CONTENT_FILE_NAME = "content.txt";
  private static final String POSIX_LAUNCH_PATH = "bin/launch";
  private static final String STARTUP_EXIT_MESSAGE_PREFIX = "app exited during startup: ";
  private static final String WINDOWS_11 = "Windows 11";
  private static final String LINUX_OS_NAME = "Linux";
  private static final String PYTHON3_COMMAND = "python3";
  private static final String SYSTEM_ENV_COMMAND = "/usr/bin/env";
  private static final String CHILD_SCRIPT_PATH = "bin/child.sh";
  private static final String CHILD_PID_FILE_NAME = "child.pid";
  private static final String WINDOWS_CHILD_EXECUTABLE = "child.exe";
  private static final String POSIX_START_PATH = "bin/start";
  private static final String STAGE_DIR_NAME = "stage";
  private static final String MANIFEST_FILE_NAME = "cryptad-app.properties";
  private static final String MKFIFO_COMMAND = "mkfifo";
  private static final String NETWORK_ACCESS_PERMISSION = "network.access";
  private static final String FILE_READ_PERMISSION = "file.read";
  private static final List<String> STANDARD_PERMISSIONS =
      List.of(NETWORK_ACCESS_PERMISSION, FILE_READ_PERMISSION);
  private static final String STANDARD_PERMISSIONS_TEXT =
      NETWORK_ACCESS_PERMISSION + "," + FILE_READ_PERMISSION;
  private static final long POLL_INTERVAL_NANOS = Duration.ofMillis(10).toNanos();
  private static final LocalProcessAppHost.TimingConfig TEST_TIMING =
      new LocalProcessAppHost.TimingConfig(
          Duration.ofMillis(300),
          Duration.ofMillis(80),
          Duration.ofMillis(40),
          Duration.ofMillis(40),
          Duration.ofMillis(20),
          Duration.ofMillis(1),
          Duration.ofMillis(2),
          Duration.ofMillis(20));
  private static final Duration TEST_LOOP_SLEEP = Duration.ofMillis(50);
  private static final Duration TEST_DELAYED_WRAPPER_EXIT = Duration.ofMillis(120);
  private static final Duration TEST_POST_CAPTURE_DELAY =
      TEST_TIMING.startupProcessCaptureWindow().plusMillis(10);
  private static final Duration TEST_LATE_CHILD_DELAY =
      TEST_TIMING.startupExitGracePeriod().plusMillis(25);
  private static final Duration TEST_POST_SPAWN_EXIT_DELAY = Duration.ofMillis(40);
  private static final Duration TEST_SHORT_EXIT_DELAY = Duration.ofMillis(50);
  private static final String TEST_LOOP_SLEEP_SECONDS = secondsLiteral(TEST_LOOP_SLEEP);
  private static final String TEST_DELAYED_WRAPPER_EXIT_SECONDS =
      secondsLiteral(TEST_DELAYED_WRAPPER_EXIT);
  private static final String TEST_POST_CAPTURE_DELAY_SECONDS =
      secondsLiteral(TEST_POST_CAPTURE_DELAY);
  private static final String TEST_LATE_CHILD_DELAY_SECONDS = secondsLiteral(TEST_LATE_CHILD_DELAY);
  private static final String TEST_POST_SPAWN_EXIT_DELAY_SECONDS =
      secondsLiteral(TEST_POST_SPAWN_EXIT_DELAY);
  private static final String TEST_SHORT_EXIT_DELAY_SECONDS = secondsLiteral(TEST_SHORT_EXIT_DELAY);
  private static final String LATE_CHILD_APP_ID = "late-child-app";
  private static final String SHELL_NOEXEC_APP_ID = "shell-noexec-app";
  private static final String WRAPPER_SCRIPT =
      """
      #!/bin/sh
      set -eu
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      wait "$child"
      """
          .formatted(CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String CHILD_PROCESS_SCRIPT =
      """
      #!/bin/sh
      trap '' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String DAEMONIZED_CHILD_PROCESS_SCRIPT =
      """
      #!/bin/sh
      trap 'exit 0' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String DETACHED_CHILD_PROCESS_SCRIPT =
      """
      #!/bin/sh
      trap '' HUP
      trap 'exit 0' TERM INT
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String DAEMONIZING_WRAPPER_IMMEDIATE_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      exit 0
      """
          .formatted(CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String DAEMONIZING_WRAPPER_DELAYED_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      echo "$$" > "$CRYPTAD_APP_RUN_DIR/wrapper.pid"
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      sleep %s
      echo exited > "$CRYPTAD_APP_RUN_DIR/wrapper-exited.txt"
      exit 0
      """
          .formatted(CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME, TEST_DELAYED_WRAPPER_EXIT_SECONDS);
  private static final String DAEMONIZING_WRAPPER_POST_CAPTURE_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      sleep %s
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      exit 0
      """
          .formatted(TEST_POST_CAPTURE_DELAY_SECONDS, CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String DAEMONIZING_WRAPPER_VIA_HELPER_SCRIPT =
      """
      #!/bin/sh
      set -eu
      ./bin/helper.sh &
      exit 0
      """;
  private static final String DELAYED_DAEMONIZING_HELPER_SCRIPT =
      """
      #!/bin/sh
      set -eu
      sleep %s
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      exit 0
      """
          .formatted(TEST_POST_CAPTURE_DELAY_SECONDS, CHILD_SCRIPT_PATH, CHILD_PID_FILE_NAME);
  private static final String POST_CAPTURE_PYTHON_DAEMONIZER =
      """
      #!/usr/bin/env %s
      import os
      import pathlib
      import subprocess
      import time

      time.sleep(%s)
      child = subprocess.Popen(["./%s"])
      pathlib.Path(os.environ["CRYPTAD_APP_RUN_DIR"], "%s").write_text(
          f"{child.pid}\\n", encoding="utf-8")
      """
          .formatted(
              PYTHON3_COMMAND,
              TEST_POST_CAPTURE_DELAY_SECONDS,
              CHILD_SCRIPT_PATH,
              CHILD_PID_FILE_NAME);
  private static final String LATE_CHILD_DIRECT_EXECUTABLE =
      """
      #!/bin/sh
      set -eu
      sleep %s
      ./%s &
      child=$!
      echo "$child" > "$CRYPTAD_APP_RUN_DIR/%s"
      sleep %s
      echo exited > "$CRYPTAD_APP_RUN_DIR/wrapper-exited.txt"
      exit 0
      """
          .formatted(
              TEST_LATE_CHILD_DELAY_SECONDS,
              CHILD_SCRIPT_PATH,
              CHILD_PID_FILE_NAME,
              TEST_POST_SPAWN_EXIT_DELAY_SECONDS);
  private static final String STDIN_EOF_SCRIPT =
      """
      #!/bin/sh
      set -eu
      cat >/dev/null
      echo closed > "$CRYPTAD_APP_RUN_DIR/stdin-closed.txt"
      while :; do
        sleep %s
      done
      """
          .formatted(TEST_LOOP_SLEEP_SECONDS);
  private static final String SINGLE_RUN_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      count_file="$CRYPTAD_APP_RUN_DIR/run-count.txt"
      count=1
      if [ -f "$count_file" ]; then
        count=$(( $(cat "$count_file") + 1 ))
      fi
      printf '%s\\n' "$count" > "$count_file"
      exit 0
      """;
  private static final String DELAYED_STARTUP_EXIT_SCRIPT =
      """
      #!/bin/sh
      set -eu
      sleep %s
      exit 0
      """
          .formatted(TEST_SHORT_EXIT_DELAY_SECONDS);

  @TempDir private Path tempDir;

  @Test
  void installFromDirectory_whenInstallingValidBundle_expectCopiedLayoutAndDescribe()
      throws IOException {
    AppHost host = host();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    assertEquals(SAMPLE_APP_ID, installation.appId());
    assertEquals(4096L, installation.manifest().dataQuotaBytes());
    assertEquals(1024L, installation.manifest().cacheQuotaBytes());
    assertTrue(Files.isRegularFile(installation.paths().manifestFile()));
    assertTrue(
        Files.isRegularFile(
            installation.paths().resolveInstalledPath(installation.manifest().execPath())));
    assertTrue(Files.isDirectory(installation.paths().dataDir()));
    assertTrue(Files.isDirectory(installation.paths().cacheDir()));
    assertTrue(Files.isDirectory(installation.paths().runDir()));
    assertEquals(java.util.List.of(installation), host.listInstalled());
    assertEquals(installation.manifest(), host.describe(SAMPLE_APP_ID).orElseThrow().manifest());
  }

  @Test
  void installFromDirectory_whenAppAlreadyInstalled_expectFailure() throws IOException {
    AppHost host = host();
    Path stagedApp = stageInstalledApp(DUPLICATE_APP_ID);

    host.installFromDirectory(stagedApp);

    assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));
  }

  @Test
  void
      updateFromDirectory_whenInstalledStoppedApp_expectManifestAndExecutableReplacedPreservingMutableDirs()
          throws IOException {
    AppHost host = host();
    Path installedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-installed").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            APP_VERSION,
            """
            #!/bin/sh
            printf 'old\\n'
            """,
            Map.of("bundle-only.txt", "old-bundle\n"));
    InstalledAppSnapshot installation = host.installFromDirectory(installedStage);
    Path dataSentinel =
        Files.writeString(
            installation.paths().dataDir().resolve("preserve-data.txt"),
            "keep-data",
            StandardCharsets.UTF_8);
    Path cacheSentinel =
        Files.writeString(
            installation.paths().cacheDir().resolve("preserve-cache.txt"),
            "keep-cache",
            StandardCharsets.UTF_8);
    Path runSentinel =
        Files.writeString(
            installation.paths().runDir().resolve("preserve-run.txt"),
            "keep-run",
            StandardCharsets.UTF_8);
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            "3.0.0",
            """
            #!/bin/sh
            printf 'new\\n'
            """,
            Map.of("new-bundle.txt", "new-bundle\n"));

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);

    assertEquals("3.0.0", updated.manifest().appVersion());
    assertEquals(installation.paths(), updated.paths());
    assertEquals("keep-data", Files.readString(dataSentinel, StandardCharsets.UTF_8));
    assertEquals("keep-cache", Files.readString(cacheSentinel, StandardCharsets.UTF_8));
    assertEquals("keep-run", Files.readString(runSentinel, StandardCharsets.UTF_8));
    assertFalse(Files.exists(updated.paths().installedRoot().resolve("bundle-only.txt")));
    assertEquals(
        "new-bundle\n",
        Files.readString(
            updated.paths().installedRoot().resolve("new-bundle.txt"), StandardCharsets.UTF_8));
    assertEquals(
        """
        #!/bin/sh
        printf 'new\\n'
        """,
        Files.readString(
            updated.paths().executablePath(updated.manifest()), StandardCharsets.UTF_8));
    assertEquals("3.0.0", host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(List.of(updated), host.listInstalled());
  }

  @Test
  void updateFromDirectory_whenInstalledManifestMissing_expectBundleRepaired() throws IOException {
    AppHost host = host();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Files.delete(installation.paths().manifestFile());
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-repair").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            "3.0.0",
            """
            #!/bin/sh
            printf 'repaired\\n'
            """,
            Map.of("repair-bundle.txt", "repair-bundle\n"));

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);

    assertEquals("3.0.0", updated.manifest().appVersion());
    assertEquals("3.0.0", host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(
        "repair-bundle\n",
        Files.readString(
            updated.paths().installedRoot().resolve("repair-bundle.txt"), StandardCharsets.UTF_8));
  }

  @Test
  void updateFromDirectory_whenStagedManifestTargetsDifferentApp_expectFailure()
      throws IOException {
    AppHost host = host();
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path mismatchedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-update").resolve(DUPLICATE_APP_ID),
            DUPLICATE_APP_ID,
            "3.0.0",
            scriptContent(new AppEnv()),
            Map.of());

    AppManifestException exception =
        assertThrows(
            AppManifestException.class,
            () -> host.updateFromDirectory(SAMPLE_APP_ID, mismatchedStage));

    assertTrue(exception.getMessage().contains("does not match requested app.id"));
    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void updateFromDirectory_whenAppNotInstalled_expectFailure() throws IOException {
    AppHost host = host();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);

    AppHostException exception =
        assertThrows(
            AppHostException.class, () -> host.updateFromDirectory(SAMPLE_APP_ID, stagedApp));

    assertEquals("app is not installed: " + SAMPLE_APP_ID, exception.getMessage());
  }

  @Test
  void updateFromDirectory_whenInstalledManifestUnreadable_expectReplacementRepairsBundle()
      throws IOException {
    AppHost host = host();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Files.delete(installation.paths().manifestFile());
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            "3.0.0",
            scriptContent(new AppEnv()),
            Map.of("new-bundle.txt", "new-bundle\n"));

    assertThrows(IOException.class, () -> host.describe(SAMPLE_APP_ID));

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);

    assertEquals("3.0.0", updated.manifest().appVersion());
    assertEquals("3.0.0", host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    assertEquals(
        "new-bundle\n",
        Files.readString(
            updated.paths().installedRoot().resolve("new-bundle.txt"), StandardCharsets.UTF_8));
  }

  @Test
  void updateFromDirectory_whenBackupCleanupFails_expectSuccessfulReplacementAndReadableInstall()
      throws IOException {
    LocalProcessAppHost host =
        host(
            Duration.ofSeconds(1),
            new AppEnv(),
            _ -> {
              throw new IOException("simulated backup cleanup failure");
            });
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path updatedStage =
        stageInstalledAppAt(
            tempDir.resolve("stage-update").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            "3.0.0",
            scriptContent(new AppEnv()),
            Map.of("new-bundle.txt", "new-bundle\n"));

    InstalledAppSnapshot updated = host.updateFromDirectory(SAMPLE_APP_ID, updatedStage);

    assertEquals("3.0.0", updated.manifest().appVersion());
    assertEquals("3.0.0", host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
    try (var entries = Files.list(updated.paths().installedRoot().getParent())) {
      assertTrue(
          entries.anyMatch(
              path ->
                  path.getFileName()
                      .toString()
                      .startsWith("app-install-backup-" + SAMPLE_APP_ID + "-")));
    }
    assertEquals(List.of(updated), host.listInstalled());
  }

  @Test
  void updateFromDirectory_whenAppIsRunning_expectFailure() throws IOException {
    AppHost host = host();
    host.installFromDirectory(stageInstalledRunnerApp(DAEMONIZED_CHILD_PROCESS_SCRIPT));
    host.start(RUNNER_APP_ID);

    try {
      AppHostException exception =
          assertThrows(
              AppHostException.class,
              () ->
                  host.updateFromDirectory(
                      RUNNER_APP_ID, tempDir.resolve(STAGE_DIR_NAME).resolve(RUNNER_APP_ID)));

      assertEquals("cannot update a running app: " + RUNNER_APP_ID, exception.getMessage());
      assertEquals(APP_VERSION, host.describe(RUNNER_APP_ID).orElseThrow().manifest().appVersion());
    } finally {
      host.stop(RUNNER_APP_ID);
    }
  }

  @Test
  void updateFromDirectory_whenStagedDirectoryInvalid_expectFailure() throws IOException {
    AppHost host = host();
    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));

    AppHostException exception =
        assertThrows(
            AppHostException.class,
            () -> host.updateFromDirectory(SAMPLE_APP_ID, tempDir.resolve("missing-stage")));

    assertTrue(exception.getMessage().contains("stagedAppDirectory must be an existing directory"));
    assertEquals(APP_VERSION, host.describe(SAMPLE_APP_ID).orElseThrow().manifest().appVersion());
  }

  @Test
  void installFromDirectory_whenInstalledAppsDirIsSymlink_expectFailure() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Path dataDir = tempDir.resolve("data");
    Path cacheDir = tempDir.resolve(CACHE_DIR_NAME);
    Path runDir = tempDir.resolve("run");
    AppHost host =
        new LocalProcessAppHost(
            new AppHostLayout(dataDir, cacheDir, runDir),
            Duration.ofSeconds(1),
            new java.security.SecureRandom());
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path installParent = Files.createDirectories(dataDir.resolve("apps"));
    Path externalInstalled = Files.createDirectories(tempDir.resolve("external-installed"));
    Files.createSymbolicLink(
        installParent.resolve(INSTALLED_DIR_NAME), externalInstalled.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains(INSTALLED_APPS_DIR_SYMLINK_MESSAGE));
    try (var children = Files.list(externalInstalled)) {
      assertEquals(List.of(), children.toList());
    }
  }

  @Test
  void uninstall_whenInstalledAppsDirBecomesSymlink_expectFailureBeforeDeletingExternalBundle()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Path dataDir = tempDir.resolve("data");
    Path cacheDir = tempDir.resolve(CACHE_DIR_NAME);
    Path runDir = tempDir.resolve("run");
    AppHost host =
        new LocalProcessAppHost(
            new AppHostLayout(dataDir, cacheDir, runDir),
            Duration.ofSeconds(1),
            new java.security.SecureRandom());

    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));

    Path installParent = dataDir.resolve("apps");
    Path installedAppsDir = installParent.resolve(INSTALLED_DIR_NAME);
    Path externalInstalled = tempDir.resolve("external-installed");
    Files.move(installedAppsDir, externalInstalled);
    Files.createSymbolicLink(installedAppsDir, externalInstalled.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.uninstall(SAMPLE_APP_ID));

    assertTrue(exception.getMessage().contains(INSTALLED_APPS_DIR_SYMLINK_MESSAGE));
    assertTrue(Files.isDirectory(externalInstalled.resolve(SAMPLE_APP_ID)));
    assertTrue(
        Files.isRegularFile(externalInstalled.resolve(SAMPLE_APP_ID).resolve(CONTENT_FILE_NAME)));
  }

  @Test
  void uninstall_whenInstalledAppsAncestorBecomesSymlink_expectFailureBeforeDeletingExternalBundle()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Path dataDir = tempDir.resolve("data");
    Path cacheDir = tempDir.resolve(CACHE_DIR_NAME);
    Path runDir = tempDir.resolve("run");
    AppHost host =
        new LocalProcessAppHost(
            new AppHostLayout(dataDir, cacheDir, runDir),
            Duration.ofSeconds(1),
            new java.security.SecureRandom());

    host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));

    Path appsDir = dataDir.resolve("apps");
    Path externalAppsDir = tempDir.resolve("external-apps");
    Files.move(appsDir, externalAppsDir);
    Files.createSymbolicLink(appsDir, externalAppsDir.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.uninstall(SAMPLE_APP_ID));

    assertTrue(exception.getMessage().contains(INSTALLED_APPS_DIR_SYMLINK_MESSAGE));
    assertTrue(
        Files.isDirectory(externalAppsDir.resolve(INSTALLED_DIR_NAME).resolve(SAMPLE_APP_ID)));
    assertTrue(
        Files.isRegularFile(
            externalAppsDir
                .resolve(INSTALLED_DIR_NAME)
                .resolve(SAMPLE_APP_ID)
                .resolve(CONTENT_FILE_NAME)));
  }

  @Test
  void listInstalled_whenStaleTemporaryInstallDirectoryExists_expectInstalledAppsOnly()
      throws IOException {
    AppHost host = host();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path staleInstallDirectory =
        tempDir
            .resolve("data")
            .resolve("apps")
            .resolve(INSTALLED_DIR_NAME)
            .resolve("app-install-stale");
    Files.createDirectories(staleInstallDirectory);
    Files.writeString(
        staleInstallDirectory.resolve(CONTENT_FILE_NAME), "stale", StandardCharsets.UTF_8);

    assertEquals(List.of(installation), host.listInstalled());
  }

  @Test
  void installFromDirectory_whenPosixDirectExecutableLacksExecutePermission_expectFailure()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    Path stagedApp =
        stageInstalledExecutableApp(
            "non-launchable-app",
            POSIX_LAUNCH_PATH,
            """
            exit 0
            """,
            Map.of(),
            false);

    Assumptions.assumeFalse(Files.isExecutable(stagedApp.resolve(POSIX_LAUNCH_PATH)));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("without execute permission"));
  }

  @Test
  void installFromDirectory_whenWindowsLauncherUsesUnsupportedScript_expectFailure()
      throws IOException {
    AppHost host = host(Duration.ofSeconds(1), new AppEnv(Map.of(), WINDOWS_11));
    Path stagedApp =
        stageInstalledExecutableApp(
            "unsupported-windows-script-app", "bin/launch.ps1", "Write-Output 'hi'\n", Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("app.exec is not launchable on Windows"));
  }

  @Test
  void installFromDirectory_whenWindowsLauncherIsGenericMzBlob_expectFailure() throws IOException {
    AppHost host = host(Duration.ofSeconds(1), new AppEnv(Map.of(), WINDOWS_11));
    Path stagedApp =
        stageInstalledExecutableApp("generic-mz-app", "bin/fake.bin", "placeholder", Map.of());
    byte[] fakeMz = new byte[64];
    fakeMz[0] = 'M';
    fakeMz[1] = 'Z';
    Files.write(stagedApp.resolve("bin/fake.bin"), fakeMz);

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("app.exec is not launchable on Windows"));
  }

  @Test
  void lifecycle_whenManifestUsesMixedCaseAppId_expectPublicApiAcceptsOriginalCase()
      throws IOException {
    AppHost host = host();
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledApp(MIXED_CASE_APP_ID));

    assertEquals(NORMALIZED_MIXED_CASE_APP_ID, installation.appId());
    assertEquals(
        installation.manifest(), host.describe(MIXED_CASE_APP_ID).orElseThrow().manifest());

    RunningAppSnapshot running = host.start(MIXED_CASE_APP_ID);

    assertEquals(NORMALIZED_MIXED_CASE_APP_ID, running.appId());
    assertEquals(running.token(), host.status(MIXED_CASE_APP_ID).orElseThrow().token());
    assertTrue(host.stop(MIXED_CASE_APP_ID));
    host.uninstall(MIXED_CASE_APP_ID);
    assertTrue(host.describe(NORMALIZED_MIXED_CASE_APP_ID).isEmpty());
  }

  @Test
  void lifecycle_whenInstalledScriptRuns_expectEnvTokenStopAndUninstall() throws IOException {
    AppHost host = host();
    Path stagedApp = stageInstalledApp(RUNNER_APP_ID);

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    assertFalse(running.token().isBlank());
    assertEquals(RUNNER_APP_ID, running.appId());
    assertEquals(running.token(), host.status(RUNNER_APP_ID).orElseThrow().token());
    List<RunningAppSnapshot> runningSnapshots = host.listRunning();
    assertEquals(1, runningSnapshots.size());
    assertEquals(running.appId(), runningSnapshots.getFirst().appId());
    assertEquals(running.token(), runningSnapshots.getFirst().token());

    Path captureFile = installation.paths().runDir().resolve("captured-env.txt");
    waitForFile(captureFile);
    String capture = Files.readString(captureFile, StandardCharsets.UTF_8);
    assertCapturedEnvironment(installation, running, capture);

    assertThrows(AppHostException.class, () -> host.uninstall(RUNNER_APP_ID));
    assertTrue(host.stop(RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());

    RunningAppSnapshot secondRun = host.start(RUNNER_APP_ID);
    assertNotEquals(running.token(), secondRun.token());
    assertTrue(host.stop(RUNNER_APP_ID));

    host.uninstall(RUNNER_APP_ID);
    assertInstallationPathsRemoved(installation);
    assertTrue(host.listInstalled().isEmpty());
  }

  @Test
  void start_whenInstalledProcessExitsImmediately_expectFailureAndNoRunningState()
      throws IOException {
    AppHost host = host();
    host.installFromDirectory(stageInstalledRunnerApp(immediateExitScriptContent(new AppEnv())));

    Instant started = Instant.now();
    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));
    Duration elapsed = Duration.between(started, Instant.now());

    assertTrue(exception.getMessage().contains(STARTUP_EXIT_MESSAGE_PREFIX + RUNNER_APP_ID));
    assertTrue(elapsed.compareTo(Duration.ofSeconds(3)) < 0);
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void start_whenInstalledProcessExitsShortlyAfterLaunch_expectNoStaleRunningState()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    host.installFromDirectory(stageInstalledRunnerApp(DELAYED_STARTUP_EXIT_SCRIPT));

    try {
      host.start(RUNNER_APP_ID);
    } catch (AppHostException exception) {
      assertTrue(exception.getMessage().contains(STARTUP_EXIT_MESSAGE_PREFIX + RUNNER_APP_ID));
    }

    waitForNotRunning(host);
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void start_whenInstalledExecParentBecomesSymlink_expectFailureBeforeExternalCodeRuns()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Path externalBin = Files.createDirectories(tempDir.resolve("external-bin"));
    Path externalLaunch = externalBin.resolve(scriptName(appEnv));
    writeStageFile(
        externalLaunch,
        """
        #!/bin/sh
        printf 'escaped' > "$CRYPTAD_APP_RUN_DIR/escaped.txt"
        while :; do
          sleep %s
        done
        """
            .formatted(TEST_LOOP_SLEEP_SECONDS),
        appEnv);
    Path installedBin = installation.paths().installedRoot().resolve("bin");
    Path relocatedInstalledBin = installation.paths().installedRoot().resolve("bin-original");
    Files.move(installedBin, relocatedInstalledBin);
    Files.createSymbolicLink(installedBin, externalBin.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertTrue(exception.getMessage().contains("symlinks or reparse points"));
    assertFalse(Files.exists(installation.paths().runDir().resolve("escaped.txt")));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
  }

  @Test
  void start_whenLauncherDaemonizesChildAndExitsImmediately_expectChildManagedAsRunningApp()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_IMMEDIATE_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      assertEquals(childPid, running.pid());
      RunningAppSnapshot current = waitForRunningApp(host, RUNNER_APP_ID);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertTrue(
          ProcessHandle.of(current.pid())
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertEquals(
          "cannot uninstall a running app: " + RUNNER_APP_ID,
          assertThrows(AppHostException.class, () -> host.uninstall(RUNNER_APP_ID)).getMessage());
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenLauncherDaemonizesChildAndExitsLater_expectRunningSnapshotPreserved()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_DELAYED_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    Path wrapperPidFile = installation.paths().runDir().resolve("wrapper.pid");
    long childPid = waitForPidFileValue(childPidFile);
    long wrapperPid = waitForPidFileValue(wrapperPidFile);
    Path wrapperExitedFile = installation.paths().runDir().resolve("wrapper-exited.txt");
    waitForFile(wrapperExitedFile);
    try {
      assertEquals(childPid, running.pid());
      waitForProcessExit(wrapperPid);
      RunningAppSnapshot current = waitForRunningApp(host, RUNNER_APP_ID);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertEquals(java.util.List.of(current), host.listRunning());
      assertTrue(
          ProcessHandle.of(current.pid())
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
      ProcessHandle.of(wrapperPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenLauncherDaemonizesChildAfterStartupCapture_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_POST_CAPTURE_EXIT_SCRIPT,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenDirectInterpreterLauncherDaemonizesChildAfterStartupCapture_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath(PYTHON3_COMMAND));
    AppHost host = host(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledExecutableApp(
            PYTHON_DAEMON_APP_ID,
            POSIX_LAUNCH_PATH,
            POST_CAPTURE_PYTHON_DAEMONIZER,
            Map.of(CHILD_SCRIPT_PATH, DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(PYTHON_DAEMON_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, PYTHON_DAEMON_APP_ID, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertEquals(java.util.List.of(current), host.listRunning());
      assertTrue(host.stop(PYTHON_DAEMON_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(PYTHON_DAEMON_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenMacHostLauncherDaemonizesViaIntermediateHelper_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(1), new AppEnv(Map.of(), "Mac OS X"));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_VIA_HELPER_SCRIPT,
            Map.of(
                "bin/helper.sh",
                DELAYED_DAEMONIZING_HELPER_SCRIPT,
                CHILD_SCRIPT_PATH,
                DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void status_whenOtherUnixHostLauncherDaemonizesViaIntermediateHelper_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(1), new AppEnv(Map.of(), "FreeBSD"));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID,
            DAEMONIZING_WRAPPER_VIA_HELPER_SCRIPT,
            Map.of(
                "bin/helper.sh",
                DELAYED_DAEMONIZING_HELPER_SCRIPT,
                CHILD_SCRIPT_PATH,
                DAEMONIZED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      RunningAppSnapshot current = waitForRunningPid(host, childPid);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertEquals(childPid, current.pid());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void recoverTrackedDescendantProcesses_whenWindowsWrapperExited_expectLiveChildRecovered() {
    ProcessHandle wrapper = new ExitedProcessHandle(7100L);
    ProcessHandle helper = new LinkedProcessHandle(7101L, wrapper, false);
    ProcessHandle child = new LinkedProcessHandle(7102L, helper, true);
    ProcessHandle grandchild = new LinkedProcessHandle(7103L, child, true);
    ProcessHandle unrelated = new LinkedProcessHandle(8100L, new ExitedProcessHandle(8099L), true);

    List<ProcessHandle> recovered =
        LocalProcessAppHost.recoverTrackedDescendantProcesses(
            List.of(wrapper, helper), List.of(child, grandchild, unrelated));

    assertEquals(List.of(7102L, 7103L), recovered.stream().map(ProcessHandle::pid).toList());
  }

  @Test
  void
      recoverWindowsBundleProcesses_whenCommandLineReferencesInstalledBundle_expectLiveChildRecovered() {
    InstalledAppPaths paths =
        new AppHostLayout(
                tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run"))
            .pathsFor(RUNNER_APP_ID);
    AppManifest manifest =
        new AppManifest(
            1,
            RUNNER_APP_ID,
            displayName(RUNNER_APP_ID),
            APP_VERSION,
            "bin/launch.cmd",
            "/",
            STANDARD_PERMISSIONS,
            4096L,
            1024L);
    Instant startedAt = Instant.parse("2026-04-05T00:00:00Z");
    ProcessHandle wrapper = new ExitedProcessHandle(7200L);
    ProcessHandle staleBundleProcess =
        new InfoProcessHandle(
            7201L,
            null,
            true,
            paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE).toString(),
            "\"" + paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE) + "\"",
            startedAt.minusSeconds(5));
    ProcessHandle recoveredChild =
        new InfoProcessHandle(
            7202L,
            null,
            true,
            null,
            "\""
                + paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE)
                + "\" --serve",
            startedAt.plusMillis(750));

    List<ProcessHandle> recovered =
        LocalProcessAppHost.recoverWindowsBundleProcesses(
            paths,
            manifest,
            startedAt,
            List.of(wrapper),
            List.of(staleBundleProcess, recoveredChild));

    assertEquals(List.of(7202L), recovered.stream().map(ProcessHandle::pid).toList());
  }

  @Test
  void parseTokenTrackedProcesses_whenReaderFails_expectCheckedIoException() {
    Process process =
        new FailingInputProcess(
            (ProcessHandle.current().pid()
                    + " CRYPTAD_APP_TOKEN="
                    + DEFAULT_TOKEN
                    + " CRYPTAD_APP_ID="
                    + RUNNER_APP_ID
                    + "\n")
                .getBytes(StandardCharsets.UTF_8));

    IOException exception =
        assertThrows(IOException.class, () -> invokeParseRunnerTokenTrackedProcesses(process));

    assertEquals("simulated ps stream failure", exception.getMessage());
  }

  @Test
  void mergeTokenTrackedProcesses_whenProcReturnsEmptyOnUnix_expectPsFallback() {
    ProcessHandle psRecovered = new LinkedProcessHandle(7205L, null, true);

    List<ProcessHandle> recovered =
        LocalProcessAppHost.mergeTokenTrackedProcesses(
            List.of(), List.of(psRecovered), new AppEnv(Map.of(), LINUX_OS_NAME));

    assertEquals(List.of(7205L), recovered.stream().map(ProcessHandle::pid).toList());
  }

  @Test
  void recoverWindowsBundleProcesses_whenProcessStartsLongAfterLaunch_expectIgnored() {
    InstalledAppPaths paths =
        new AppHostLayout(
                tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run"))
            .pathsFor(RUNNER_APP_ID);
    AppManifest manifest =
        new AppManifest(
            1,
            RUNNER_APP_ID,
            displayName(RUNNER_APP_ID),
            APP_VERSION,
            "bin/launch.cmd",
            "/",
            STANDARD_PERMISSIONS,
            4096L,
            1024L);
    Instant startedAt = Instant.parse("2026-04-05T00:00:00Z");
    ProcessHandle unrelatedLaterProcess =
        new InfoProcessHandle(
            7204L,
            null,
            true,
            null,
            "\""
                + paths.installedRoot().resolve("bin").resolve(WINDOWS_CHILD_EXECUTABLE)
                + "\" --serve",
            startedAt.plusSeconds(30));

    List<ProcessHandle> recovered =
        LocalProcessAppHost.recoverWindowsBundleProcesses(
            paths,
            manifest,
            startedAt,
            List.of(new ExitedProcessHandle(7200L)),
            List.of(unrelatedLaterProcess));

    assertEquals(List.of(), recovered);
  }

  @Test
  void status_whenDirectLauncherSpawnsChildAfterStartupGrace_expectChildRetained()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(1));
    Path stagedApp =
        stageInstalledExecutableApp(
            LATE_CHILD_APP_ID,
            POSIX_LAUNCH_PATH,
            LATE_CHILD_DIRECT_EXECUTABLE,
            Map.of(CHILD_SCRIPT_PATH, DETACHED_CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    RunningAppSnapshot running = host.start(LATE_CHILD_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    Path wrapperExitedFile = installation.paths().runDir().resolve("wrapper-exited.txt");
    waitForFile(wrapperExitedFile);
    try {
      RunningAppSnapshot current = waitForRunningApp(host, LATE_CHILD_APP_ID);
      assertEquals(running.appId(), current.appId());
      assertEquals(running.token(), current.token());
      assertTrue(
          ProcessHandle.of(childPid)
              .map(LocalProcessAppHostTest::isEffectivelyAlive)
              .orElse(false));
      assertTrue(host.stop(LATE_CHILD_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(LATE_CHILD_APP_ID).isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void stop_whenProcessDoesNotExit_expectRunningStatePreserved()
      throws ReflectiveOperationException {
    LocalProcessAppHost host = host(Duration.ofMillis(10));
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(host, RUNNER_APP_ID, snapshot, new NonStoppingProcess(snapshot.pid()));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.stop(RUNNER_APP_ID));

    assertEquals("timed out stopping app: " + RUNNER_APP_ID, exception.getMessage());
    assertEquals(snapshot, host.status(RUNNER_APP_ID).orElseThrow());
    assertEquals(java.util.List.of(snapshot), host.listRunning());
    assertEquals(
        "cannot uninstall a running app: " + RUNNER_APP_ID,
        assertThrows(AppHostException.class, () -> host.uninstall(RUNNER_APP_ID)).getMessage());
    assertEquals(
        "app is already running: " + RUNNER_APP_ID,
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID)).getMessage());
  }

  @Test
  void stop_whenProcessExitsBetweenRefreshAndTracking_expectCleanSuccess()
      throws IOException, ReflectiveOperationException {
    LocalProcessAppHost host = host();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(
        host,
        RUNNER_APP_ID,
        snapshot,
        new FadingProcess(snapshot.pid(), 2),
        CompletableFuture.completedFuture(null));

    assertTrue(host.stop(RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void status_whenLiveProcessHandleOmitsOptionalMetadata_expectSnapshotRetained()
      throws ReflectiveOperationException {
    LocalProcessAppHost host = host();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(host, RUNNER_APP_ID, snapshot, new NonStoppingProcess(snapshot.pid()));

    assertEquals(snapshot, host.status(RUNNER_APP_ID).orElseThrow());
    assertEquals(java.util.List.of(snapshot), host.listRunning());
  }

  @Test
  void stop_whenWrapperScriptOwnsChildProcess_expectEntireProcessTreeTerminated()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(2));
    Path stagedApp =
        stageInstalledApp(
            RUNNER_APP_ID, WRAPPER_SCRIPT, Map.of(CHILD_SCRIPT_PATH, CHILD_PROCESS_SCRIPT));

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);
    host.start(RUNNER_APP_ID);

    Path childPidFile = installation.paths().runDir().resolve(CHILD_PID_FILE_NAME);
    long childPid = waitForPidFileValue(childPidFile);
    try {
      assertTrue(host.stop(RUNNER_APP_ID));
      waitForProcessExit(childPid);
      assertTrue(host.status(RUNNER_APP_ID).isEmpty());
      assertTrue(host.listRunning().isEmpty());
    } finally {
      ProcessHandle.of(childPid).ifPresent(ProcessHandle::destroyForcibly);
    }
  }

  @Test
  void stop_whenRecoveredLateChildExitsWithinStopTimeout_expectCleanSuccess()
      throws IOException, ReflectiveOperationException {
    long recoveredChildPid = 84L;
    LocalProcessAppHost host = host(Duration.ofMillis(200));
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(
        host,
        RUNNER_APP_ID,
        snapshot,
        new LateRecoveredChildProcess(snapshot.pid(), recoveredChildPid, 8),
        CompletableFuture.completedFuture(null));

    assertTrue(host.stop(RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void stop_whenShutdownSpawnsReplacementChild_expectFailureAndRunningStatePreserved()
      throws ReflectiveOperationException {
    String appId = "shutdown-respawn-app";
    long replacementChildPid = 84L;
    LocalProcessAppHost host = host(Duration.ofMillis(200));
    RunningAppSnapshot snapshot = runningSnapshot(appId);
    injectRunningProcess(
        host, appId, snapshot, new LateChildSpawningProcess(snapshot.pid(), replacementChildPid));

    AppHostException exception = assertThrows(AppHostException.class, () -> host.stop(appId));

    assertEquals("timed out stopping app: " + appId, exception.getMessage());
    RunningAppSnapshot current = host.status(appId).orElseThrow();
    assertEquals(appId, current.appId());
    assertEquals(replacementChildPid, current.pid());
  }

  @Test
  void launchCommand_whenWindowsBatchScript_expectQuotedCmdWrapper() throws IOException {
    AppEnv windowsAppEnv = new AppEnv(Map.of(), WINDOWS_11);
    Path batchScript = Path.of("C:/Users/Alice & Bob/Cryptad Apps^(1)/runner/bin/launch.cmd");
    Path nativeExecutable = Path.of("C:/apps/runner/bin/runner.exe");

    List<String> batchCommand = LocalProcessAppHost.launchCommand(batchScript, windowsAppEnv);

    assertEquals(4, batchCommand.size());
    assertTrue(batchCommand.get(0).toLowerCase(java.util.Locale.ROOT).endsWith("cmd.exe"));
    assertEquals("/d", batchCommand.get(1));
    assertEquals("/c", batchCommand.get(2));
    assertEquals("\"" + batchScript + "\"", batchCommand.get(3));
    assertEquals(
        java.util.List.of(nativeExecutable.toString()),
        LocalProcessAppHost.launchCommand(nativeExecutable, windowsAppEnv));
  }

  @Test
  void launchCommand_whenShebangUsesEnvSplitString_expectInterpreterArgumentPreserved()
      throws IOException {
    AppEnv appEnv = new AppEnv(Map.of(), LINUX_OS_NAME);
    Path script = tempDir.resolve("env-shebang.sh");
    Files.writeString(
        script,
        """
        #!/usr/bin/env -S bash -euo pipefail
        exit 0
        """,
        StandardCharsets.UTF_8);
    assertTrue(script.toFile().setExecutable(true, false));

    List<String> command = LocalProcessAppHost.launchCommand(script, appEnv);

    assertEquals(SYSTEM_ENV_COMMAND, command.get(0));
    assertEquals("-S bash -euo pipefail", command.get(1));
    assertEquals("-c", command.get(2));
    assertEquals(script.toString(), command.get(4));
  }

  @Test
  void installFromDirectory_whenShebangInterpreterIsFilesystemRoot_expectFailure()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    Path stagedApp =
        stageInstalledExecutableApp(
            "invalid-shebang-app",
            POSIX_START_PATH,
            """
            #!/
            exit 0
            """,
            Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertEquals("invalid shebang interpreter: /", exception.getMessage());
  }

  @Test
  void launchCommand_whenPythonShebangUsesShSuffix_expectInterpreterLaunch() throws IOException {
    AppEnv appEnv = new AppEnv(Map.of(), LINUX_OS_NAME);
    Path script = tempDir.resolve("python-launch.sh");
    Files.writeString(
        script,
        """
        #!/usr/bin/env %s
        print("ok")
        """
            .formatted(PYTHON3_COMMAND),
        StandardCharsets.UTF_8);

    List<String> command = LocalProcessAppHost.launchCommand(script, appEnv);

    assertEquals(SYSTEM_ENV_COMMAND, command.getFirst());
    assertEquals(PYTHON3_COMMAND, command.get(1));
    assertEquals(script.toString(), command.get(2));
  }

  @Test
  void installFromDirectory_whenInterpreterManagedLauncherContainsNonUtf8Body_expectSuccess()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath(PYTHON3_COMMAND));
    AppHost host = host();
    Path stagedApp =
        stageInstalledExecutableApp(
            "non-utf8-launcher-app",
            POSIX_START_PATH,
            """
            #!/usr/bin/env %s
            pass
            """
                .formatted(PYTHON3_COMMAND),
            Map.of(),
            false);
    Path script = stagedApp.resolve(POSIX_START_PATH);
    try (OutputStream output = Files.newOutputStream(script)) {
      output.write(
          ("#!/usr/bin/env " + PYTHON3_COMMAND + "\n").getBytes(StandardCharsets.US_ASCII));
      output.write(new byte[] {(byte) 0xC3, (byte) 0x28, (byte) '\n'});
    }

    List<String> command = LocalProcessAppHost.launchCommand(script, appEnv);
    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    assertEquals(SYSTEM_ENV_COMMAND, command.getFirst());
    assertEquals(PYTHON3_COMMAND, command.get(1));
    assertEquals(script.toString(), command.get(2));
    assertEquals("non-utf8-launcher-app", installation.appId());
  }

  @Test
  void start_whenPosixShellScriptRequiresShebangAndZeroArguments_expectSuccessfulLaunch()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath("bash"));
    AppHost host = host();
    InstalledAppSnapshot installation =
        host.installFromDirectory(
            stageInstalledRunnerApp(
                """
                #!/usr/bin/env bash
                set -euo pipefail
                [[ $# -eq 0 ]]
                letters=(alpha beta)
                printf '%%s' "${letters[0]}" > "$CRYPTAD_APP_RUN_DIR/shebang-ok.txt"
                while :; do
                  sleep %s
                done
                """
                    .formatted(TEST_LOOP_SLEEP_SECONDS)));

    host.start(RUNNER_APP_ID);

    Path confirmationFile = installation.paths().runDir().resolve("shebang-ok.txt");
    waitForFile(confirmationFile);
    assertEquals("alpha", Files.readString(confirmationFile, StandardCharsets.UTF_8));
    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void start_whenExtensionlessShebangLauncherLacksExecuteBit_expectSuccessfulLaunch()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    InstalledAppSnapshot installation =
        host.installFromDirectory(
            stageInstalledExecutableApp(
                SHELL_NOEXEC_APP_ID,
                POSIX_START_PATH,
                """
                #!/bin/sh
                set -eu
                printf '%%s' "ok" > "$CRYPTAD_APP_RUN_DIR/noexec-ok.txt"
                while :; do
                  sleep %s
                done
                """
                    .formatted(TEST_LOOP_SLEEP_SECONDS),
                Map.of(),
                false));

    host.start(SHELL_NOEXEC_APP_ID);

    Path confirmationFile = installation.paths().runDir().resolve("noexec-ok.txt");
    waitForFile(confirmationFile);
    assertEquals("ok", Files.readString(confirmationFile, StandardCharsets.UTF_8));
    assertTrue(host.stop(SHELL_NOEXEC_APP_ID));
  }

  @Test
  void start_whenLauncherWaitsForStandardInputEof_expectInitializationContinues()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host(Duration.ofSeconds(2));
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledRunnerApp(STDIN_EOF_SCRIPT));

    host.start(RUNNER_APP_ID);

    Path confirmationFile = installation.paths().runDir().resolve("stdin-closed.txt");
    waitForFile(confirmationFile);
    assertEquals("closed\n", Files.readString(confirmationFile, StandardCharsets.UTF_8));
    assertTrue(host.stop(RUNNER_APP_ID));
  }

  @Test
  void start_whenShellLauncherExitsCleanlyWithoutChild_expectFailureAfterSingleExecution()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    InstalledAppSnapshot installation =
        host.installFromDirectory(stageInstalledRunnerApp(SINGLE_RUN_EXIT_SCRIPT));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    Path runCountFile = installation.paths().runDir().resolve("run-count.txt");
    waitForFile(runCountFile);
    assertEquals("1\n", Files.readString(runCountFile, StandardCharsets.UTF_8));
    assertTrue(exception.getMessage().contains(STARTUP_EXIT_MESSAGE_PREFIX + RUNNER_APP_ID));
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  @Test
  void populateEnvironment_whenHostEnvironmentContainsSecrets_expectSanitizedChildEnvironment() {
    Map<String, String> environment = new HashMap<>();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);

    environment.put("GITHUB_TOKEN", "secret");
    environment.put("AWS_SECRET_ACCESS_KEY", "top-secret");

    LocalProcessAppHost.populateEnvironment(
        environment,
        snapshot.manifest(),
        snapshot.paths(),
        DEFAULT_TOKEN,
        new AppEnv(Map.of(), LINUX_OS_NAME));

    assertFalse(environment.containsKey("GITHUB_TOKEN"));
    assertFalse(environment.containsKey("AWS_SECRET_ACCESS_KEY"));
    assertEquals(
        "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:"
            + "/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin",
        environment.get("PATH"));
    assertEquals(DEFAULT_TOKEN, environment.get("CRYPTAD_APP_TOKEN"));
    assertEquals(RUNNER_APP_ID, environment.get("CRYPTAD_APP_ID"));
  }

  @Test
  void populateEnvironment_whenMacBaseEnvironment_expectPackageManagerPrefixesPresent() {
    Map<String, String> environment = new HashMap<>();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);

    LocalProcessAppHost.populateEnvironment(
        environment,
        snapshot.manifest(),
        snapshot.paths(),
        DEFAULT_TOKEN,
        new AppEnv(Map.of(), "Mac OS X"));

    assertEquals(
        "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin:"
            + "/opt/homebrew/bin:/opt/homebrew/sbin:/opt/local/bin:/opt/local/sbin",
        environment.get("PATH"));
  }

  @Test
  void populateEnvironment_whenWindowsBaseEnvironment_expectPowerShellDirectoryPresent() {
    Map<String, String> environment = new HashMap<>();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);

    LocalProcessAppHost.populateEnvironment(
        environment,
        snapshot.manifest(),
        snapshot.paths(),
        DEFAULT_TOKEN,
        new AppEnv(Map.of(), WINDOWS_11));

    List<String> pathEntries = List.of(environment.get("PATH").replace('\\', '/').split(";"));
    assertTrue(pathEntries.stream().anyMatch(entry -> entry.endsWith("/System32")));
    assertTrue(
        pathEntries.stream().anyMatch(entry -> entry.endsWith("/System32/WindowsPowerShell/v1.0")));
  }

  @Test
  void installFromDirectory_whenStagingContainsNamedPipe_expectFailureWithoutHanging()
      throws Exception {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    Assumptions.assumeTrue(appEnv.onPath(MKFIFO_COMMAND));
    AppHost host = host();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path namedPipe = stagedApp.resolve("blocked.pipe");

    Process mkfifo =
        new ProcessBuilder(resolveTrustedMkfifoCommand(), namedPipe.toString()).start();
    assertEquals(0, waitForExit(mkfifo));

    AppHostException exception = installExpectingAppHostException(host, stagedApp);

    assertTrue(
        exception.getMessage().contains("staging directory must contain only regular files"));
  }

  @Test
  void installFromDirectory_whenManifestIsSymlink_expectFailureBeforeParsingExternalContent()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    Path stagedApp =
        Files.createDirectories(tempDir.resolve(STAGE_DIR_NAME).resolve("manifest-symlink"));
    Path externalManifest = tempDir.resolve("outside-manifest.properties");
    String externalContent = "outside-secret-data";
    Files.writeString(externalManifest, externalContent, StandardCharsets.UTF_8);
    Files.createSymbolicLink(
        stagedApp.resolve(MANIFEST_FILE_NAME), externalManifest.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("symlink"));
    assertFalse(exception.getMessage().contains(externalContent));
  }

  @Test
  void installFromDirectory_whenStagingRootIsSymlink_expectFailure() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path linkedRoot = tempDir.resolve("linked-stage-root");
    Files.createSymbolicLink(linkedRoot, stagedApp.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(linkedRoot));

    assertTrue(exception.getMessage().contains("stagedAppDirectory must not be a symlink"));
  }

  @Test
  void installFromDirectory_whenStagingRootHasAliasedAncestor_expectSuccess() throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    Path realStagingParent = Files.createDirectories(tempDir.resolve("real-staging-parent"));
    Path aliasedParent = tempDir.resolve("aliased-staging-parent");
    Files.createSymbolicLink(aliasedParent, realStagingParent.toAbsolutePath());
    Path stagedApp =
        stageInstalledAppAt(
            aliasedParent.resolve(SAMPLE_APP_ID), SAMPLE_APP_ID, scriptContent(appEnv), Map.of());

    InstalledAppSnapshot installation = host.installFromDirectory(stagedApp);

    assertEquals(SAMPLE_APP_ID, installation.appId());
    assertTrue(Files.isRegularFile(installation.paths().manifestFile()));
  }

  @Test
  void start_whenMutableRunDirectoryBecomesSymlink_expectFailureBeforeWritingOutsideLayout()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Path externalRun = Files.createDirectories(tempDir.resolve("external-run"));
    Files.delete(installation.paths().runDir());
    Files.createSymbolicLink(installation.paths().runDir(), externalRun.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertTrue(exception.getMessage().contains("runDir must not be a symlink"));
    assertFalse(Files.exists(externalRun.resolve("process.log")));
  }

  @Test
  void start_whenMutableRunAncestorBecomesSymlink_expectFailureBeforeWritingOutsideLayout()
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeFalse(appEnv.isWindows());
    AppHost host = host();
    host.installFromDirectory(stageInstalledApp(RUNNER_APP_ID));
    Path runAppsDir = tempDir.resolve("run").resolve("apps");
    Path externalRunAppsDir = tempDir.resolve("external-run-apps");
    Files.move(runAppsDir, externalRunAppsDir);
    Files.createSymbolicLink(runAppsDir, externalRunAppsDir.toAbsolutePath());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.start(RUNNER_APP_ID));

    assertTrue(exception.getMessage().contains("runDir must not be a symlink"));
    assertFalse(Files.exists(externalRunAppsDir.resolve(RUNNER_APP_ID).resolve("process.log")));
  }

  @Test
  void installFromDirectory_whenStagingRootOverlapsInstalledTree_expectCleanFailure()
      throws IOException {
    AppHost host = host();
    Path stagedApp =
        stageInstalledAppAt(
            tempDir.resolve("data"), SAMPLE_APP_ID, scriptContent(new AppEnv()), Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("must not overlap the installed app tree"));
    assertFalse(Files.exists(tempDir.resolve("data").resolve("apps").resolve(INSTALLED_DIR_NAME)));
  }

  @Test
  void installFromDirectory_whenStagingRootCollidesWithRunDir_expectCleanFailure()
      throws IOException {
    AppHost host = host();
    Path stagedApp =
        stageInstalledAppAt(
            tempDir.resolve("run").resolve("apps").resolve(SAMPLE_APP_ID),
            SAMPLE_APP_ID,
            scriptContent(new AppEnv()),
            Map.of());

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("must not overlap runDir"));
    assertTrue(Files.isRegularFile(stagedApp.resolve(MANIFEST_FILE_NAME)));
    assertTrue(Files.isRegularFile(stagedApp.resolve(CONTENT_FILE_NAME)));
  }

  @Test
  void installFromDirectory_whenWindowsJunctionEscapesStagingRoot_expectFailure() throws Exception {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeTrue(appEnv.isWindows());
    AppHost host = host();
    Path stagedApp = stageInstalledApp(SAMPLE_APP_ID);
    Path externalRoot = Files.createDirectories(tempDir.resolve("outside-root"));
    Path junction = stagedApp.resolve("outside-junction");

    Process mklink =
        new ProcessBuilder(
                windowsCommandInterpreter(),
                "/c",
                "mklink",
                "/J",
                junction.toString(),
                externalRoot.toString())
            .start();
    assertEquals(0, waitForExit(mklink));

    AppHostException exception =
        assertThrows(AppHostException.class, () -> host.installFromDirectory(stagedApp));

    assertTrue(exception.getMessage().contains("links or reparse points"));
  }

  @Test
  void uninstall_whenWindowsJunctionExistsUnderAppData_expectTargetPreserved() throws Exception {
    AppEnv appEnv = new AppEnv();
    Assumptions.assumeTrue(appEnv.isWindows());
    AppHost host = host();
    InstalledAppSnapshot installation = host.installFromDirectory(stageInstalledApp(SAMPLE_APP_ID));
    Path externalRoot = Files.createDirectories(tempDir.resolve("outside-uninstall-root"));
    Path externalFile = externalRoot.resolve("outside.txt");
    Files.writeString(externalFile, "preserve", StandardCharsets.UTF_8);
    Path junction = installation.paths().dataDir().resolve("outside-junction");

    Process mklink =
        new ProcessBuilder(
                windowsCommandInterpreter(),
                "/c",
                "mklink",
                "/J",
                junction.toString(),
                externalRoot.toString())
            .start();
    assertEquals(0, waitForExit(mklink));

    host.uninstall(SAMPLE_APP_ID);

    assertTrue(Files.exists(externalFile));
    assertFalse(Files.exists(installation.paths().installedRoot()));
    assertFalse(Files.exists(installation.paths().dataDir()));
    assertFalse(Files.exists(installation.paths().cacheDir()));
    assertFalse(Files.exists(installation.paths().runDir()));
  }

  @Test
  void preserveRunningState_whenTrackedProcessAlreadyExited_expectEntryRemovedWithoutFailure()
      throws ReflectiveOperationException {
    LocalProcessAppHost host = host();
    RunningAppSnapshot snapshot = runningSnapshot(RUNNER_APP_ID);
    injectRunningProcess(host, RUNNER_APP_ID, snapshot, new ExitedProcess(snapshot.pid()));

    Object runningProcess = runnerProcessEntry(host);
    boolean preserved = invokePreserveRunnerState(host, runningProcess);

    assertFalse(preserved);
    assertTrue(host.status(RUNNER_APP_ID).isEmpty());
    assertTrue(host.listRunning().isEmpty());
  }

  private LocalProcessAppHost host() {
    return host(Duration.ofSeconds(1));
  }

  private LocalProcessAppHost host(Duration stopTimeout) {
    return host(stopTimeout, new AppEnv());
  }

  private LocalProcessAppHost host(Duration stopTimeout, AppEnv appEnv) {
    return new LocalProcessAppHost(
        new AppHostLayout(
            tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run")),
        stopTimeout,
        new java.security.SecureRandom(),
        appEnv,
        TEST_TIMING);
  }

  private LocalProcessAppHost host(
      Duration stopTimeout,
      AppEnv appEnv,
      LocalProcessAppHost.ManagedTreeDeleter managedTreeDeleter) {
    return new LocalProcessAppHost(
        new AppHostLayout(
            tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run")),
        stopTimeout,
        new java.security.SecureRandom(),
        appEnv,
        TEST_TIMING,
        managedTreeDeleter);
  }

  private Path stageInstalledApp(String appId) throws IOException {
    return stageInstalledApp(appId, scriptContent(new AppEnv()), Map.of());
  }

  private Path stageInstalledRunnerApp(String scriptContent) throws IOException {
    return stageInstalledApp(RUNNER_APP_ID, scriptContent, Map.of());
  }

  private Path stageInstalledApp(String appId, String scriptContent, Map<String, String> extraFiles)
      throws IOException {
    Path stagedDir = tempDir.resolve(STAGE_DIR_NAME).resolve(appId);
    return stageInstalledAppAt(stagedDir, appId, scriptContent, extraFiles);
  }

  private Path stageInstalledAppAt(
      Path stagedDir, String appId, String scriptContent, Map<String, String> extraFiles)
      throws IOException {
    return stageInstalledAppAt(stagedDir, appId, APP_VERSION, scriptContent, extraFiles);
  }

  private Path stageInstalledAppAt(
      Path stagedDir,
      String appId,
      String appVersion,
      String scriptContent,
      Map<String, String> extraFiles)
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Files.createDirectories(stagedDir);
    Path binDir = Files.createDirectories(stagedDir.resolve("bin"));
    String scriptName = scriptName(appEnv);
    Path scriptFile = binDir.resolve(scriptName);
    writeStageFile(scriptFile, scriptContent, appEnv);
    for (Map.Entry<String, String> extraFile : extraFiles.entrySet()) {
      writeStageFile(stagedDir.resolve(extraFile.getKey()), extraFile.getValue(), appEnv);
    }
    Files.writeString(stagedDir.resolve(CONTENT_FILE_NAME), "payload", StandardCharsets.UTF_8);
    Files.writeString(
        stagedDir.resolve(MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/%s
        app.ui.entry=/
        app.permissions=%s
        quota.data.bytes=4096
        quota.cache.bytes=1024
        """
            .formatted(
                appId, displayName(appId), appVersion, scriptName, STANDARD_PERMISSIONS_TEXT),
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private Path stageInstalledExecutableApp(
      String appId, String execRelativePath, String execContent, Map<String, String> extraFiles)
      throws IOException {
    return stageInstalledExecutableApp(appId, execRelativePath, execContent, extraFiles, true);
  }

  private Path stageInstalledExecutableApp(
      String appId,
      String execRelativePath,
      String execContent,
      Map<String, String> extraFiles,
      boolean executable)
      throws IOException {
    AppEnv appEnv = new AppEnv();
    Path stagedDir = Files.createDirectories(tempDir.resolve(STAGE_DIR_NAME).resolve(appId));
    writeExecutableStageFile(stagedDir.resolve(execRelativePath), execContent, appEnv, executable);
    for (Map.Entry<String, String> extraFile : extraFiles.entrySet()) {
      writeStageFile(stagedDir.resolve(extraFile.getKey()), extraFile.getValue(), appEnv);
    }
    Files.writeString(stagedDir.resolve(CONTENT_FILE_NAME), "payload", StandardCharsets.UTF_8);
    Files.writeString(
        stagedDir.resolve(MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=%s
        app.ui.entry=/
        app.permissions=%s
        quota.data.bytes=4096
        quota.cache.bytes=1024
        """
            .formatted(
                appId,
                displayName(appId),
                APP_VERSION,
                execRelativePath,
                STANDARD_PERMISSIONS_TEXT),
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private RunningAppSnapshot runningSnapshot(String appId) {
    AppManifest manifest =
        new AppManifest(
            1,
            appId,
            displayName(appId),
            APP_VERSION,
            "bin/" + scriptName(new AppEnv()),
            "/",
            STANDARD_PERMISSIONS,
            4096L,
            1024L);
    InstalledAppPaths paths =
        new AppHostLayout(
                tempDir.resolve("data"), tempDir.resolve(CACHE_DIR_NAME), tempDir.resolve("run"))
            .pathsFor(appId);
    return new RunningAppSnapshot(manifest, paths, DEFAULT_TOKEN, 42L, Instant.EPOCH);
  }

  @SuppressWarnings({"java:S3011"})
  private static void injectRunningProcess(
      LocalProcessAppHost host, String appId, RunningAppSnapshot snapshot, Process process)
      throws ReflectiveOperationException {
    injectRunningProcess(host, appId, snapshot, process, new CompletableFuture<>());
  }

  @SuppressWarnings({"unchecked", "java:S3011"})
  private static void injectRunningProcess(
      LocalProcessAppHost host,
      String appId,
      RunningAppSnapshot snapshot,
      Process process,
      CompletableFuture<Void> exitCleanup)
      throws ReflectiveOperationException {
    Field runningAppsField = LocalProcessAppHost.class.getDeclaredField("runningApps");
    runningAppsField.setAccessible(true);
    Map<String, Object> runningApps = (Map<String, Object>) runningAppsField.get(host);

    Class<?> runningProcessClass =
        Class.forName(LocalProcessAppHost.class.getName() + "$RunningProcess");
    Constructor<?> constructor =
        runningProcessClass.getDeclaredConstructor(
            Process.class, RunningAppSnapshot.class, CompletableFuture.class, List.class);
    constructor.setAccessible(true);
    Object runningProcess =
        constructor.newInstance(process, snapshot, exitCleanup, List.of(process.toHandle()));
    runningApps.put(appId, runningProcess);
  }

  @SuppressWarnings({"unchecked", "java:S3011"})
  private static Object runnerProcessEntry(LocalProcessAppHost host)
      throws ReflectiveOperationException {
    Field runningAppsField = LocalProcessAppHost.class.getDeclaredField("runningApps");
    runningAppsField.setAccessible(true);
    Map<String, Object> runningApps = (Map<String, Object>) runningAppsField.get(host);
    return runningApps.get(RUNNER_APP_ID);
  }

  @SuppressWarnings("java:S3011")
  private static boolean invokePreserveRunnerState(LocalProcessAppHost host, Object runningProcess)
      throws ReflectiveOperationException {
    Class<?> runningProcessClass =
        Class.forName(LocalProcessAppHost.class.getName() + "$RunningProcess");
    Method preserveRunningState =
        LocalProcessAppHost.class.getDeclaredMethod(
            "preserveRunningState", String.class, runningProcessClass);
    preserveRunningState.setAccessible(true);
    return (boolean) preserveRunningState.invoke(host, RUNNER_APP_ID, runningProcess);
  }

  private static void invokeParseRunnerTokenTrackedProcesses(Process process)
      throws ReflectiveOperationException, IOException {
    MethodHandle parseTokenTrackedProcesses =
        MethodHandles.privateLookupIn(LocalProcessAppHost.class, MethodHandles.lookup())
            .findStatic(
                LocalProcessAppHost.class,
                "parseTokenTrackedProcesses",
                MethodType.methodType(List.class, Process.class, String.class, String.class));
    try {
      parseTokenTrackedProcesses.invoke(process, DEFAULT_TOKEN, RUNNER_APP_ID);
    } catch (Throwable throwable) {
      switch (throwable) {
        case IOException ioException -> throw ioException;
        case RuntimeException runtimeException -> throw runtimeException;
        case Error error -> throw error;
        case ReflectiveOperationException reflectiveOperationException ->
            throw reflectiveOperationException;
        default -> {
          // do nothing
        }
      }
      throw new ReflectiveOperationException(
          "failed to invoke parseTokenTrackedProcesses", throwable);
    }
  }

  private static void writeStageFile(Path file, String content, AppEnv appEnv) throws IOException {
    Files.createDirectories(parentOrThrow(file));
    Files.writeString(file, content, StandardCharsets.UTF_8);
    if (!appEnv.isWindows() && fileNameOrThrow(file).endsWith(".sh")) {
      assertTrue(file.toFile().setExecutable(true, false));
    }
  }

  private static void writeExecutableStageFile(
      Path file, String content, AppEnv appEnv, boolean executable) throws IOException {
    Files.createDirectories(parentOrThrow(file));
    Files.writeString(file, content, StandardCharsets.UTF_8);
    if (!appEnv.isWindows()) {
      assertTrue(file.toFile().setExecutable(executable, false));
    }
  }

  private static Path parentOrThrow(Path path) {
    Path parent = path.getParent();
    if (parent == null) {
      throw new AssertionError("Expected parent for path " + path);
    }
    return parent;
  }

  private static String fileNameOrThrow(Path path) {
    Path fileName = path.getFileName();
    if (fileName == null) {
      throw new AssertionError("Expected file name for path " + path);
    }
    return fileName.toString();
  }

  private static String displayName(String appId) {
    return switch (appId) {
      case RUNNER_APP_ID -> "Runner App";
      case SAMPLE_APP_ID -> "Sample App";
      case MIXED_CASE_APP_ID -> "Mixed Case App";
      default -> "Duplicate App";
    };
  }

  private static String scriptName(AppEnv appEnv) {
    return appEnv.isWindows() ? "launch.cmd" : "launch.sh";
  }

  private static String scriptContent(AppEnv appEnv) {
    if (appEnv.isWindows()) {
      return """
      @echo off
      setlocal EnableExtensions
      set > "%CRYPTAD_APP_RUN_DIR%\\captured-env.txt"
      :loop
      timeout /t 1 /nobreak >nul
      goto loop
      """;
    }
    return """
    #!/bin/sh
    set -eu
    env > "$CRYPTAD_APP_RUN_DIR/captured-env.txt"
    while :; do
      sleep %s
    done
    """
        .formatted(TEST_LOOP_SLEEP_SECONDS);
  }

  private static String secondsLiteral(Duration duration) {
    return String.format(java.util.Locale.ROOT, "%.3f", duration.toNanos() / 1_000_000_000.0d);
  }

  private static String immediateExitScriptContent(AppEnv appEnv) {
    if (appEnv.isWindows()) {
      return """
      @echo off
      exit /b 0
      """;
    }
    return """
    #!/bin/sh
    exit 0
    """;
  }

  private static void assertCapturedEnvironment(
      InstalledAppSnapshot installation, RunningAppSnapshot running, String capture) {
    assertTrue(capture.contains("CRYPTAD_APP_ID=" + RUNNER_APP_ID));
    assertTrue(capture.contains("CRYPTAD_APP_NAME=Runner App"));
    assertTrue(capture.contains("CRYPTAD_APP_VERSION=" + APP_VERSION));
    assertTrue(capture.contains("CRYPTAD_APP_DATA_DIR=" + installation.paths().dataDir()));
    assertTrue(capture.contains("CRYPTAD_APP_CACHE_DIR=" + installation.paths().cacheDir()));
    assertTrue(capture.contains("CRYPTAD_APP_RUN_DIR=" + installation.paths().runDir()));
    assertTrue(capture.contains("CRYPTAD_APP_TOKEN=" + running.token()));
    assertTrue(capture.contains("CRYPTAD_APP_PERMISSIONS=" + STANDARD_PERMISSIONS_TEXT));
    assertTrue(capture.contains("CRYPTAD_APP_UI_ENTRY=/"));
  }

  private static void assertInstallationPathsRemoved(InstalledAppSnapshot installation) {
    assertFalse(Files.exists(installation.paths().installedRoot()));
    assertFalse(Files.exists(installation.paths().dataDir()));
    assertFalse(Files.exists(installation.paths().cacheDir()));
    assertFalse(Files.exists(installation.paths().runDir()));
  }

  private static AppHostException installExpectingAppHostException(AppHost host, Path stagedApp)
      throws Exception {
    //noinspection resource
    ExecutorService executor =
        Executors.newSingleThreadExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "apphost-install-test");
              thread.setDaemon(true);
              return thread;
            });
    try {
      ExecutionException exception =
          installFailure(executor.submit(() -> host.installFromDirectory(stagedApp)), stagedApp);
      assertInstanceOf(AppHostException.class, exception.getCause());
      return (AppHostException) exception.getCause();
    } catch (TimeoutException e) {
      throw new AssertionError("installFromDirectory hung on named pipe: " + stagedApp, e);
    } finally {
      executor.shutdownNow();
    }
  }

  private static ExecutionException installFailure(
      java.util.concurrent.Future<InstalledAppSnapshot> installFuture, Path stagedApp)
      throws InterruptedException, TimeoutException {
    try {
      installFuture.get(5, TimeUnit.SECONDS);
      throw new AssertionError("expected installFromDirectory() to fail for " + stagedApp);
    } catch (ExecutionException e) {
      return e;
    }
  }

  private static int waitForExit(Process process) throws IOException, InterruptedException {
    if (!process.waitFor(5, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      throw new IOException("timed out waiting for process to exit: " + process.pid());
    }
    return process.exitValue();
  }

  private static RunningAppSnapshot waitForRunningApp(AppHost host, String appId) {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      Optional<RunningAppSnapshot> running = host.status(appId);
      if (running.isPresent()) {
        return running.orElseThrow();
      }
      pausePolling("interrupted while waiting for app to be running: " + appId);
    }
    throw new AssertionError("timed out waiting for app to be running: " + appId);
  }

  private static void waitForNotRunning(AppHost host) {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      if (host.status(RUNNER_APP_ID).isEmpty()
          && host.listRunning().stream().noneMatch(app -> RUNNER_APP_ID.equals(app.appId()))) {
        return;
      }
      pausePolling("interrupted while waiting for app to stop running: " + RUNNER_APP_ID);
    }
    throw new AssertionError("timed out waiting for app to stop running: " + RUNNER_APP_ID);
  }

  private static RunningAppSnapshot waitForRunningPid(AppHost host, long pid) {
    return waitForRunningPid(host, RUNNER_APP_ID, pid);
  }

  private static RunningAppSnapshot waitForRunningPid(AppHost host, String appId, long pid) {
    long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    while (System.nanoTime() < deadline) {
      Optional<RunningAppSnapshot> running = host.status(appId);
      if (running.isPresent() && running.orElseThrow().pid() == pid) {
        return running.orElseThrow();
      }
      pausePolling("interrupted while waiting for app " + appId + " to report pid " + pid);
    }
    throw new AssertionError("timed out waiting for app " + appId + " to report pid " + pid);
  }

  private static void waitForProcessExit(long pid) throws IOException {
    ProcessHandle handle = ProcessHandle.of(pid).orElse(null);
    if (handle == null || !isEffectivelyAlive(handle)) {
      return;
    }
    try {
      handle.onExit().get(5, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("interrupted while waiting for process " + pid + " to exit", e);
    } catch (ExecutionException e) {
      throw new IOException("failed while waiting for process " + pid + " to exit", e);
    } catch (TimeoutException e) {
      throw new AssertionError("timed out waiting for child process " + pid + " to exit", e);
    }
  }

  private static boolean isEffectivelyAlive(ProcessHandle handle) {
    return handle.isAlive() && !isZombieProcess(handle);
  }

  private static boolean isZombieProcess(ProcessHandle handle) {
    Path statFile = Path.of("/proc", Long.toString(handle.pid()), "stat");
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

  private static void pausePolling(String interruptMessage) {
    LockSupport.parkNanos(POLL_INTERVAL_NANOS);
    if (Thread.interrupted()) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interruptMessage, new InterruptedException(interruptMessage));
    }
  }

  private static String resolveTrustedMkfifoCommand() {
    for (Path trustedDir :
        List.of(Path.of("/usr/bin"), Path.of("/bin"), Path.of("/usr/sbin"), Path.of("/sbin"))) {
      Path candidate = trustedDir.resolve(MKFIFO_COMMAND);
      if (Files.isExecutable(candidate)) {
        return candidate.toString();
      }
    }
    throw new AssertionError("trusted command not found: " + MKFIFO_COMMAND);
  }

  private static String windowsCommandInterpreter() {
    String comSpec = System.getenv("ComSpec");
    return comSpec != null && !comSpec.isBlank() ? comSpec : "cmd.exe";
  }

  private static void waitForFile(Path file) throws IOException {
    if (Files.isRegularFile(file)) {
      return;
    }

    Path parent = file.getParent();
    if (parent == null) {
      throw new AssertionError("file has no parent: " + file);
    }

    long timeoutMillis = Duration.ofSeconds(10).toMillis();
    try (WatchService watchService = parent.getFileSystem().newWatchService()) {
      parent.register(
          watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
      long deadline = System.nanoTime() + Duration.ofMillis(timeoutMillis).toNanos();
      while (System.nanoTime() < deadline) {
        WatchKey key = pollWatchKey(watchService, deadline, file);
        if (Files.isRegularFile(file)) {
          return;
        }
        if (key != null) {
          if (isWatchedFilePresent(file, key)) {
            return;
          }
          if (!key.reset()) {
            throw new AssertionError("watch service closed before " + file + " appeared");
          }
        }
      }
      if (Files.isRegularFile(file)) {
        return;
      }
    }
    throw new AssertionError("timed out waiting for " + file);
  }

  private static long waitForPidFileValue(Path file) throws IOException {
    ObservedPid observedPid = tryReadPidFileValue(file);
    if (observedPid.pid() != null) {
      return observedPid.pid();
    }

    Path parent = file.getParent();
    if (parent == null) {
      throw new AssertionError("file has no parent: " + file);
    }

    long timeoutMillis = Duration.ofSeconds(10).toMillis();
    try (WatchService watchService = parent.getFileSystem().newWatchService()) {
      parent.register(
          watchService, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_MODIFY);
      long deadline = System.nanoTime() + Duration.ofMillis(timeoutMillis).toNanos();
      while (System.nanoTime() < deadline) {
        WatchKey key = pollWatchKey(watchService, deadline, file);
        observedPid = tryReadPidFileValue(file);
        if (observedPid.pid() != null) {
          return observedPid.pid();
        }
        if (key != null && !key.reset()) {
          throw new AssertionError("watch service closed before " + file + " became readable");
        }
      }
    }

    observedPid = tryReadPidFileValue(file);
    if (observedPid.pid() != null) {
      return observedPid.pid();
    }

    throw new AssertionError(
        "timed out waiting for numeric pid in "
            + file
            + (observedPid.contents() == null
                ? ""
                : "; last observed contents: '" + observedPid.contents() + "'"));
  }

  private static ObservedPid tryReadPidFileValue(Path file) throws IOException {
    if (!Files.isRegularFile(file)) {
      return new ObservedPid(null, null);
    }

    String contents = Files.readString(file, StandardCharsets.UTF_8).trim();
    if (contents.isEmpty()) {
      return new ObservedPid(null, contents);
    }

    try {
      return new ObservedPid(Long.parseLong(contents), contents);
    } catch (NumberFormatException e) {
      return new ObservedPid(null, contents);
    }
  }

  private static WatchKey pollWatchKey(WatchService watchService, long deadline, Path file)
      throws IOException {
    long remainingNanos = deadline - System.nanoTime();
    if (remainingNanos <= 0L) {
      return null;
    }
    try {
      return watchService.poll(remainingNanos, TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("interrupted while waiting for " + file, e);
    }
  }

  private static boolean isWatchedFilePresent(Path file, WatchKey key) {
    for (WatchEvent<?> event : key.pollEvents()) {
      if (event.context() instanceof Path changed
          && changed.equals(file.getFileName())
          && Files.isRegularFile(file)) {
        return true;
      }
    }
    return false;
  }

  private record ObservedPid(@Nullable Long pid, @Nullable String contents) {}

  private static final class LateChildSpawningProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;
    private final ProcessHandle childHandle;
    private boolean rootAlive = true;
    private boolean childSpawned;

    private LateChildSpawningProcess(long pid, long childPid) {
      this.pid = pid;
      this.handle = new LateChildSpawningProcessHandle();
      this.childHandle = new LinkedProcessHandle(childPid, handle, true);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return !rootAlive;
    }

    @Override
    public int exitValue() {
      if (rootAlive) {
        throw new IllegalThreadStateException("process is still running");
      }
      return 0;
    }

    @Override
    public void destroy() {
      childSpawned = true;
      rootAlive = false;
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return rootAlive;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }

    private final class LateChildSpawningProcessHandle implements ProcessHandle {
      @Override
      public long pid() {
        return pid;
      }

      @Override
      public Info info() {
        return new Info() {
          @Override
          public Optional<String> command() {
            return Optional.empty();
          }

          @Override
          public Optional<String> commandLine() {
            return Optional.empty();
          }

          @Override
          public Optional<String[]> arguments() {
            return Optional.empty();
          }

          @Override
          public Optional<Instant> startInstant() {
            return Optional.empty();
          }

          @Override
          public Optional<Duration> totalCpuDuration() {
            return Optional.empty();
          }

          @Override
          public Optional<String> user() {
            return Optional.empty();
          }
        };
      }

      @Override
      public CompletableFuture<ProcessHandle> onExit() {
        return rootAlive ? new CompletableFuture<>() : CompletableFuture.completedFuture(this);
      }

      @Override
      public boolean supportsNormalTermination() {
        return true;
      }

      @Override
      public boolean destroy() {
        LateChildSpawningProcess.this.destroy();
        return true;
      }

      @Override
      public boolean destroyForcibly() {
        return destroy();
      }

      @Override
      public boolean isAlive() {
        return rootAlive;
      }

      @Override
      public Optional<ProcessHandle> parent() {
        return Optional.empty();
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> children() {
        return childSpawned
            ? java.util.stream.Stream.of(childHandle)
            : java.util.stream.Stream.empty();
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> descendants() {
        return children();
      }

      @Override
      public int compareTo(ProcessHandle other) {
        return Long.compare(pid, other.pid());
      }

      @Override
      public boolean equals(Object other) {
        return other instanceof ProcessHandle otherHandle && pid == otherHandle.pid();
      }

      @Override
      public int hashCode() {
        return Long.hashCode(pid);
      }
    }
  }

  private static final class LateRecoveredChildProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;
    private boolean rootAlive = true;

    private LateRecoveredChildProcess(long pid, long childPid, int childAliveChecksBeforeExit) {
      this.pid = pid;
      this.handle = new LateRecoveredChildProcessHandle(childPid, childAliveChecksBeforeExit);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return !rootAlive;
    }

    @Override
    public int exitValue() {
      if (rootAlive) {
        throw new IllegalThreadStateException("process is still running");
      }
      return 0;
    }

    @Override
    public void destroy() {
      rootAlive = false;
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return rootAlive;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }

    private final class LateRecoveredChildProcessHandle implements ProcessHandle {
      private final ProcessHandle childHandle;
      private final AtomicInteger deferredChildVisibilityChecks = new AtomicInteger(1);

      private LateRecoveredChildProcessHandle(long childPid, int childAliveChecksBeforeExit) {
        this.childHandle = new FadingProcessHandle(childPid, childAliveChecksBeforeExit);
      }

      @Override
      public long pid() {
        return pid;
      }

      @Override
      public Info info() {
        return new Info() {
          @Override
          public Optional<String> command() {
            return Optional.empty();
          }

          @Override
          public Optional<String> commandLine() {
            return Optional.empty();
          }

          @Override
          public Optional<String[]> arguments() {
            return Optional.empty();
          }

          @Override
          public Optional<Instant> startInstant() {
            return Optional.empty();
          }

          @Override
          public Optional<Duration> totalCpuDuration() {
            return Optional.empty();
          }

          @Override
          public Optional<String> user() {
            return Optional.empty();
          }
        };
      }

      @Override
      public CompletableFuture<ProcessHandle> onExit() {
        return rootAlive ? new CompletableFuture<>() : CompletableFuture.completedFuture(this);
      }

      @Override
      public boolean supportsNormalTermination() {
        return true;
      }

      @Override
      public boolean destroy() {
        LateRecoveredChildProcess.this.destroy();
        return true;
      }

      @Override
      public boolean destroyForcibly() {
        return destroy();
      }

      @Override
      public boolean isAlive() {
        return rootAlive;
      }

      @Override
      public Optional<ProcessHandle> parent() {
        return Optional.empty();
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> children() {
        if (rootAlive) {
          return java.util.stream.Stream.empty();
        }
        int checksRemaining =
            deferredChildVisibilityChecks.getAndUpdate(current -> Math.max(0, current - 1));
        if (checksRemaining > 0) {
          return java.util.stream.Stream.empty();
        }
        return java.util.stream.Stream.of(childHandle);
      }

      @Override
      public java.util.stream.Stream<ProcessHandle> descendants() {
        return children();
      }

      @Override
      public int compareTo(ProcessHandle other) {
        return Long.compare(pid, other.pid());
      }

      @Override
      public boolean equals(Object other) {
        return other instanceof ProcessHandle otherHandle && pid == otherHandle.pid();
      }

      @Override
      public int hashCode() {
        return Long.hashCode(pid);
      }
    }
  }

  private static final class NonStoppingProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;

    private NonStoppingProcess(long pid) {
      this.pid = pid;
      this.handle = new NonStoppingProcessHandle(pid);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      throw new UnsupportedOperationException("waitFor() not used by this test");
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return false;
    }

    @Override
    public int exitValue() {
      throw new IllegalThreadStateException("process is still running");
    }

    @Override
    public void destroy() {
      // Intentionally blank: this fake process ignores graceful termination so stop() times out.
    }

    @Override
    public Process destroyForcibly() {
      destroy();
      return this;
    }

    @Override
    public boolean isAlive() {
      return true;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }
  }

  private record NonStoppingProcessHandle(long pid) implements ProcessHandle {
    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return new CompletableFuture<>();
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return false;
    }

    @Override
    public boolean destroyForcibly() {
      return false;
    }

    @Override
    public boolean isAlive() {
      return true;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  private static final class ExitedProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;

    private ExitedProcess(long pid) {
      this.pid = pid;
      this.handle = new ExitedProcessHandle(pid);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return true;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      // Intentionally blank: this fake process already exits.
    }

    @Override
    public Process destroyForcibly() {
      return this;
    }

    @Override
    public boolean isAlive() {
      return false;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }
  }

  private static final class FadingProcess extends Process {
    private final long pid;
    private final ProcessHandle handle;

    private FadingProcess(long pid, int aliveChecksBeforeExit) {
      this.pid = pid;
      this.handle = new FadingProcessHandle(pid, aliveChecksBeforeExit);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return !handle.isAlive();
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      // Intentionally blank: the handle simulates lifecycle.
    }

    @Override
    public Process destroyForcibly() {
      return this;
    }

    @Override
    public boolean isAlive() {
      return handle.isAlive();
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public ProcessHandle toHandle() {
      return handle;
    }
  }

  private static final class FailingInputProcess extends Process {
    private final InputStream inputStream;

    private FailingInputProcess(byte[] prefixBytes) {
      this.inputStream = new FailingInputStream(prefixBytes);
    }

    @Override
    public OutputStream getOutputStream() {
      return OutputStream.nullOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return inputStream;
    }

    @Override
    public InputStream getErrorStream() {
      return InputStream.nullInputStream();
    }

    @Override
    public int waitFor() {
      return 0;
    }

    @Override
    public boolean waitFor(long timeout, TimeUnit unit) {
      return true;
    }

    @Override
    public int exitValue() {
      return 0;
    }

    @Override
    public void destroy() {
      // Intentionally blank: this fake process exists only to expose a failing input stream.
    }

    @Override
    public Process destroyForcibly() {
      return this;
    }

    @Override
    public boolean isAlive() {
      return false;
    }

    @Override
    public long pid() {
      return 0L;
    }

    @Override
    public ProcessHandle toHandle() {
      return new ExitedProcessHandle(0L);
    }
  }

  private static final class FailingInputStream extends InputStream {
    private final byte[] prefixBytes;
    private int offset;

    private FailingInputStream(byte[] prefixBytes) {
      this.prefixBytes = prefixBytes;
    }

    @Override
    public int read() throws IOException {
      if (offset < prefixBytes.length) {
        return prefixBytes[offset++] & 0xFF;
      }
      throw new IOException("simulated ps stream failure");
    }

    @Override
    public int read(byte @NonNull [] buffer, int off, int len) throws IOException {
      if (offset < prefixBytes.length) {
        int bytesToCopy = Math.min(len, prefixBytes.length - offset);
        System.arraycopy(prefixBytes, offset, buffer, off, bytesToCopy);
        offset += bytesToCopy;
        return bytesToCopy;
      }
      throw new IOException("simulated ps stream failure");
    }
  }

  private static final class LinkedProcessHandle implements ProcessHandle {
    private final long pid;
    private final ProcessHandle parent;
    private final boolean alive;

    private LinkedProcessHandle(long pid, ProcessHandle parent, boolean alive) {
      this.pid = pid;
      this.parent = parent;
      this.alive = alive;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return false;
    }

    @Override
    public boolean destroyForcibly() {
      return false;
    }

    @Override
    public boolean isAlive() {
      return alive;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.ofNullable(parent);
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  private static final class InfoProcessHandle implements ProcessHandle {
    private final long pid;
    private final ProcessHandle parent;
    private final boolean alive;
    private final @Nullable String command;
    private final @Nullable String commandLine;
    private final @Nullable Instant startInstant;

    private InfoProcessHandle(
        long pid,
        ProcessHandle parent,
        boolean alive,
        @Nullable String command,
        @Nullable String commandLine,
        @Nullable Instant startInstant) {
      this.pid = pid;
      this.parent = parent;
      this.alive = alive;
      this.command = command;
      this.commandLine = commandLine;
      this.startInstant = startInstant;
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public Info info() {
      return new Info() {
        @Override
        public Optional<String> command() {
          return Optional.ofNullable(command);
        }

        @Override
        public Optional<String> commandLine() {
          return Optional.ofNullable(commandLine);
        }

        @Override
        public Optional<String[]> arguments() {
          return Optional.empty();
        }

        @Override
        public Optional<Instant> startInstant() {
          return Optional.ofNullable(startInstant);
        }

        @Override
        public Optional<Duration> totalCpuDuration() {
          return Optional.empty();
        }

        @Override
        public Optional<String> user() {
          return Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return false;
    }

    @Override
    public boolean destroyForcibly() {
      return false;
    }

    @Override
    public boolean isAlive() {
      return alive;
    }

    @Override
    public Optional<ProcessHandle> parent() {
      return Optional.ofNullable(parent);
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class FadingProcessHandle implements ProcessHandle {
    private final long pid;
    private final AtomicInteger remainingAliveChecks;

    private FadingProcessHandle(long pid, int aliveChecksBeforeExit) {
      this.pid = pid;
      this.remainingAliveChecks = new AtomicInteger(aliveChecksBeforeExit);
    }

    @Override
    public long pid() {
      return pid;
    }

    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return true;
    }

    @Override
    public boolean destroyForcibly() {
      return true;
    }

    @Override
    public boolean isAlive() {
      int checksRemaining = remainingAliveChecks.getAndUpdate(current -> Math.max(0, current - 1));
      return checksRemaining > 0;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof ProcessHandle handle && pid == handle.pid();
    }

    @Override
    public int hashCode() {
      return Long.hashCode(pid);
    }
  }

  private record ExitedProcessHandle(long pid) implements ProcessHandle {
    @Override
    public Info info() {
      return new Info() {
        @Override
        public java.util.Optional<String> command() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> commandLine() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String[]> arguments() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Instant> startInstant() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<Duration> totalCpuDuration() {
          return java.util.Optional.empty();
        }

        @Override
        public java.util.Optional<String> user() {
          return java.util.Optional.empty();
        }
      };
    }

    @Override
    public CompletableFuture<ProcessHandle> onExit() {
      return CompletableFuture.completedFuture(this);
    }

    @Override
    public boolean supportsNormalTermination() {
      return true;
    }

    @Override
    public boolean destroy() {
      return true;
    }

    @Override
    public boolean destroyForcibly() {
      return true;
    }

    @Override
    public boolean isAlive() {
      return false;
    }

    @Override
    public java.util.Optional<ProcessHandle> parent() {
      return java.util.Optional.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> children() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public java.util.stream.Stream<ProcessHandle> descendants() {
      return java.util.stream.Stream.empty();
    }

    @Override
    public int compareTo(ProcessHandle other) {
      return Long.compare(pid, other.pid());
    }
  }
}
