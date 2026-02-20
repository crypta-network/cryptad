package network.crypta.fs;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static java.nio.file.Files.createTempDirectory;
import static java.nio.file.Files.deleteIfExists;
import static java.nio.file.Files.exists;
import static java.nio.file.Files.write;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SuppressWarnings("java:S100") // Enforce method_whenCondition_expectOutcome naming for tests.
class AppEnvTest {

  @Test
  void isDocker_whenCryptadDockerOverrideSet_expectTrue() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    env.put("CRYPTAD_DOCKER", "1");
    AppEnv ae = new AppEnv(env, "Linux", "tester", _ -> null);

    // Act
    boolean isDocker = ae.isDocker();

    // Assert
    assertTrue(isDocker);
  }

  @Test
  void isDocker_whenNonLinux_expectFalse() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Mac OS X", "tester", Path::toString);

    // Act
    boolean isDocker = ae.isDocker();

    // Assert
    assertFalse(isDocker);
  }

  @Test
  void osKind_whenDifferentOsNames_expectCorrectFamilies() {
    // Arrange
    AppEnv win = new AppEnv(new HashMap<>(), "Windows 11", "u", _ -> null);
    AppEnv mac = new AppEnv(new HashMap<>(), "Mac OS X", "u", _ -> null);
    AppEnv lin = new AppEnv(new HashMap<>(), "Linux", "u", _ -> null);

    // Act
    boolean winDetected = win.isWindows();
    boolean macDetected = mac.isMac();
    boolean linDetected = lin.isLinux();
    AppEnv.OsKind winKind = win.osKind();
    AppEnv.OsKind macKind = mac.osKind();
    AppEnv.OsKind linKind = lin.osKind();

    // Assert
    assertTrue(winDetected);
    assertTrue(macDetected);
    assertTrue(linDetected);
    assertEquals(AppEnv.OsKind.WINDOWS, winKind);
    assertEquals(AppEnv.OsKind.MAC, macKind);
    assertEquals(AppEnv.OsKind.LINUX, linKind);
  }

  @Test
  void isFlatpakAndIsSnap_whenMarkersPresent_expectTrue() {
    // Arrange
    Map<String, String> flatpakEnv = new HashMap<>();
    flatpakEnv.put("FLATPAK_ID", "network.crypta.Cryptad");
    AppEnv flatpakAppEnv = new AppEnv(flatpakEnv, "Linux", "u", _ -> null);

    Map<String, String> snapEnv = new HashMap<>();
    snapEnv.put("SNAP", "1");
    AppEnv snapAppEnv = new AppEnv(snapEnv, "Linux", "u", _ -> null);

    // Act
    boolean flatpakDetected = flatpakAppEnv.isFlatpak();
    boolean snapDetected = snapAppEnv.isSnap();

    // Assert
    assertTrue(flatpakDetected);
    assertTrue(snapDetected);
  }

  @Test
  void isSystemdServiceAndServiceMode_whenSystemdDirectoriesExported_expectTrue() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    env.put("LOGS_DIRECTORY", "/var/log/cryptad");
    AppEnv ae = new AppEnv(env, "Linux", "cryptad", _ -> null);

    // Act
    boolean systemdService = ae.isSystemdService();
    boolean serviceMode = ae.isServiceMode();

    // Assert
    assertTrue(systemdService);
    assertTrue(serviceMode);
  }

  @Test
  void isWindowsServiceAndServiceMode_whenSystemUser_expectTrue() {
    // Arrange
    Map<String, String> env = new HashMap<>();
    env.put("USERNAME", "SYSTEM");
    AppEnv ae = new AppEnv(env, "Windows 10", "SYSTEM", _ -> null);

    // Act
    boolean windowsService = ae.isWindowsService();
    boolean serviceMode = ae.isServiceMode();

    // Assert
    assertTrue(windowsService);
    assertTrue(serviceMode);
  }

  @Test
  void isMacService_whenRootOrLaunchd_expectTrue() {
    // Arrange
    Map<String, String> rootEnv = new HashMap<>();
    AppEnv rootMac = new AppEnv(rootEnv, "Mac OS X", "root", _ -> null);

    Map<String, String> launchdEnv = new HashMap<>();
    launchdEnv.put("LAUNCHD_JOB", "network.crypta.cryptad");
    AppEnv launchdMac = new AppEnv(launchdEnv, "Mac OS X", "user", _ -> null);

    // Act
    boolean rootDetected = rootMac.isMacService();
    boolean launchdDetected = launchdMac.isMacService();

    // Assert
    assertTrue(rootDetected);
    assertTrue(launchdDetected);
  }

  @Test
  void isServiceMode_whenPropertyOverrideSet_expectOverrideWins() {
    // Arrange
    String old = System.getProperty("cryptad.service.mode");
    try {
      Map<String, String> env = new HashMap<>();
      env.put("CRYPTAD_SERVICE", "1");
      AppEnv ae = new AppEnv(env, "Linux", "u", _ -> null);

      // Act
      System.setProperty("cryptad.service.mode", "user");
      boolean forcedUserMode = ae.isServiceMode();
      System.setProperty("cryptad.service.mode", "service");
      boolean forcedServiceMode = ae.isServiceMode();

      // Assert
      assertFalse(forcedUserMode, "system property should force user mode");
      assertTrue(forcedServiceMode, "system property should force service mode");
    } finally {
      if (old != null) {
        System.setProperty("cryptad.service.mode", old);
      } else {
        System.clearProperty("cryptad.service.mode");
      }
    }
  }

  @Test
  void arch_whenOsArchVaries_expectNormalizedValue() {
    // Arrange
    String old = System.getProperty("os.arch");
    try {
      // Act
      System.setProperty("os.arch", "aarch64");
      String arm64 = new AppEnv(new HashMap<>(), "Linux", "u", _ -> null).arch();
      System.setProperty("os.arch", "x86_64");
      String amd64 = new AppEnv(new HashMap<>(), "Linux", "u", _ -> null).arch();

      // Assert
      assertEquals("arm64", arm64);
      assertEquals("amd64", amd64);
    } finally {
      if (old != null) {
        System.setProperty("os.arch", old);
      } else {
        System.clearProperty("os.arch");
      }
    }
  }

  @Test
  void availableManagersAndOnPath_whenLinuxPathContainsExecutables_expectDetected()
      throws Exception {
    // Arrange
    Path tmp = createTempDirectory("aptenv");
    try {
      File rpm = tmp.resolve("rpm").toFile();
      File flatpak = tmp.resolve("flatpak").toFile();
      write(
          rpm.toPath(),
          new byte[] {0},
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING);
      write(
          flatpak.toPath(),
          new byte[] {0},
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING);
      boolean rpmExec = rpm.setExecutable(true);
      boolean flatpakExec = flatpak.setExecutable(true);
      Map<String, String> env = new HashMap<>();
      env.put("PATH", tmp.toString());
      AppEnv ae = new AppEnv(env, "Linux", "u", _ -> null);

      // Act
      boolean rpmOnPath = ae.onPath("rpm");
      boolean flatpakOnPath = ae.onPath("flatpak");
      boolean rpmManagerDetected = ae.availableManagers().contains("rpm");
      boolean flatpakManagerDetected = ae.availableManagers().contains("flatpak");

      // Assert
      assertTrue(rpmExec || rpm.canExecute(), "Failed to mark rpm test binary executable");
      assertTrue(
          flatpakExec || flatpak.canExecute(), "Failed to mark flatpak test binary executable");
      assertTrue(rpmOnPath);
      assertTrue(flatpakOnPath);
      assertTrue(rpmManagerDetected);
      assertTrue(flatpakManagerDetected);
    } finally {
      try {
        deleteIfExists(tmp.resolve("rpm"));
      } catch (Exception _) {
        /* best-effort cleanup; ignore */
      }
      try {
        deleteIfExists(tmp.resolve("flatpak"));
      } catch (Exception _) {
        /* best-effort cleanup; ignore */
      }
      try {
        deleteIfExists(tmp);
      } catch (Exception _) {
        /* best-effort cleanup; ignore */
      }
    }
  }

  @Test
  void detectEnvironment_whenLinuxArmAndFlatpakOnPath_expectConsistentSummary() throws Exception {
    // Arrange
    String oldArch = System.getProperty("os.arch");
    try {
      System.setProperty("os.arch", "aarch64");
      Path tmp = createTempDirectory("aptenv2");
      try {
        File flatpak = tmp.resolve("flatpak").toFile();
        write(
            flatpak.toPath(),
            new byte[] {0},
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING);
        boolean executable = flatpak.setExecutable(true);
        Map<String, String> env = new HashMap<>();
        env.put("PATH", tmp.toString());
        AppEnv ae = new AppEnv(env, "Linux", "u", _ -> null);

        // Act
        AppEnv.EnvDetection det = ae.detectEnvironment();

        // Assert
        assertTrue(
            executable || flatpak.canExecute(), "Failed to mark flatpak test binary executable");
        assertEquals(AppEnv.OsKind.LINUX, det.getOs());
        assertEquals("arm64", det.getArch());
        assertTrue(det.getAvailableManagers().contains("flatpak"));
      } finally {
        try {
          deleteIfExists(tmp.resolve("flatpak"));
        } catch (Exception _) {
          /* best-effort cleanup; ignore */
        }
        try {
          deleteIfExists(tmp);
        } catch (Exception _) {
          /* best-effort cleanup; ignore */
        }
      }
    } finally {
      if (oldArch != null) {
        System.setProperty("os.arch", oldArch);
      } else {
        System.clearProperty("os.arch");
      }
    }
  }

  @Test
  void isDocker_whenCgroupContainsDockerMarker_expectTrue() {
    // Arrange
    assumeTrue(
        exists(Path.of("/proc/1/cgroup")), "Skipping cgroup-based docker test on non-Linux host");
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Linux", "tester", _ -> "12:devices:/docker/abcdef\n");

    // Act
    boolean isDocker = ae.isDocker();

    // Assert
    assertTrue(isDocker);
  }

  @Test
  void osNameRawAndOsVersionRaw_whenPropertiesSet_expectValuesReturned() {
    // Arrange
    String old = System.getProperty("os.version");
    try {
      System.setProperty("os.version", "13.3.1");
      AppEnv ae = new AppEnv(new HashMap<>(), "Mac OS X", "u", _ -> null);

      // Act
      String osNameRaw = ae.osNameRaw();
      String osVersionRaw = ae.osVersionRaw();

      // Assert
      assertEquals("Mac OS X", osNameRaw);
      assertEquals("13.3.1", osVersionRaw);
    } finally {
      if (old != null) {
        System.setProperty("os.version", old);
      } else {
        System.clearProperty("os.version");
      }
    }
  }
}
