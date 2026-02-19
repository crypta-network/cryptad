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

public class AppEnvTest {

  @Test
  public void dockerEnvOverride_isTrue() {
    Map<String, String> env = new HashMap<>();
    env.put("CRYPTAD_DOCKER", "1");
    AppEnv ae = new AppEnv(env, "Linux", "tester", p -> null);
    assertTrue(ae.isDocker());
  }

  @Test
  public void nonLinux_isDockerFalse() {
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Mac OS X", "tester", Path::toString);
    assertFalse(ae.isDocker());
  }

  @Test
  public void osKind_basicFamilies() {
    AppEnv win = new AppEnv(new HashMap<>(), "Windows 11", "u", p -> null);
    AppEnv mac = new AppEnv(new HashMap<>(), "Mac OS X", "u", p -> null);
    AppEnv lin = new AppEnv(new HashMap<>(), "Linux", "u", p -> null);
    assertTrue(win.isWindows());
    assertTrue(mac.isMac());
    assertTrue(lin.isLinux());
    assertEquals(AppEnv.OsKind.WINDOWS, win.osKind());
    assertEquals(AppEnv.OsKind.MAC, mac.osKind());
    assertEquals(AppEnv.OsKind.LINUX, lin.osKind());
  }

  @Test
  public void flatpak_snap_detection() {
    Map<String, String> env = new HashMap<>();
    env.put("FLATPAK_ID", "network.crypta.Cryptad");
    assertTrue(new AppEnv(env, "Linux", "u", p -> null).isFlatpak());
    env.clear();
    env.put("SNAP", "1");
    assertTrue(new AppEnv(env, "Linux", "u", p -> null).isSnap());
  }

  @Test
  public void systemd_service_detection_via_exported_dirs() {
    Map<String, String> env = new HashMap<>();
    env.put("LOGS_DIRECTORY", "/var/log/cryptad");
    AppEnv ae = new AppEnv(env, "Linux", "cryptad", p -> null);
    assertTrue(ae.isSystemdService());
    assertTrue(ae.isServiceMode());
  }

  @Test
  public void windows_service_detection_via_username_system() {
    Map<String, String> env = new HashMap<>();
    env.put("USERNAME", "SYSTEM");
    AppEnv ae = new AppEnv(env, "Windows 10", "SYSTEM", p -> null);
    assertTrue(ae.isWindowsService());
    assertTrue(ae.isServiceMode());
  }

  @Test
  public void mac_service_detection_via_root_or_launchd() {
    Map<String, String> env = new HashMap<>();
    AppEnv rootMac = new AppEnv(env, "Mac OS X", "root", p -> null);
    assertTrue(rootMac.isMacService());
    env.put("LAUNCHD_JOB", "network.crypta.cryptad");
    AppEnv launchdMac = new AppEnv(env, "Mac OS X", "user", p -> null);
    assertTrue(launchdMac.isMacService());
  }

  @Test
  public void serviceMode_property_override() {
    String old = System.getProperty("cryptad.service.mode");
    try {
      Map<String, String> env = new HashMap<>();
      env.put("CRYPTAD_SERVICE", "1");
      AppEnv ae = new AppEnv(env, "Linux", "u", p -> null);
      System.setProperty("cryptad.service.mode", "user");
      assertFalse(ae.isServiceMode(), "system property should force user mode");
      System.setProperty("cryptad.service.mode", "service");
      assertTrue(ae.isServiceMode(), "system property should force service mode");
    } finally {
      if (old != null) System.setProperty("cryptad.service.mode", old);
      else System.clearProperty("cryptad.service.mode");
    }
  }

  @Test
  public void arch_mapping_from_osArch_property() {
    String old = System.getProperty("os.arch");
    try {
      System.setProperty("os.arch", "aarch64");
      assertEquals("arm64", new AppEnv(new HashMap<>(), "Linux", "u", p -> null).arch());
      System.setProperty("os.arch", "x86_64");
      assertEquals("amd64", new AppEnv(new HashMap<>(), "Linux", "u", p -> null).arch());
    } finally {
      if (old != null) System.setProperty("os.arch", old);
      else System.clearProperty("os.arch");
    }
  }

  @Test
  public void availableManagers_and_onPath_linux() throws Exception {
    Path tmp = createTempDirectory("aptenv");
    try {
      // Create mock executables
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
      // Make them executable on *nix
      boolean rpmExec = rpm.setExecutable(true);
      boolean flatpakExec = flatpak.setExecutable(true);
      assertTrue(rpmExec || rpm.canExecute(), "Failed to mark rpm test binary executable");
      assertTrue(
          flatpakExec || flatpak.canExecute(), "Failed to mark flatpak test binary executable");

      Map<String, String> env = new HashMap<>();
      env.put("PATH", tmp.toString());
      AppEnv ae = new AppEnv(env, "Linux", "u", p -> null);
      assertTrue(ae.onPath("rpm"));
      assertTrue(ae.onPath("flatpak"));
      assertTrue(ae.availableManagers().contains("rpm"));
      assertTrue(ae.availableManagers().contains("flatpak"));
    } finally {
      try {
        deleteIfExists(tmp.resolve("rpm"));
      } catch (Exception ignored) {
        /* best-effort cleanup; ignore */
      }
      try {
        deleteIfExists(tmp.resolve("flatpak"));
      } catch (Exception ignored) {
        /* best-effort cleanup; ignore */
      }
      try {
        deleteIfExists(tmp);
      } catch (Exception ignored) {
        /* best-effort cleanup; ignore */
      }
    }
  }

  @Test
  public void detectEnvironment_integrates_all() throws Exception {
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
        // Mark executable after creating the file
        boolean ok = flatpak.setExecutable(true);
        assertTrue(ok || flatpak.canExecute(), "Failed to mark flatpak test binary executable");
        Map<String, String> env = new HashMap<>();
        env.put("PATH", tmp.toString());
        AppEnv ae = new AppEnv(env, "Linux", "u", p -> null);
        AppEnv.EnvDetection det = ae.detectEnvironment();
        assertEquals(AppEnv.OsKind.LINUX, det.getOs());
        assertEquals(det.getArch(), "arm64");
        assertTrue(det.getAvailableManagers().contains("flatpak"));
      } finally {
        try {
          deleteIfExists(tmp.resolve("flatpak"));
        } catch (Exception ignored) {
          /* best-effort cleanup; ignore */
        }
        try {
          deleteIfExists(tmp);
        } catch (Exception ignored) {
          /* best-effort cleanup; ignore */
        }
      }
    } finally {
      if (oldArch != null) System.setProperty("os.arch", oldArch);
      else System.clearProperty("os.arch");
    }
  }

  @Test
  public void docker_detection_via_cgroup_reader() {
    // Skip on hosts where cgroup file does not exist (non-Linux or unusual setups)
    assumeTrue(
        exists(java.nio.file.Path.of("/proc/1/cgroup")),
        "Skipping cgroup-based docker test on non-Linux host");
    Map<String, String> env = new HashMap<>();
    AppEnv ae = new AppEnv(env, "Linux", "tester", p -> "12:devices:/docker/abcdef\n");
    assertTrue(ae.isDocker());
  }

  @Test
  public void osNameRaw_and_osVersionRaw_provide_values() {
    String old = System.getProperty("os.version");
    try {
      System.setProperty("os.version", "13.3.1");
      AppEnv ae = new AppEnv(new HashMap<>(), "Mac OS X", "u", p -> null);
      assertEquals(ae.osNameRaw(), "Mac OS X");
      assertEquals(ae.osVersionRaw(), "13.3.1");
    } finally {
      if (old != null) System.setProperty("os.version", old);
      else System.clearProperty("os.version");
    }
  }
}
