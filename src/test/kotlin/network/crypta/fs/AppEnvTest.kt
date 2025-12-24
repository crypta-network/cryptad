package network.crypta.fs

import java.nio.file.Files.createTempDirectory
import java.nio.file.Files.deleteIfExists
import java.nio.file.Files.exists
import java.nio.file.Files.write
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

internal class AppEnvTest {

  @Test
  internal fun dockerEnvOverride_isTrue() {
    val env = HashMap<String, String>()
    env["CRYPTAD_DOCKER"] = "1"
    val ae = AppEnv(env, "Linux", "tester") { null }
    assertTrue(ae.isDocker())
  }

  @Test
  internal fun nonLinux_isDockerFalse() {
    val env = HashMap<String, String>()
    val ae = AppEnv(env, "Mac OS X", "tester", Path::toString)
    assertFalse(ae.isDocker())
  }

  @Test
  internal fun osKind_basicFamilies() {
    val win = AppEnv(HashMap(), "Windows 11", "u") { null }
    val mac = AppEnv(HashMap(), "Mac OS X", "u") { null }
    val lin = AppEnv(HashMap(), "Linux", "u") { null }
    assertTrue(win.isWindows())
    assertTrue(mac.isMac())
    assertTrue(lin.isLinux())
    assertEquals(AppEnv.OsKind.WINDOWS, win.osKind())
    assertEquals(AppEnv.OsKind.MAC, mac.osKind())
    assertEquals(AppEnv.OsKind.LINUX, lin.osKind())
  }

  @Test
  internal fun flatpak_snap_detection() {
    val env = HashMap<String, String>()
    env["FLATPAK_ID"] = "network.crypta.Cryptad"
    assertTrue(AppEnv(env, "Linux", "u") { null }.isFlatpak())
    env.clear()
    env["SNAP"] = "1"
    assertTrue(AppEnv(env, "Linux", "u") { null }.isSnap())
  }

  @Test
  internal fun systemd_service_detection_via_exported_dirs() {
    val env = HashMap<String, String>()
    env["LOGS_DIRECTORY"] = "/var/log/cryptad"
    val ae = AppEnv(env, "Linux", "cryptad") { null }
    assertTrue(ae.isSystemdService())
    assertTrue(ae.isServiceMode())
  }

  @Test
  internal fun windows_service_detection_via_username_system() {
    val env = HashMap<String, String>()
    env["USERNAME"] = "SYSTEM"
    val ae = AppEnv(env, "Windows 10", "SYSTEM") { null }
    assertTrue(ae.isWindowsService())
    assertTrue(ae.isServiceMode())
  }

  @Test
  internal fun mac_service_detection_via_root_or_launchd() {
    val env = HashMap<String, String>()
    val rootMac = AppEnv(env, "Mac OS X", "root") { null }
    assertTrue(rootMac.isMacService())
    env["LAUNCHD_JOB"] = "network.crypta.cryptad"
    val launchdMac = AppEnv(env, "Mac OS X", "user") { null }
    assertTrue(launchdMac.isMacService())
  }

  @Test
  internal fun serviceMode_property_override() {
    val old = System.getProperty("cryptad.service.mode")
    try {
      val env = HashMap<String, String>()
      env["CRYPTAD_SERVICE"] = "1"
      val ae = AppEnv(env, "Linux", "u") { null }
      System.setProperty("cryptad.service.mode", "user")
      assertFalse(ae.isServiceMode(), "system property should force user mode")
      System.setProperty("cryptad.service.mode", "service")
      assertTrue(ae.isServiceMode(), "system property should force service mode")
    } finally {
      if (old != null) {
        System.setProperty("cryptad.service.mode", old)
      } else {
        System.clearProperty("cryptad.service.mode")
      }
    }
  }

  @Test
  internal fun arch_mapping_from_osArch_property() {
    val old = System.getProperty("os.arch")
    try {
      System.setProperty("os.arch", "aarch64")
      assertEquals("arm64", AppEnv(HashMap(), "Linux", "u") { null }.arch())
      System.setProperty("os.arch", "x86_64")
      assertEquals("amd64", AppEnv(HashMap(), "Linux", "u") { null }.arch())
    } finally {
      if (old != null) {
        System.setProperty("os.arch", old)
      } else {
        System.clearProperty("os.arch")
      }
    }
  }

  @Test
  internal fun availableManagers_and_onPath_linux() {
    val tmp = createTempDirectory("aptenv")
    try {
      // Create mock executables
      val rpm = tmp.resolve("rpm").toFile()
      val flatpak = tmp.resolve("flatpak").toFile()
      write(
        rpm.toPath(),
        byteArrayOf(0),
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
      )
      write(
        flatpak.toPath(),
        byteArrayOf(0),
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
      )
      // Make them executable on *nix
      val rpmExec = rpm.setExecutable(true)
      val flatpakExec = flatpak.setExecutable(true)
      assertTrue(rpmExec || rpm.canExecute(), "Failed to mark rpm test binary executable")
      assertTrue(
        flatpakExec || flatpak.canExecute(),
        "Failed to mark flatpak test binary executable",
      )

      val env = HashMap<String, String>()
      env["PATH"] = tmp.toString()
      val ae = AppEnv(env, "Linux", "u") { null }
      assertTrue(ae.onPath("rpm"))
      assertTrue(ae.onPath("flatpak"))
      assertTrue(ae.availableManagers().contains("rpm"))
      assertTrue(ae.availableManagers().contains("flatpak"))
    } finally {
      try {
        deleteIfExists(tmp.resolve("rpm"))
      } catch (_: Exception) {
        /* best-effort cleanup; ignore */
      }
      try {
        deleteIfExists(tmp.resolve("flatpak"))
      } catch (_: Exception) {
        /* best-effort cleanup; ignore */
      }
      try {
        deleteIfExists(tmp)
      } catch (_: Exception) {
        /* best-effort cleanup; ignore */
      }
    }
  }

  @Test
  internal fun detectEnvironment_integrates_all() {
    val oldArch = System.getProperty("os.arch")
    try {
      System.setProperty("os.arch", "aarch64")
      val tmp = createTempDirectory("aptenv2")
      try {
        val flatpak = tmp.resolve("flatpak").toFile()
        write(
          flatpak.toPath(),
          byteArrayOf(0),
          StandardOpenOption.CREATE,
          StandardOpenOption.TRUNCATE_EXISTING,
        )
        // Mark executable after creating the file
        val ok = flatpak.setExecutable(true)
        assertTrue(ok || flatpak.canExecute(), "Failed to mark flatpak test binary executable")
        val env = HashMap<String, String>()
        env["PATH"] = tmp.toString()
        val ae = AppEnv(env, "Linux", "u") { null }
        val det = ae.detectEnvironment()
        assertEquals(AppEnv.OsKind.LINUX, det.os)
        assertEquals("arm64", det.arch)
        assertTrue(det.availableManagers.contains("flatpak"))
      } finally {
        try {
          deleteIfExists(tmp.resolve("flatpak"))
        } catch (_: Exception) {
          /* best-effort cleanup; ignore */
        }
        try {
          deleteIfExists(tmp)
        } catch (_: Exception) {
          /* best-effort cleanup; ignore */
        }
      }
    } finally {
      if (oldArch != null) {
        System.setProperty("os.arch", oldArch)
      } else {
        System.clearProperty("os.arch")
      }
    }
  }

  @Test
  internal fun docker_detection_via_cgroup_reader() {
    // Skip on hosts where cgroup file does not exist (non-Linux or unusual setups)
    assumeTrue(
      exists(Path.of("/proc/1/cgroup")),
      "Skipping cgroup-based docker test on non-Linux host",
    )
    val env = HashMap<String, String>()
    val ae = AppEnv(env, "Linux", "tester") { "12:devices:/docker/abcdef\n" }
    assertTrue(ae.isDocker())
  }

  @Test
  internal fun osNameRaw_and_osVersionRaw_provide_values() {
    val old = System.getProperty("os.version")
    try {
      System.setProperty("os.version", "13.3.1")
      val ae = AppEnv(HashMap(), "Mac OS X", "u") { null }
      assertEquals("Mac OS X", ae.osNameRaw())
      assertEquals("13.3.1", ae.osVersionRaw())
    } finally {
      if (old != null) {
        System.setProperty("os.version", old)
      } else {
        System.clearProperty("os.version")
      }
    }
  }
}
