package network.crypta.fs

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

// constants PERM_GROUP_RX, PERM_USER_RWX, MACOS_LIBRARY_PATH live in Dirs.kt

/**
 * Environment and platform detection for Cryptad.
 *
 * New code is written in Kotlin by project guidelines.
 */
class AppEnv
@JvmOverloads
constructor(
  private val env: Map<String, String> = System.getenv(),
  private val osName: String = System.getProperty("os.name") ?: "",
  private val userName: String = System.getProperty("user.name") ?: "",
  private val fileReader: (Path) -> String? = { path ->
    try {
      if (Files.exists(path)) Files.readString(path) else null
    } catch (_: IOException) {
      null
    }
  },
) {

  /** Broad OS family for the current runtime. */
  enum class OsKind {
    WINDOWS,
    MAC,
    LINUX,
    OTHER,
  }

  /**
   * Summary of the current runtime environment.
   * - `os`: broad OS family
   * - `arch`: normalized CPU arch ("amd64" or "arm64"; others map to "amd64")
   * - `availableManagers`: Linux‑only package tools present on PATH (e.g., ["flatpak", "rpm"]).
   */
  data class EnvDetection(val os: OsKind, val arch: String, val availableManagers: List<String>)

  fun isWindows(): Boolean = osName.lowercase().contains("win")

  fun isMac(): Boolean = osName.lowercase().contains("mac") || osName.lowercase().contains("darwin")

  fun isLinux(): Boolean = !isWindows() && !isMac()

  fun isFlatpak(): Boolean = env.containsKey("FLATPAK_ID")

  fun isSnap(): Boolean = env.containsKey("SNAP")

  /**
   * Detects Docker/container runtime on Linux via cgroup markers.
   *
   * Returns true when explicitly overridden by CRYPTAD_DOCKER=1. Otherwise on Linux, checks for
   * /proc/1/cgroup and looks for common container keywords. Safely returns false when the cgroup
   * file is missing or unreadable.
   */
  fun isDocker(): Boolean {
    // Allow explicit override for tests/containers
    if (env["CRYPTAD_DOCKER"] == "1") return true
    if (!isLinux()) return false
    val cgroupPath = Path.of("/proc/1/cgroup")
    if (!Files.exists(cgroupPath)) return false
    val cgroup = fileReader(cgroupPath) ?: return false
    val s = cgroup.lowercase()
    return s.contains("docker") || s.contains("containerd") || s.contains("kubepods")
  }

  fun isSystemdService(): Boolean {
    if (!isLinux()) return false
    if (env["CRYPTAD_SERVICE"] == "1") return true
    // systemd exported envs (present when using RuntimeDirectory= etc.)
    val keys =
      listOf(
        "CONFIGURATION_DIRECTORY",
        "STATE_DIRECTORY",
        "CACHE_DIRECTORY",
        "LOGS_DIRECTORY",
        "RUNTIME_DIRECTORY",
      )
    return keys.any { env.containsKey(it) }
  }

  fun isWindowsService(): Boolean {
    if (!isWindows()) return false
    if (env["CRYPTAD_SERVICE"] == "1") return true
    val user = env["USERNAME"]?.uppercase()
    val session = env["SESSIONNAME"]?.uppercase()
    return user == "SYSTEM" || session == "SERVICES"
  }

  fun isMacService(): Boolean {
    if (!isMac()) return false
    if (env["CRYPTAD_SERVICE"] == "1") return true
    // Heuristic: launchd job with root
    return userName == "root" || env.containsKey("LAUNCHD_JOB")
  }

  fun isServiceMode(): Boolean {
    // Highest precedence: explicit system property override from CLI
    when (System.getProperty("cryptad.service.mode")?.lowercase()) {
      "service" -> return true
      "user" -> return false
    }
    return env["CRYPTAD_SERVICE"] == "1" ||
      isSystemdService() ||
      isWindowsService() ||
      isMacService()
  }

  /** Return the current OS family. */
  fun osKind(): OsKind =
    when {
      isWindows() -> OsKind.WINDOWS
      isMac() -> OsKind.MAC
      isLinux() -> OsKind.LINUX
      else -> OsKind.OTHER
    }

  /** Return the normalized CPU architecture ("amd64" or "arm64"). */
  fun arch(): String {
    val prop = (System.getProperty("os.arch") ?: "amd64").lowercase()
    return if (prop.contains("aarch64") || prop.contains("arm64")) "arm64" else "amd64"
  }

  /** True when an executable is present on the current PATH. */
  fun onPath(cmd: String): Boolean {
    val path = env["PATH"] ?: return false
    val sep = java.io.File.pathSeparatorChar
    val isWin = isWindows()
    return path.split(sep).any { dir ->
      val base = java.io.File(dir, cmd)
      val withExe = if (isWin) java.io.File(dir, "$cmd.exe") else null
      (base.exists() && base.canExecute()) || (withExe?.exists() == true && withExe.canExecute())
    }
  }

  /** Raw OS name string from the JVM (e.g., "Windows 11", "Mac OS X", "Linux"). */
  fun osNameRaw(): String = osName

  /** Raw OS version string from the JVM or empty when unavailable. */
  fun osVersionRaw(): String = System.getProperty("os.version") ?: ""

  /**
   * Linux‑only: detect available package managers by looking for their executables on PATH. Returns
   * an empty list on non‑Linux platforms.
   */
  fun availableManagers(): List<String> {
    if (!isLinux()) return emptyList()
    val managers = mutableListOf<String>()
    if (onPath("flatpak")) managers += "flatpak"
    if (onPath("snap")) managers += "snap"
    if (onPath("dpkg")) managers += "dpkg"
    if (onPath("rpm")) managers += "rpm"
    return managers
  }

  /** Compute a summary of the current runtime environment. */
  fun detectEnvironment(): EnvDetection = EnvDetection(osKind(), arch(), availableManagers())
}
