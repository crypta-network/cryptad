package network.crypta.fs

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path

const val PERM_GROUP_RX = "rwxr-x---"
const val PERM_USER_RWX = "rwx------"
const val MACOS_LIBRARY_PATH = "Library"

/**
 * Environment and platform detection for Cryptad.
 *
 * New code is written in Kotlin by project guidelines.
 */
class AppEnv @JvmOverloads constructor(
    private val env: Map<String, String> = System.getenv(),
    private val osName: String = System.getProperty("os.name") ?: "",
    private val userName: String = System.getProperty("user.name") ?: "",
    private val fileReader: (Path) -> String? = { path ->
        try {
            if (Files.exists(path)) Files.readString(path) else null
        } catch (_: IOException) { null }
    }
) {

    fun isWindows(): Boolean = osName.lowercase().contains("win")
    fun isMac(): Boolean = osName.lowercase().contains("mac") || osName.lowercase().contains("darwin")
    fun isLinux(): Boolean = !isWindows() && !isMac()

    fun isFlatpak(): Boolean = env.containsKey("FLATPAK_ID")

    fun isSnap(): Boolean = env.containsKey("SNAP")

    fun isDocker(): Boolean {
        // Allow explicit override for tests/containers
        if (env["CRYPTAD_DOCKER"] == "1") return true
        if (!isLinux()) return false
        val cgroup = fileReader(Path.of("/proc/1/cgroup")) ?: return false
        val s = cgroup.lowercase()
        return s.contains("docker") || s.contains("containerd") || s.contains("kubepods")
    }

    fun isSystemdService(): Boolean {
        if (!isLinux()) return false
        if (env["CRYPTAD_SERVICE"] == "1") return true
        // systemd exported envs (present when using RuntimeDirectory= etc.)
        val keys = listOf(
            "CONFIGURATION_DIRECTORY", "STATE_DIRECTORY", "CACHE_DIRECTORY", "LOGS_DIRECTORY", "RUNTIME_DIRECTORY"
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
        return env["CRYPTAD_SERVICE"] == "1" || isSystemdService() || isWindowsService() || isMacService()
    }
}
