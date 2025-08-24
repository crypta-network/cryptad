package network.crypta.fs

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectories
import kotlin.io.path.exists

/**
 * Computes directory locations for user-session (non-service) mode.
 * Applies XDG for Linux/Flatpak/Snap, macOS conventions, and Windows.
 * Supports env overrides and CLI overrides.
 */
class AppDirs @JvmOverloads constructor(
    private val cliOverrides: Map<String, String> = emptyMap(),
    private val env: Map<String, String> = System.getenv(),
    private val systemProperties: Map<String, String> = System.getProperties().entries.associate { (k, v) -> k.toString() to v.toString() },
    private val appEnv: AppEnv = AppEnv(env)
) {

    data class Resolved(
        val configDir: Path,
        val dataDir: Path,
        val cacheDir: Path,
        val runDir: Path,
        val logsDir: Path
    )

    fun resolve(): Resolved {
        // CLI overrides have highest precedence
        val cliConfig = cliOverrides["configDir"]?.let { Paths.get(it) }
        val cliData = cliOverrides["dataDir"]?.let { Paths.get(it) }
        val cliCache = cliOverrides["cacheDir"]?.let { Paths.get(it) }
        val cliRun = cliOverrides["runDir"]?.let { Paths.get(it) }
        val cliLogs = cliOverrides["logsDir"]?.let { Paths.get(it) }

        // Env overrides next
        val envConfig = env["CRYPTAD_CONFIG_DIR"]?.let { Paths.get(it) }
        val envData = env["CRYPTAD_DATA_DIR"]?.let { Paths.get(it) }
        val envCache = env["CRYPTAD_CACHE_DIR"]?.let { Paths.get(it) }
        val envRun = env["CRYPTAD_RUN_DIR"]?.let { Paths.get(it) }
        val envLogs = env["CRYPTAD_LOGS_DIR"]?.let { Paths.get(it) }

        val osxPrefersXdg = env.containsKey("XDG_CONFIG_HOME") || env.containsKey("XDG_DATA_HOME") || env.containsKey("XDG_CACHE_HOME")

        val home = systemProperties["user.home"] ?: System.getProperty("user.home")
        val tmp = systemProperties["java.io.tmpdir"] ?: System.getProperty("java.io.tmpdir")

        var configBase: Path
        var dataBase: Path
        var cacheBase: Path
        var runtimeBase: Path
        var logsBase: Path

        if (appEnv.isWindows()) {
            val appData = env["APPDATA"] ?: Paths.get(home, "AppData", "Roaming").toString()
            val localAppData = env["LOCALAPPDATA"] ?: Paths.get(home, "AppData", "Local").toString()
            configBase = Paths.get(appData)
            dataBase = Paths.get(localAppData)
            cacheBase = Paths.get(localAppData, "Cache")
            runtimeBase = Paths.get(localAppData, "Cryptad", "Run")
            logsBase = Paths.get(localAppData, "Cryptad", "Logs")
        } else if (appEnv.isMac() && !osxPrefersXdg) {
            // macOS native (GUI/Homebrew default w/o XDG)
            val appSupport = Paths.get(home, MACOS_LIBRARY_PATH, "Application Support")
            configBase = appSupport
            dataBase = appSupport
            cacheBase = Paths.get(home, MACOS_LIBRARY_PATH, "Caches")
            runtimeBase = cacheBase.resolve("Cryptad").resolve("run")
            logsBase = Paths.get(home, MACOS_LIBRARY_PATH, "Logs", "Cryptad")
        } else {
            // Linux/XDG and macOS when XDG_* set
            val xdgConfig = env["XDG_CONFIG_HOME"] ?: Paths.get(home, ".config").toString()
            val xdgData = env["XDG_DATA_HOME"] ?: Paths.get(home, ".local", "share").toString()
            val xdgCache = env["XDG_CACHE_HOME"] ?: Paths.get(home, ".cache").toString()
            configBase = Paths.get(xdgConfig)
            dataBase = Paths.get(xdgData)
            cacheBase = Paths.get(xdgCache)

            val xdgRuntime = env["XDG_RUNTIME_DIR"]?.let { Paths.get(it) }
            runtimeBase = when {
                appEnv.isFlatpak() -> {
                    val appId = env["FLATPAK_ID"] ?: "io.cryptad.Cryptad"
                    (xdgRuntime ?: Paths.get("/run/user", (systemProperties["user.name"] ?: "0")))
                        .resolve("app").resolve(appId).resolve("network/crypta")
                }
                appEnv.isSnap() -> {
                    val rd = xdgRuntime ?: Paths.get(env["SNAP_USER_DATA"] ?: tmp)
                    rd.resolve("network/crypta")
                }
                xdgRuntime != null -> xdgRuntime.resolve("network/crypta")
                else -> {
                    val uidBased = Paths.get("/run/user").resolve(System.getProperty("user.name") ?: "0").resolve("network/crypta")
                    if (Files.isWritable(uidBased.parent)) uidBased else cacheBase.resolve("rt")
                }
            }

            logsBase = dataBase.resolve("Cryptad").resolve("logs")
        }

        // Docker-specific base overrides, if provided
        if (appEnv.isDocker()) {
            env["APP_CONFIG_DIR"]?.let { configBase = Paths.get(it) }
            env["APP_DATA_DIR"]?.let { dataBase = Paths.get(it) }
            env["APP_CACHE_DIR"]?.let { cacheBase = Paths.get(it) }
        }

        // Snap strict: prefer SNAP_USER_COMMON for data persistence across refreshes
        if (appEnv.isSnap() && env["CRYPTAD_SNAP_PER_REV"] != "1") {
            val common = env["SNAP_USER_COMMON"]
            if (!common.isNullOrBlank()) {
                dataBase = Paths.get(common, "Cryptad")
            }
        }

        // Docker: encourage env overrides but default to XDG
        // if (appEnv.isDocker()) {
            // Already using XDG above; env overrides still apply below.
        // }

        // Apply env/cli overrides
        val finalConfig = cliConfig ?: envConfig ?: configBase.resolve("Cryptad").resolve("config")
        val finalData = cliData ?: envData ?: dataBase.resolve("Cryptad").resolve("data")
        val finalCache = cliCache ?: envCache ?: cacheBase.resolve("Cryptad")
        val finalRun = cliRun ?: envRun ?: runtimeBase
        val finalLogs = cliLogs ?: envLogs ?: logsBase

        // Ensure exist and set minimal permissions on POSIX
        ensureDir(finalConfig, perms = PERM_USER_RWX)
        ensureDir(finalData, perms = PERM_GROUP_RX)
        ensureDir(finalCache, perms = PERM_GROUP_RX)
        ensureDir(finalRun, perms = PERM_GROUP_RX)
        ensureDir(finalLogs, perms = PERM_GROUP_RX)

        return Resolved(finalConfig, finalData, finalCache, finalRun, finalLogs)
    }

    private fun ensureDir(path: Path, perms: String) {
        if (!path.exists()) path.createDirectories()
        try {
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                val set: Set<PosixFilePermission> = PosixFilePermissions.fromString(perms)
                Files.setPosixFilePermissions(path, set)
            }
        } catch (_: Exception) {
            // Non-POSIX or failure — ignore silently per cross-platform allowance
        }
    }
}
