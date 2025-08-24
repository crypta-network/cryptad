package network.crypta.fs

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectories
import kotlin.io.path.exists

/** Service-aware directories based on systemd (Linux), launchd (macOS), and Windows Service. */
class ServiceDirs @JvmOverloads constructor(
    private val env: Map<String, String> = System.getenv(),
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
        val (configDir, stateDir, cacheDir, logsDir, runDir) = when {
            appEnv.isWindows() -> {
                val programData = env["PROGRAMDATA"] ?: Paths.get(System.getProperty("user.home"), "AppData", "Local").toString()
                val root = Paths.get(programData).resolve("Cryptad")
                tuple(
                    root.resolve("config"),
                    root.resolve("data"),
                    root.resolve("cache"),
                    root.resolve("logs"),
                    root.resolve("run"),
                )
            }
            appEnv.isMac() -> {
                val root = Paths.get("/Library", "Application Support", "Cryptad")
                tuple(
                    root.resolve("config"),
                    root.resolve("data"),
                    Paths.get("/Library", "Caches", "Cryptad"),
                    Paths.get("/Library", "Logs", "Cryptad"),
                    Paths.get("/Library", "Caches", "Cryptad", "run"),
                )
            }
            else -> { // Linux systemd
                val config = env["CONFIGURATION_DIRECTORY"]?.let { Paths.get(it) }
                val state = env["STATE_DIRECTORY"]?.let { Paths.get(it) }
                val cache = env["CACHE_DIRECTORY"]?.let { Paths.get(it) }
                val logs = env["LOGS_DIRECTORY"]?.let { Paths.get(it) }
                val run = env["RUNTIME_DIRECTORY"]?.let { Paths.get(it) }
                tuple(
                    config ?: Paths.get("/etc/cryptad"),
                    state ?: Paths.get("/var/lib/cryptad"),
                    cache ?: Paths.get("/var/cache/cryptad"),
                    logs ?: Paths.get("/var/log/cryptad"),
                    run ?: Paths.get("/run/cryptad"),
                )
            }
        }

        ensure(configDir, perms = "rwx------")
        ensure(stateDir, perms = "rwxr-x---")
        ensure(cacheDir, perms = "rwxr-x---")
        ensure(logsDir, perms = "rwxr-x---")
        ensure(runDir, perms = "rwxr-x---")

        return Resolved(configDir, stateDir, cacheDir, runDir, logsDir)
    }

    private fun ensure(path: Path, perms: String) {
        if (!path.exists()) path.createDirectories()
        try {
            if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms))
            }
        } catch (_: Exception) {
        }
    }

    private fun <A, B, C, D, E> tuple(a: A, b: B, c: C, d: D, e: E) = Quint(a, b, c, d, e)

    private data class Quint<A, B, C, D, E>(val a: A, val b: B, val c: C, val d: D, val e: E)
}
