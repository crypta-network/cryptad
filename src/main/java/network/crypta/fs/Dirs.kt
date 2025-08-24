package network.crypta.fs

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectories
import kotlin.io.path.exists

/**
 * Shared filesystem definitions and directory resolvers for Cryptad.
 *
 * Contains:
 * - Resolved: final absolute directories for config, data/state, cache, run, logs
 * - AppDirs: user-session directories (XDG/macOS/Windows) with CLI and env overrides
 * - ServiceDirs: service/daemon directories (systemd/launchd/Windows Service) with CLI overrides
 * - Permission presets and macOS Library path constant
 * - A shared ensureDir() helper used by both resolvers
 */
data class Resolved(
  val configDir: Path,
  val dataDir: Path,
  val cacheDir: Path,
  val runDir: Path,
  val logsDir: Path,
)

const val PERM_GROUP_RX = "rwxr-x---"
const val PERM_USER_RWX = "rwx------"
const val MACOS_LIBRARY_PATH = "Library"
const val APP_RUNTIME_SUBPATH = "network/crypta"
const val USER_HOME = "user.home"

/** Ensure a directory exists with best-effort POSIX permissions when supported. */
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

data class Overrides(
  val config: Path? = null,
  val data: Path? = null,
  val cache: Path? = null,
  val run: Path? = null,
  val logs: Path? = null,
)

abstract class BaseDirs(
  protected val env: Map<String, String>,
  protected val systemProperties: Map<String, String>,
  protected val cliOverrides: Map<String, String>,
  protected val appEnv: AppEnv,
) {
  protected abstract fun computeBase(): Resolved

  protected open fun envOverrides(): Overrides = Overrides()

  private fun cliOverrides(): Overrides =
    Overrides(
      config = cliOverrides["configDir"]?.let { Paths.get(it) },
      data = cliOverrides["dataDir"]?.let { Paths.get(it) },
      cache = cliOverrides["cacheDir"]?.let { Paths.get(it) },
      run = cliOverrides["runDir"]?.let { Paths.get(it) },
      logs = cliOverrides["logsDir"]?.let { Paths.get(it) },
    )

  fun resolve(): Resolved {
    val base = computeBase()
    val envO = envOverrides()
    val cliO = cliOverrides()
    val finalConfig = cliO.config ?: envO.config ?: base.configDir
    val finalData = cliO.data ?: envO.data ?: base.dataDir
    val finalCache = cliO.cache ?: envO.cache ?: base.cacheDir
    val finalRun = cliO.run ?: envO.run ?: base.runDir
    val finalLogs = cliO.logs ?: envO.logs ?: base.logsDir
    ensureDir(finalConfig, PERM_USER_RWX)
    ensureDir(finalData, PERM_GROUP_RX)
    ensureDir(finalCache, PERM_GROUP_RX)
    ensureDir(finalRun, PERM_GROUP_RX)
    ensureDir(finalLogs, PERM_GROUP_RX)
    return Resolved(finalConfig, finalData, finalCache, finalRun, finalLogs)
  }
}

/**
 * Computes directory locations for user-session (non-service) mode. Applies XDG for
 * Linux/Flatpak/Snap, macOS conventions, and Windows. Supports env overrides and CLI overrides.
 */
class AppDirs(
  env: Map<String, String>,
  systemProperties: Map<String, String>,
  cliOverrides: Map<String, String>,
  appEnv: AppEnv,
) : BaseDirs(env, systemProperties, cliOverrides, appEnv) {

  // Zero-arg constructor for Java callers
  constructor() :
    this(
      System.getenv(),
      System.getProperties().entries.associate { (k, v) -> k.toString() to v.toString() },
      emptyMap(),
      AppEnv(System.getenv()),
    )

  // One-arg constructor (cli overrides only) for Java callers
  constructor(
    cliOverrides: Map<String, String>
  ) : this(
    System.getenv(),
    System.getProperties().entries.associate { (k, v) -> k.toString() to v.toString() },
    cliOverrides,
    AppEnv(System.getenv()),
  )

  override fun computeBase(): Resolved {
    val osxPrefersXdg =
      env.containsKey("XDG_CONFIG_HOME") ||
        env.containsKey("XDG_DATA_HOME") ||
        env.containsKey("XDG_CACHE_HOME")
    val home = systemProperties[USER_HOME] ?: System.getProperty(USER_HOME)
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
      runtimeBase =
        when {
          appEnv.isFlatpak() -> {
            val appId = env["FLATPAK_ID"] ?: "network.crypta.Cryptad"
            (xdgRuntime ?: Paths.get("/run/user", (systemProperties["user.name"] ?: "0")))
              .resolve("app")
              .resolve(appId)
              .resolve(APP_RUNTIME_SUBPATH)
          }
          appEnv.isSnap() -> {
            val rd = xdgRuntime ?: Paths.get(env["SNAP_USER_DATA"] ?: tmp)
            rd.resolve(APP_RUNTIME_SUBPATH)
          }
          xdgRuntime != null -> xdgRuntime.resolve(APP_RUNTIME_SUBPATH)
          else -> {
            val uidBased =
              Paths.get("/run/user")
                .resolve(System.getProperty("user.name") ?: "0")
                .resolve(APP_RUNTIME_SUBPATH)
            if (Files.isWritable(uidBased.parent)) uidBased else cacheBase.resolve("rt")
          }
        }

      logsBase = dataBase.resolve("Cryptad").resolve("logs")
    }

    // Snap strict: prefer SNAP_USER_COMMON for data persistence across refreshes
    if (appEnv.isSnap() && env["CRYPTAD_SNAP_PER_REV"] != "1") {
      val common = env["SNAP_USER_COMMON"]
      if (!common.isNullOrBlank()) {
        dataBase = Paths.get(common, "Cryptad")
      }
    }

    return Resolved(
      configBase.resolve("Cryptad").resolve("config"),
      dataBase.resolve("Cryptad").resolve("data"),
      cacheBase.resolve("Cryptad"),
      runtimeBase,
      logsBase,
    )
  }

  override fun envOverrides(): Overrides {
    // Env overrides (CRYPTAD_*) and Docker-specific APP_* when in docker
    val config = env["CRYPTAD_CONFIG_DIR"]?.let { Paths.get(it) }
    val data = env["CRYPTAD_DATA_DIR"]?.let { Paths.get(it) }
    val cache = env["CRYPTAD_CACHE_DIR"]?.let { Paths.get(it) }
    val run = env["CRYPTAD_RUN_DIR"]?.let { Paths.get(it) }
    val logs = env["CRYPTAD_LOGS_DIR"]?.let { Paths.get(it) }
    var o = Overrides(config, data, cache, run, logs)
    if (appEnv.isDocker()) {
      o =
        Overrides(
          config = env["APP_CONFIG_DIR"]?.let { Paths.get(it) } ?: o.config,
          data = env["APP_DATA_DIR"]?.let { Paths.get(it) } ?: o.data,
          cache = env["APP_CACHE_DIR"]?.let { Paths.get(it) } ?: o.cache,
          run = o.run,
          logs = o.logs,
        )
    }
    return o
  }
}

/** Service-aware directories based on systemd (Linux), launchd (macOS), and Windows Service. */
class ServiceDirs(
  env: Map<String, String>,
  systemProperties: Map<String, String>,
  cliOverrides: Map<String, String>,
  appEnv: AppEnv,
) : BaseDirs(env, systemProperties, cliOverrides, appEnv) {

  // Zero-arg constructor for Java callers
  constructor() :
    this(
      System.getenv(),
      System.getProperties().entries.associate { (k, v) -> k.toString() to v.toString() },
      emptyMap(),
      AppEnv(System.getenv()),
    )

  // One-arg constructor (cli overrides only) used by NodeStarter
  constructor(
    cliOverrides: Map<String, String>
  ) : this(
    System.getenv(),
    System.getProperties().entries.associate { (k, v) -> k.toString() to v.toString() },
    cliOverrides,
    AppEnv(System.getenv()),
  )

  // Backward-compat constructor used from Java tests: (env, appEnv)
  constructor(
    env: Map<String, String>,
    appEnv: AppEnv,
  ) : this(
    env,
    System.getProperties().entries.associate { (k, v) -> k.toString() to v.toString() },
    emptyMap(),
    appEnv,
  )

  override fun computeBase(): Resolved {
    return when {
      appEnv.isWindows() -> {
        val programData =
          env["PROGRAMDATA"]
            ?: Paths.get(
                systemProperties[USER_HOME] ?: System.getProperty(USER_HOME),
                "AppData",
                "Local",
              )
              .toString()
        val root = Paths.get(programData).resolve("Cryptad")
        Resolved(
          root.resolve("config"),
          root.resolve("data"),
          root.resolve("cache"),
          root.resolve("run"),
          root.resolve("logs"),
        )
      }
      appEnv.isMac() -> {
        val root = Paths.get("/$MACOS_LIBRARY_PATH", "Application Support", "Cryptad")
        Resolved(
          root.resolve("config"),
          root.resolve("data"),
          Paths.get("/$MACOS_LIBRARY_PATH", "Caches", "Cryptad"),
          Paths.get("/$MACOS_LIBRARY_PATH", "Caches", "Cryptad", "run"),
          Paths.get("/$MACOS_LIBRARY_PATH", "Logs", "Cryptad"),
        )
      }
      else -> {
        // Linux systemd defaults
        Resolved(
          Paths.get("/etc/cryptad"),
          Paths.get("/var/lib/cryptad"),
          Paths.get("/var/cache/cryptad"),
          Paths.get("/run/cryptad"),
          Paths.get("/var/log/cryptad"),
        )
      }
    }
  }

  override fun envOverrides(): Overrides {
    // For Linux/systemd environments, prefer exported directories
    return if (!appEnv.isLinux()) Overrides()
    else
      Overrides(
        config = env["CONFIGURATION_DIRECTORY"]?.let { Paths.get(it) },
        data = env["STATE_DIRECTORY"]?.let { Paths.get(it) },
        cache = env["CACHE_DIRECTORY"]?.let { Paths.get(it) },
        run = env["RUNTIME_DIRECTORY"]?.let { Paths.get(it) },
        logs = env["LOGS_DIRECTORY"]?.let { Paths.get(it) },
      )
  }
}
