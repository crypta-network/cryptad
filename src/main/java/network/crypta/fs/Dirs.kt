package network.crypta.fs

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import network.crypta.support.Logger

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
// Local log source for filesystem directory creation/permission setting
private object FSLogger

private fun ensureDir(path: Path, perms: String) {
  if (!path.exists()) path.createDirectories()
  try {
    if (Files.getFileStore(path).supportsFileAttributeView("posix")) {
      val set: Set<PosixFilePermission> = PosixFilePermissions.fromString(perms)
      Files.setPosixFilePermissions(path, set)
    }
  } catch (e: Exception) {
    // Non-POSIX or failure — log at WARNING to aid debugging but do not fail
    Logger.warning(
      FSLogger::class.java,
      "Failed to set POSIX permissions '$perms' on $path: ${e.message}",
      e,
    )
  }
}

// --- Dedup helpers -----------------------------------------------------------

/** Base XDG or platform roots before app subdirectories are applied. */
private data class Bases(val config: Path, val data: Path, val cache: Path)

/** Compose a Resolved from base roots plus runtime and logs. */
private fun buildResolved(b: Bases, appDirName: String, runtime: Path, logs: Path): Resolved =
  Resolved(
    b.config.resolve(appDirName).resolve("config"),
    b.data.resolve(appDirName).resolve("data"),
    b.cache.resolve(appDirName),
    runtime,
    logs,
  )

/** Compute XDG base roots for config/data/cache given env and home. */
private fun xdgBases(env: Map<String, String>, home: String): Bases =
  Bases(
    config = Paths.get(env["XDG_CONFIG_HOME"] ?: Paths.get(home, ".config").toString()),
    data = Paths.get(env["XDG_DATA_HOME"] ?: Paths.get(home, ".local", "share").toString()),
    cache = Paths.get(env["XDG_CACHE_HOME"] ?: Paths.get(home, ".cache").toString()),
  )

/** Standard (non-Snap) XDG runtime resolution, including Flatpak handling. */
private fun computeStandardXdgRuntime(
  env: Map<String, String>,
  systemProperties: Map<String, String>,
  appEnv: AppEnv,
  cacheBase: Path,
): Path {
  val xdgRuntime = env["XDG_RUNTIME_DIR"]?.let { Paths.get(it) }
  return when {
    appEnv.isFlatpak() -> {
      val appId = env["FLATPAK_ID"] ?: "network.crypta.Cryptad"
      (xdgRuntime ?: Paths.get("/run/user", (systemProperties["user.name"] ?: "0")))
        .resolve("app")
        .resolve(appId)
        .resolve(APP_RUNTIME_SUBPATH)
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
}

/** Snap-specific runtime directory under /run/user/<uid>/snap.<instance>. */
private fun computeSnapRuntime(env: Map<String, String>, cacheBase: Path): Path {
  val uidEnv = env["UID"]
  val inst = env["SNAP_INSTANCE_NAME"] ?: env["SNAP_NAME"]
  val uid =
    uidEnv
      ?: run {
        val rd = env["XDG_RUNTIME_DIR"] ?: ""
        val m = Regex("^/run/user/(\\d+)/").find(rd)
        m?.groupValues?.getOrNull(1) ?: "0"
      }
  val snapInstance = inst ?: "cryptad"
  val candidate = Paths.get("/run/user", uid, "snap.$snapInstance")
  return try {
    val parent = candidate.parent
    if (parent != null && Files.isWritable(parent)) candidate else cacheBase.resolve("rt")
  } catch (_: Exception) {
    cacheBase.resolve("rt")
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
 * Computes directory locations for user-session (non-service) mode.
 * - Linux/XDG and macOS with XDG_* set: use lowercase app dir name `cryptad` under the XDG bases.
 * - macOS native (no XDG_*): use `Cryptad` under Library conventions.
 * - Windows: use `Cryptad` under `%APPDATA%`/`%LOCALAPPDATA%`.
 *
 * Supports env overrides and CLI overrides.
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
    // Choose app directory casing: XDG on Linux and macOS with XDG_* set use lowercase
    val appDirName =
      if (appEnv.isWindows() || (appEnv.isMac() && !osxPrefersXdg)) "Cryptad" else "cryptad"
    val home = systemProperties[USER_HOME] ?: System.getProperty(USER_HOME)
    if (appEnv.isWindows()) {
      val appData = env["APPDATA"] ?: Paths.get(home, "AppData", "Roaming").toString()
      val localAppData = env["LOCALAPPDATA"] ?: Paths.get(home, "AppData", "Local").toString()
      val bases =
        Bases(Paths.get(appData), Paths.get(localAppData), Paths.get(localAppData, "Cache"))
      val runtimeBase = Paths.get(localAppData, "Cryptad", "Run")
      val logsBase = Paths.get(localAppData, "Cryptad", "Logs")
      return buildResolved(bases, appDirName, runtimeBase, logsBase)
    } else if (appEnv.isMac() && !osxPrefersXdg) {
      // macOS native (GUI/Homebrew default w/o XDG)
      val appSupport = Paths.get(home, MACOS_LIBRARY_PATH, "Application Support")
      val bases = Bases(appSupport, appSupport, Paths.get(home, MACOS_LIBRARY_PATH, "Caches"))
      val runtimeBase = bases.cache.resolve("Cryptad").resolve("run")
      val logsBase = Paths.get(home, MACOS_LIBRARY_PATH, "Logs", "Cryptad")
      return buildResolved(bases, appDirName, runtimeBase, logsBase)
    } else {
      // Linux/XDG and macOS when XDG_* set
      var bases = xdgBases(env, home)
      if (appEnv.isSnap()) {
        val snapCommon = env["SNAP_USER_COMMON"]
        if (!snapCommon.isNullOrBlank()) {
          bases =
            Bases(
              Paths.get(snapCommon, ".config"),
              Paths.get(snapCommon),
              Paths.get(snapCommon, ".cache"),
            )
          val runtimeBase = computeSnapRuntime(env, bases.cache)
          val logsBase = bases.data.resolve(appDirName).resolve("logs")
          return buildResolved(bases, appDirName, runtimeBase, logsBase)
        }
      }

      val runtimeBase = computeStandardXdgRuntime(env, systemProperties, appEnv, bases.cache)
      val logsBase = bases.data.resolve(appDirName).resolve("logs")
      return buildResolved(bases, appDirName, runtimeBase, logsBase)
    }
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
