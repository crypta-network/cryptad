package network.crypta.fs

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import network.crypta.config.expandAll
import network.crypta.support.SimpleFieldSet
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class AppDirsTest {
  @TempDir private var tmp: Path? = null

  private fun norm(value: String): String = value.replace('\\', '/')

  private fun tmpDirPath(): Path = requireNotNull(tmp)

  private fun sysProps(home: Path, tmpdir: Path): Map<String, String> {
    val props = HashMap<String, String>()
    props["user.home"] = home.toString()
    props["java.io.tmpdir"] = tmpdir.toString()
    props["os.name"] = "Linux"
    return props
  }

  @Test
  fun resolve_whenLinuxXdgUnset_defaultsUnderHome() {
    val home = tmpDirPath().resolve("home")
    val t = tmpDirPath().resolve("t")
    Files.createDirectories(home)
    Files.createDirectories(t)
    val env = HashMap<String, String>()
    val envResolver = AppEnv(env, "Linux", "tester")
    val dirs = AppDirs(env, sysProps(home, t), HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(norm(resolved.configDir.toString()).contains(".config/cryptad/config"))
    assertTrue(norm(resolved.dataDir.toString()).contains(".local/share/cryptad/data"))
    assertTrue(Files.exists(resolved.configDir))
  }

  @Test
  fun resolve_whenLinuxXdgSet_respectsEnv() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    val t = root.resolve("t")
    val xdgConfig = root.resolve("xdg-config")
    val xdgData = root.resolve("xdg-data")
    val xdgCache = root.resolve("xdg-cache")
    Files.createDirectories(home)
    Files.createDirectories(t)
    Files.createDirectories(xdgConfig)
    Files.createDirectories(xdgData)
    Files.createDirectories(xdgCache)
    val env = HashMap<String, String>()
    env["XDG_CONFIG_HOME"] = xdgConfig.toString()
    env["XDG_DATA_HOME"] = xdgData.toString()
    env["XDG_CACHE_HOME"] = xdgCache.toString()
    val envResolver = AppEnv(env, "Linux", "tester")
    val dirs = AppDirs(env, sysProps(home, t), HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(resolved.configDir.startsWith(xdgConfig))
    assertTrue(resolved.dataDir.startsWith(xdgData))
    assertTrue(resolved.cacheDir.startsWith(xdgCache))
  }

  @Test
  fun resolve_whenMacNative_defaultsToLibrary() {
    val home = tmpDirPath().resolve("home")
    Files.createDirectories(home)
    val env = HashMap<String, String>()
    val envResolver = AppEnv(env, "Mac OS X", "user")
    val props = sysProps(home, tmpDirPath()).toMutableMap()
    props["os.name"] = "Mac OS X"
    val dirs = AppDirs(env, props, HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(
      norm(resolved.configDir.toString()).contains("Library/Application Support/Cryptad/config")
    )
    assertTrue(norm(resolved.cacheDir.toString()).contains("Library/Caches/Cryptad"))
  }

  @Test
  fun resolve_whenMacXdgSet_respectsEnv() {
    val home = tmpDirPath().resolve("home")
    val xdgConfig = tmpDirPath().resolve("xdg")
    Files.createDirectories(home)
    Files.createDirectories(xdgConfig)
    val env = HashMap<String, String>()
    env["XDG_CONFIG_HOME"] = xdgConfig.toString()
    val envResolver = AppEnv(env, "Mac OS X", "user")
    val props = sysProps(home, tmpDirPath()).toMutableMap()
    props["os.name"] = "Mac OS X"
    val dirs = AppDirs(env, props, HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(resolved.configDir.startsWith(xdgConfig))
  }

  @Test
  fun resolve_whenSnapStrict_usesCommonForData() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    val common = root.resolve("snap-common")
    Files.createDirectories(home)
    Files.createDirectories(common)
    val env = HashMap<String, String>()
    env["SNAP"] = "/snap/app"
    env["SNAP_USER_COMMON"] = common.toString()
    env["SNAP_USER_DATA"] = home.toString()
    env["XDG_CONFIG_HOME"] = home.resolve(".config").toString()
    env["XDG_DATA_HOME"] = home.resolve(".local/share").toString()
    env["XDG_CACHE_HOME"] = home.resolve(".cache").toString()
    val envResolver = AppEnv(env, "Linux", "user")
    val dirs = AppDirs(env, sysProps(home, root), HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(resolved.dataDir.startsWith(common.resolve("cryptad")))
  }

  @Test
  fun resolve_whenSnapWithoutCommon_usesXdgAndRuntimeUnderXdgRt() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    val xdgConfig = root.resolve("xdg-config")
    val xdgData = root.resolve("xdg-data")
    val xdgCache = root.resolve("xdg-cache")
    val xdgRt = root.resolve("xdg-rt")
    Files.createDirectories(home)
    Files.createDirectories(xdgConfig)
    Files.createDirectories(xdgData)
    Files.createDirectories(xdgCache)
    Files.createDirectories(xdgRt)
    val env = HashMap<String, String>()
    env["SNAP"] = "/snap/app"
    env["XDG_CONFIG_HOME"] = xdgConfig.toString()
    env["XDG_DATA_HOME"] = xdgData.toString()
    env["XDG_CACHE_HOME"] = xdgCache.toString()
    env["XDG_RUNTIME_DIR"] = xdgRt.toString()
    val envResolver = AppEnv(env, "Linux", "user")
    val dirs = AppDirs(env, sysProps(home, root), HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(resolved.configDir.startsWith(xdgConfig.resolve("cryptad/config")))
    assertTrue(resolved.dataDir.startsWith(xdgData.resolve("cryptad/data")))
    assertTrue(resolved.cacheDir.startsWith(xdgCache.resolve("cryptad")))
    assertTrue(resolved.runDir.startsWith(xdgRt.resolve(APP_RUNTIME_SUBPATH)))
  }

  @Test
  fun resolve_whenSnapWithCommonAndRuntimeUnwritable_fallsBackToCacheRuntime() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    val common = root.resolve("snap-common")
    val xdgCache = common.resolve(".cache")
    Files.createDirectories(home)
    Files.createDirectories(common)
    Files.createDirectories(xdgCache)
    val env = HashMap<String, String>()
    env["SNAP"] = "/snap/app"
    env["UID"] = "99999"
    env["SNAP_INSTANCE_NAME"] = "cryptad.test"
    env["SNAP_USER_COMMON"] = common.toString()
    // Do not set XDG_RUNTIME_DIR; computeSnapRuntime will attempt /run (unwritable in tests) and
    // fall back to cache/rt.
    val envResolver = AppEnv(env, "Linux", "user")
    val dirs = AppDirs(env, sysProps(home, root), HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(resolved.configDir.startsWith(common.resolve("cryptad/config")))
    assertTrue(resolved.dataDir.startsWith(common.resolve("cryptad/data")))
    assertTrue(resolved.cacheDir.startsWith(xdgCache.resolve("cryptad")))
    assertTrue(resolved.runDir.startsWith(xdgCache.resolve("rt")))
    assertTrue(resolved.logsDir.startsWith(common.resolve("cryptad/logs")))
  }

  @Test
  fun resolve_whenMacXdgCasing_isLowercaseCryptad() {
    val home = tmpDirPath().resolve("home")
    val xdgConfig = tmpDirPath().resolve("xdg")
    Files.createDirectories(home)
    Files.createDirectories(xdgConfig)
    val env = HashMap<String, String>()
    env["XDG_CONFIG_HOME"] = xdgConfig.toString()
    val envResolver = AppEnv(env, "Mac OS X", "user")
    val props = sysProps(home, tmpDirPath()).toMutableMap()
    props["os.name"] = "Mac OS X"
    val dirs = AppDirs(env, props, HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(norm(resolved.configDir.toString()).contains("/cryptad/config"))
  }

  @Test
  fun resolve_whenWindowsAppDirs_casingIsCryptad() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    val roaming = home.resolve("AppData/Roaming")
    val local = home.resolve("AppData/Local")
    Files.createDirectories(roaming)
    Files.createDirectories(local)
    val env = HashMap<String, String>()
    env["APPDATA"] = roaming.toString()
    env["LOCALAPPDATA"] = local.toString()
    val envResolver = AppEnv(env, "Windows 10", "user")
    val props = sysProps(home, root).toMutableMap()
    props["os.name"] = "Windows 10"
    val dirs = AppDirs(env, props, HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(norm(resolved.configDir.toString()).contains("/Cryptad/config"))
    assertTrue(norm(resolved.cacheDir.toString()).contains("/Cryptad"))
  }

  @Test
  fun resolve_whenXdgRuntimeMissing_fallsBackToCacheRt() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    val xdgCache = root.resolve("xdg-cache")
    val xdgConfig = root.resolve("xdg-config")
    val xdgData = root.resolve("xdg-data")
    Files.createDirectories(home)
    Files.createDirectories(xdgCache)
    Files.createDirectories(xdgConfig)
    Files.createDirectories(xdgData)
    val env = HashMap<String, String>()
    env["XDG_CONFIG_HOME"] = xdgConfig.toString()
    env["XDG_DATA_HOME"] = xdgData.toString()
    env["XDG_CACHE_HOME"] = xdgCache.toString()
    val envResolver = AppEnv(env, "Linux", "user")
    val dirs = AppDirs(env, sysProps(home, root), HashMap(), envResolver)

    val resolved = dirs.resolve()

    // Without XDG_RUNTIME_DIR and without a writable /run parent, runDir should be <cache>/rt
    assertTrue(resolved.runDir.startsWith(xdgCache.resolve("rt")))
  }

  @Test
  fun resolve_whenFlatpakXdgSet_usesXdgDirs() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    val xdgConfig = root.resolve("xdg-config")
    val env = flatpakEnv(root, home, xdgConfig)
    val envResolver = AppEnv(env, "Linux", "user")
    val dirs = AppDirs(env, sysProps(home, root), HashMap(), envResolver)

    val resolved = dirs.resolve()

    assertTrue(resolved.configDir.startsWith(xdgConfig))
    assertTrue(
      norm(resolved.runDir.toString()).contains("/app/org.example.Cryptad/$APP_RUNTIME_SUBPATH")
    )
  }

  private fun flatpakEnv(root: Path, home: Path, xdgConfig: Path): Map<String, String> {
    val xdgData = root.resolve("xdg-data")
    val xdgCache = root.resolve("xdg-cache")
    Files.createDirectories(home)
    Files.createDirectories(xdgConfig)
    Files.createDirectories(xdgData)
    Files.createDirectories(xdgCache)
    val env = HashMap<String, String>()
    env["FLATPAK_ID"] = "org.example.Cryptad"
    env["XDG_CONFIG_HOME"] = xdgConfig.toString()
    env["XDG_DATA_HOME"] = xdgData.toString()
    env["XDG_CACHE_HOME"] = xdgCache.toString()
    env["XDG_RUNTIME_DIR"] = root.resolve("xdg-rt").toString()
    return env
  }

  @Test
  fun resolve_whenSystemdService_usesExportedDirs() {
    val root = tmpDirPath()
    val env = HashMap<String, String>()
    env["CONFIGURATION_DIRECTORY"] = root.resolve("etc").toString()
    env["STATE_DIRECTORY"] = root.resolve("lib").toString()
    env["CACHE_DIRECTORY"] = root.resolve("cache").toString()
    env["LOGS_DIRECTORY"] = root.resolve("log").toString()
    env["RUNTIME_DIRECTORY"] = root.resolve("run").toString()
    val svc = ServiceDirs(env, AppEnv(env, "Linux", "root"))

    val resolved = svc.resolve()

    assertTrue(resolved.configDir.startsWith(root.resolve("etc")))
    assertTrue(resolved.dataDir.startsWith(root.resolve("lib")))
    assertTrue(resolved.logsDir.startsWith(root.resolve("log")))
  }

  @Test
  fun resolve_whenWindowsService_rootsUnderProgramData() {
    val root = tmpDirPath()
    val env = HashMap<String, String>()
    env["PROGRAMDATA"] = root.resolve("ProgramData").toString()
    val svc = ServiceDirs(env, AppEnv(env, "Windows 10", "SYSTEM"))

    val resolved = svc.resolve()

    assertTrue(resolved.configDir.toString().contains("ProgramData"))
    assertTrue(resolved.logsDir.toString().contains("ProgramData"))
  }

  @Test
  fun resolve_whenMacDaemon_defaultsApply() {
    val env = HashMap<String, String>()
    val svc = ServiceDirs(env, AppEnv(env, "Mac OS X", "root"))

    val resolved = svc.resolve()

    assertTrue(
      norm(resolved.configDir.toString()).startsWith("/Library/Application Support/Cryptad/config")
    )
    assertTrue(norm(resolved.logsDir.toString()).startsWith("/Library/Logs/Cryptad"))
  }

  @Test
  @Throws(IOException::class)
  fun expandAll_whenPlaceholdersPresent_expandsAll() {
    val root = tmpDirPath()
    val home = root.resolve("home")
    Files.createDirectories(home)
    val env = HashMap<String, String>()
    val envResolver = AppEnv(env, "Linux", "tester") { null }
    val dirs = AppDirs(env, sysProps(home, root), HashMap(), envResolver)
    val resolved = dirs.resolve()
    val lines =
      arrayOf(
        $$"node.install.cfgDir=${configDir}",
        "node.install.storeDir=stateDir", // leading token form
        "node.install.tempDir=cacheDir/tmp",
        $$"logger.dirname=${logsDir}",
        "End",
      )
    val sfs = SimpleFieldSet(lines, true, true, false)

    val out = expandAll(sfs, resolved, System.getProperties())

    println("DEBUG cfgDir expected=${resolved.configDir}")
    println("DEBUG node.install.cfgDir actual=${out.get("node.install.cfgDir")}")
    assertTrue(out.get("node.install.cfgDir").startsWith(resolved.configDir.toString()))
    assertEquals(resolved.dataDir.toString(), out.get("node.install.storeDir"))
    assertTrue(out.get("node.install.tempDir").startsWith(resolved.cacheDir.toString()))
    println("DEBUG logsDir expected=${resolved.logsDir}")
    println("DEBUG logger.dirname actual=${out.get("logger.dirname")}")
    assertEquals(resolved.logsDir.toString(), out.get("logger.dirname"))
  }
}
