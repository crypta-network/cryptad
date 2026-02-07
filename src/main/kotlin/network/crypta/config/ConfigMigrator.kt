@file:JvmName("ConfigMigrator")

package network.crypta.config

import java.io.IOException
import java.nio.file.*
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import network.crypta.fs.Resolved
import network.crypta.support.SimpleFieldSet
import org.slf4j.LoggerFactory

// SLF4J logger for this file (file-level @JvmName("ConfigMigrator"))
private val LOG = LoggerFactory.getLogger("network.crypta.config.ConfigMigrator")

/** Best-effort migration from legacy relative paths to adaptive directories. */
const val CONFIG_FILE = "cryptad.ini"

@Throws(IOException::class)
fun migrateIfNeeded(dirs: Resolved, executableDir: Path) {
  val cfgFile = dirs.configDir.resolve(CONFIG_FILE)

  val cwd = Paths.get("").toAbsolutePath().normalize()
  val cwdCfg = cwd.resolve(CONFIG_FILE)
  val exeCfg = executableDir.resolve(CONFIG_FILE)

  if (!Files.exists(cfgFile)) {
    if (Files.exists(cwdCfg)) {
      copyIfMissing(cwdCfg, cfgFile)
      LOG.info("Migrated cryptad.ini from CWD to {}", cfgFile)
    } else if (Files.exists(exeCfg)) {
      copyIfMissing(exeCfg, cfgFile)
      LOG.info("Migrated cryptad.ini from executable dir to {}", cfgFile)
    } else {
      if (!cfgFile.parent.exists()) cfgFile.parent.createDirectories()
      Files.writeString(cfgFile, defaultTemplate())
      LOG.info("Created default cryptad.ini at {}", cfgFile)
    }
  }

  if (Files.exists(cfgFile)) rewriteLegacyPaths(cfgFile)

  moveIfPresent(cwd.resolve("datastore"), dirs.dataDir.resolve("datastore"))
  moveIfPresent(cwd.resolve("plugins"), dirs.dataDir.resolve("plugins"))
  moveIfPresent(cwd.resolve("plugin-data"), dirs.dataDir.resolve("plugins"))
  moveIfPresent(cwd.resolve("temp"), dirs.cacheDir.resolve("tmp"))
  moveIfPresent(cwd.resolve("persistent-temp"), dirs.cacheDir.resolve("persistent-temp"))
  moveIfPresent(cwd.resolve("downloads"), dirs.dataDir.resolve("downloads"))
  moveIfPresent(cwd.resolve("logs"), dirs.logsDir)
}

private fun moveIfPresent(src: Path, dst: Path) {
  if (!Files.exists(src) || Files.exists(dst)) return
  try {
    val parent = dst.parent
    if (parent != null && !Files.exists(parent)) Files.createDirectories(parent)
    Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE)
    LOG.info("Moved {} -> {} (atomic)", src, dst)
  } catch (_: AtomicMoveNotSupportedException) {
    // Fallback to non-atomic move and log
    try {
      Files.move(src, dst)
      LOG.info("Moved {} -> {} (non-atomic fallback)", src, dst)
    } catch (e2: Exception) {
      LOG.warn(
        "Failed to move {} -> {} (fallback after atomic not supported): {}",
        src,
        dst,
        e2.message,
        e2,
      )
    }
  } catch (e: Exception) {
    // Log unexpected failures for debugging; continue best-effort
    LOG.warn("Failed to move {} -> {} atomically: {}", src, dst, e.message, e)
  }
}

@Throws(IOException::class)
private fun rewriteLegacyPaths(configFile: Path) {
  try {
    val sfs = SimpleFieldSet.readFrom(Files.newInputStream(configFile), true, true)

    fun rewrite(key: String, rel: String, placeholder: String) {
      val v = sfs[key] ?: return
      if (v == rel || v == "./$rel") sfs.putOverwrite(key, placeholder)
    }
    rewrite("node.install.cfgDir", ".", $$"${configDir}")
    rewrite("node.install.userDir", ".", $$"${configDir}")
    rewrite("node.install.nodeDir", ".", $$"${dataDir}/node")
    rewrite("node.install.storeDir", "./datastore", $$"${dataDir}/datastore")
    rewrite("node.install.pluginDir", "./plugins", $$"${dataDir}/plugins")
    rewrite("node.install.pluginStoresDir", "plugin-data", $$"${dataDir}/plugins")
    rewrite("node.install.tempDir", "./temp", $$"${cacheDir}/tmp")
    rewrite("node.install.persistentTempDir", "./persistent-temp", $$"${cacheDir}/persistent-temp")
    rewrite("node.downloadsDir", "./downloads", $$"${dataDir}/downloads")
    rewrite("logger.dirname", "./logs", $$"${logsDir}")

    Files.newOutputStream(configFile).use { os -> sfs.writeToBigBuffer(os) }
    LOG.info("Rewrote legacy paths in {}", configFile)
  } catch (e: Exception) {
    // Tolerate parse errors; continue without a rewrite, but log for visibility
    LOG.warn("Failed to rewrite legacy paths in {}: {}", configFile, e.message, e)
  }
}
