@file:JvmName("ConfigMigrator")

package network.crypta.config

import network.crypta.fs.Resolved
import network.crypta.support.SimpleFieldSet
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import kotlin.io.path.createDirectories
import kotlin.io.path.exists

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
            println("[cryptad] Migrated cryptad.ini from CWD to $cfgFile")
        } else if (Files.exists(exeCfg)) {
            copyIfMissing(exeCfg, cfgFile)
            println("[cryptad] Migrated cryptad.ini from executable dir to $cfgFile")
        } else {
            if (!cfgFile.parent.exists()) cfgFile.parent.createDirectories()
            Files.writeString(cfgFile, defaultTemplate())
            println("[cryptad] Created default cryptad.ini at $cfgFile")
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
    try {
        if (Files.exists(src) && !Files.exists(dst)) {
            if (!Files.exists(dst.parent)) Files.createDirectories(dst.parent)
            Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE)
            println("[cryptad] Moved $src -> $dst")
        }
    } catch (_: Exception) {
        // Skip on conflicts or failures
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
        rewrite("node.install.cfgDir", ".", "\${configDir}")
        rewrite("node.install.userDir", ".", "\${configDir}")
        rewrite("node.install.nodeDir", ".", "\${dataDir}/node")
        rewrite("node.install.storeDir", "./datastore", "\${dataDir}/datastore")
        rewrite("node.install.pluginDir", "./plugins", "\${dataDir}/plugins")
        rewrite("node.install.pluginStoresDir", "plugin-data", "\${dataDir}/plugins")
        rewrite("node.install.tempDir", "./temp", "\${cacheDir}/tmp")
        rewrite(
            "node.install.persistentTempDir",
            "./persistent-temp",
            "\${cacheDir}/persistent-temp"
        )
        rewrite("node.downloadsDir", "./downloads", "\${dataDir}/downloads")
        rewrite("logger.dirname", "./logs", "\${logsDir}")

        Files.newOutputStream(configFile).use { os -> sfs.writeToBigBuffer(os) }
        println("[cryptad] Rewrote legacy paths in $configFile")
    } catch (_: Exception) {
        // Tolerate parse errors; continue without rewrite
    }
}
