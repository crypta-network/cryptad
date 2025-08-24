@file:JvmName("CryptadConfig")

package network.crypta.config

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.*
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import network.crypta.fs.Resolved
import network.crypta.support.SimpleFieldSet

@Throws(IOException::class)
fun loadExpandingPlaceholders(
  configFile: Path,
  dirs: Resolved,
  systemProps: Properties = System.getProperties(),
): SimpleFieldSet {
  if (!configFile.parent.exists()) configFile.parent.createDirectories()
  if (!Files.exists(configFile)) {
    Files.writeString(configFile, defaultTemplate(), StandardCharsets.UTF_8)
  }
  val sfs = SimpleFieldSet.readFrom(Files.newInputStream(configFile), true, true)
  val expanded = expandAll(sfs, dirs, systemProps)
  createAll(expanded)
  return expanded
}

fun expandAll(
  input: SimpleFieldSet,
  dirs: Resolved,
  systemProps: Properties = System.getProperties(),
): SimpleFieldSet {
  val home = systemProps.getProperty("user.home")
  val tmp = systemProps.getProperty("java.io.tmpdir")
  val base =
    mapOf(
      "configDir" to dirs.configDir.toString(),
      "dataDir" to dirs.dataDir.toString(),
      "stateDir" to dirs.dataDir.toString(),
      "cacheDir" to dirs.cacheDir.toString(),
      "runDir" to dirs.runDir.toString(),
      "logsDir" to dirs.logsDir.toString(),
      "home" to home,
      "tmp" to tmp,
    )

  val out = SimpleFieldSet(input)
  val it = out.keyIterator()
  while (it.hasNext()) {
    val key = it.next()
    val value = out[key] ?: continue
    val newVal = expandValue(value, base)
    if (newVal != value) out.putOverwrite(key, newVal)
  }
  ensureFinalDefaults(out, base)
  return out
}

private fun ensureFinalDefaults(sfs: SimpleFieldSet, base: Map<String, String>) {
  fun setIfMissing(k: String, v: String) {
    if (sfs[k] == null) sfs.putSingle(k, v)
  }
  setIfMissing("node.install.cfgDir", base.getValue("configDir"))
  setIfMissing("node.install.storeDir", base.getValue("dataDir"))
  setIfMissing("node.install.userDir", base.getValue("configDir"))
  setIfMissing(
    "node.install.pluginStoresDir",
    Path.of(base.getValue("dataDir"), "plugin-data").toString(),
  )
  setIfMissing("node.install.pluginDir", Path.of(base.getValue("dataDir"), "plugins").toString())
  setIfMissing("node.install.tempDir", Path.of(base.getValue("cacheDir"), "tmp").toString())
  setIfMissing(
    "node.install.persistentTempDir",
    Path.of(base.getValue("cacheDir"), "persistent-temp").toString(),
  )
  setIfMissing("node.install.nodeDir", Path.of(base.getValue("dataDir"), "node").toString())
  setIfMissing("node.install.runDir", base.getValue("runDir"))
  setIfMissing("node.downloadsDir", Path.of(base.getValue("dataDir"), "downloads").toString())
  setIfMissing("logger.dirname", base.getValue("logsDir"))
}

/**
 * Expand a single configuration value by replacing supported placeholders and leading tokens, then
 * validate that any resulting path which starts under a known base directory does not escape that
 * base via path traversal (e.g. "../../").
 *
 * Supported placeholders (anywhere in the string): ${configDir}, ${dataDir}, ${stateDir},
 * ${cacheDir}, ${runDir}, ${logsDir}, ${home}, ${tmp}
 *
 * Also supports legacy leading-token forms, e.g. "dataDir/foo" and "dataDir\\foo" which are
 * rewritten relative to the data directory.
 *
 * Path traversal protection: If after expansion the value begins with one of the resolved base
 * directories, the path is normalized and must remain within that base. Otherwise an [IOException]
 * is thrown to prevent writing outside the expected directories.
 */
fun expandValue(value: String, base: Map<String, String>): String {
  var out = value

  // 1) Replace ${token} placeholders wherever they appear
  base.forEach { (k, v) ->
    val placeholder = "\${$k}"
    out = out.replace(placeholder, v)
  }

  // 2) Support leading-token shorthand (e.g., "dataDir/foo")
  base.forEach { (k, v) ->
    when {
      out == k -> out = v
      out.startsWith("$k/") -> out = Path.of(v, out.removePrefix("$k/")).toString()
      out.startsWith("$k\\") -> {
        // Support Windows-style separators even on POSIX by normalizing to '/'
        val rem = out.removePrefix("$k\\").replace('\\', '/')
        out = Path.of(v, rem).normalize().toString()
      }
    }
  }

  // 3) If the result starts under any known base directory, normalize and ensure it does not
  //    escape the base via traversal.
  base.values.forEach { v ->
    val basePath = Path.of(v).normalize()
    // Fast-path: exact equality, rewrite to normalized base
    if (out == v) {
      out = basePath.toString()
      return@forEach
    }

    val forward = "$v/"
    val usesForward = out.startsWith(forward)
    val usesBackward = out.startsWith(v + "\\")
    if (usesForward || usesBackward) {
      val remainderRaw = if (usesForward) out.removePrefix(forward) else out.removePrefix(v + "\\")
      // Normalize Windows-style separators to POSIX for safe resolution
      val remainder = if (usesBackward) remainderRaw.replace('\\', '/') else remainderRaw
      val resolved = basePath.resolve(remainder).normalize()
      // Ensure resolved path stays under base
      if (!resolved.startsWith(basePath)) {
        throw IOException(
          "Illegal path traversal in config value: '$value' (resolved: '$resolved')"
        )
      }
      out = resolved.toString()
    }
  }

  return out
}

private fun createAll(sfs: SimpleFieldSet) {
  val dirs =
    sequenceOf(
        "node.install.cfgDir",
        "node.install.storeDir",
        "node.install.userDir",
        "node.install.pluginStoresDir",
        "node.install.pluginDir",
        "node.install.tempDir",
        "node.install.persistentTempDir",
        "node.install.nodeDir",
        "node.install.runDir",
        "node.downloadsDir",
        "logger.dirname",
      )
      .mapNotNull { sfs[it] }
      .map { Path.of(it) }
  dirs.forEach {
    try {
      if (!Files.exists(it)) Files.createDirectories(it)
    } catch (_: Exception) {
      // Ignore
    }
  }
}

fun defaultTemplate(): String =
  """
    # Cryptad config (auto-generated)
    node.install.nodeDir=stateDir/node
    node.install.cfgDir=configDir
    node.install.userDir=configDir
    node.install.runDir=runDir
    node.install.storeDir=stateDir
    node.install.pluginStoresDir=stateDir/plugin-data
    node.install.pluginDir=stateDir/plugins
    node.install.tempDir=cacheDir/tmp
    node.install.persistentTempDir=cacheDir/persistent-temp
    node.downloadsDir=stateDir/downloads
    logger.dirname=logsDir
    logger.priority=NORMAL
    node.updater.enabled=false
    node.updater.autoupdate=false
    node.updater.updateInstallers=false
    End
"""
    .trimIndent() + "\n"

@Throws(IOException::class)
fun copyIfMissing(src: Path, dst: Path) {
  if (!Files.exists(dst) && Files.exists(src)) {
    if (!dst.parent.exists()) dst.parent.createDirectories()
    Files.copy(src, dst, StandardCopyOption.COPY_ATTRIBUTES)
  }
}
