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
  val userDir = Path.of(base.getValue("dataDir"), "user").toString()
  setIfMissing("node.install.cfgDir", base.getValue("configDir"))
  setIfMissing("node.install.storeDir", base.getValue("dataDir"))
  setIfMissing("node.install.userDir", userDir)
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
  setIfMissing("node.masterKeyFile", Path.of(userDir, "master.keys").toString())
}

/**
 * Expands a single configuration value by:
 * - Replacing placeholders like ${configDir}, ${dataDir}, etc.
 * - Expanding leading-token shorthand like `dataDir/foo` or `dataDir\foo`.
 * - Anchoring to known base directories and normalizing the path.
 * - Enforcing traversal protection: paths anchored to a base must remain within it.
 *
 * Notes
 * - Mixed separators (both `\\` and `/`) are supported on all platforms. Comparisons are made on a
 *   normalized representation with forward slashes, then paths are resolved/normalized via `Path`
 *   for the final result.
 */
fun expandValue(value: String, base: Map<String, String>): String {
  val (afterPlaceholders, replacedAny) = replacePlaceholders(value, base)
  val afterLeadingToken = expandLeadingToken(afterPlaceholders, base)
  val (anchored, isAnchored) = anchorAndNormalize(afterLeadingToken, base, original = value)
  validateUnanchoredTraversal(anchored, isAnchored, replacedAny, original = value)
  return anchored
}

// --- Implementation helpers ---

private fun normSep(s: String): String = s.replace('\\', '/')

private fun replacePlaceholders(input: String, base: Map<String, String>): Pair<String, Boolean> {
  var out = input
  var replacedAny = false
  base.forEach { (k, v) ->
    val placeholder = "\${$k}"
    if (out.contains(placeholder)) replacedAny = true
    out = out.replace(placeholder, v)
  }
  return out to replacedAny
}

private fun expandLeadingToken(input: String, base: Map<String, String>): String {
  var out = input
  base.forEach { (k, v) ->
    when {
      out == k -> out = v
      out.startsWith("$k/") || out.startsWith("$k\\") -> {
        val rem = out.substring(k.length + 1)
        val remNorm = normSep(rem)
        // Use OS-specific joining, deferring normalization to the anchoring pass.
        out = Path.of(v, remNorm).toString()
      }
    }
  }
  return out
}

private fun anchorAndNormalize(
  input: String,
  base: Map<String, String>,
  original: String,
): Pair<String, Boolean> {
  var out = input
  var anchored = false
  val outNorm = normSep(out)

  base.values.forEach { v ->
    val basePath = Path.of(v).normalize()
    val vNorm = normSep(v).trimEnd('/')

    // Exact equality (with or without trailing slash) => normalize to base path
    if (outNorm == vNorm || outNorm == "$vNorm/") {
      out = basePath.toString()
      anchored = true
      return@forEach
    }

    val prefix = "$vNorm/"
    if (outNorm.startsWith(prefix)) {
      val remainder = outNorm.removePrefix(prefix)
      val resolved = basePath.resolve(remainder).normalize()
      if (!resolved.startsWith(basePath)) {
        throw IOException(
          "Illegal path traversal in config value: '$original' (resolved: '$resolved')"
        )
      }
      out = resolved.toString()
      anchored = true
    }
  }
  return out to anchored
}

private fun validateUnanchoredTraversal(
  out: String,
  anchored: Boolean,
  replacedAny: Boolean,
  original: String,
) {
  if (replacedAny && !anchored) {
    val safe = normSep(out)
    val traversalPattern = Regex("(^|/)\\.\\.(/|$)")
    if (traversalPattern.containsMatchIn(safe)) {
      throw IOException(
        "Illegal path traversal in config value: '$original' (unanchored with '..' segments)"
      )
    }
  }
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
