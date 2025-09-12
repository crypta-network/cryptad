package network.crypta.node.updater

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets
import network.crypta.client.FetchException
import network.crypta.client.FetchException.FetchExceptionMode
import network.crypta.client.FetchResult
import network.crypta.client.async.ClientContext
import network.crypta.client.async.ClientGetCallback
import network.crypta.client.async.ClientGetter
import network.crypta.client.events.ClientEvent
import network.crypta.client.events.ClientEventListener
import network.crypta.clients.http.ExternalLinkToadlet
import network.crypta.keys.FreenetURI
import network.crypta.node.RequestClient
import network.crypta.node.RequestStarter
import network.crypta.support.HTMLNode
import network.crypta.support.Logger
import network.crypta.support.io.FileBucket

/**
 * Package‑based updater that subscribes to `USK@.../info/<N>` and offers OS installers instead of
 * self‑updating the running JAR.
 *
 * Responsibilities
 * - Fetch the latest “core info” descriptor (JSON) and parse it.
 * - Detect the current OS/arch and available package managers.
 * - Choose a suitable artifact (e.g., amd64.deb → Flatpak/Snap preferred when present).
 * - On request (or when auto‑update is allowed), fetch the artifact’s CHK to the updates directory.
 * - Render small UI controls on the Alerts page: Download/Install/Open in Store.
 *
 * Thread‑safety: public getters and UI state rely on `@Volatile` fields; long‑running work runs
 * through the client fetcher and event callbacks.
 */
class CoreUpdater(
  manager: NodeUpdateManager,
  uri: FreenetURI,
  current: Int,
  min: Int,
  max: Int,
  blobFilenamePrefix: String,
) : NodeUpdater(manager, uri, current, min, max, blobFilenamePrefix) {

  @Volatile private var latestInfo: CoreInfo? = null
  @Volatile private var selectedKey: String? = null // "<arch>.<ext>"
  @Volatile private var selectedSpec: PackageSpec? = null
  @Volatile private var fetcher: PackageFetcher? = null
  @Volatile private var env: EnvDetection? = null

  override fun jarName(): String = "core-info.json"

  override fun onStartFetching() {
    // No-op for UI; we render state via renderProperties.
  }

  override fun maybeParseManifest(result: FetchResult, build: Int) {
    // Parse JSON (treat fetched blob as UTF-8 text)
    val info = parseInfo(result)
    latestInfo = info
    // Detect environment and select an artifact to propose
    val e = detectEnvironment()
    env = e
    selectArtifact(info, e)
    // Optionally auto-download when autoupdate=true
    if (manager.isAutoUpdateAllowed && selectedSpec?.chk != null && fetcher == null) {
      tryStartDownload()
    }
  }

  override fun processSuccess(fetched: Int, result: FetchResult, blobFile: File?) {
    // Nothing to persist from info JSON beyond in-memory state.
  }

  /**
   * CHK for a short changelog, if provided by the descriptor. Suitable for user‑facing “What’s
   * new?” links.
   */
  fun getShortChangelogCHK(): String? = latestInfo?.changelogChk

  /**
   * CHK for a detailed changelog, if provided by the descriptor. Suitable for developer‑oriented
   * change logs.
   */
  fun getFullChangelogCHK(): String? = latestInfo?.fullChangelogChk

  private fun parseInfo(result: FetchResult): CoreInfo {
    val text = readAll(result.asBucket().inputStream)
    return CoreJson.parse(text)
  }

  private fun readAll(ins: InputStream): String =
    ins.use { input ->
      val out = ByteArrayOutputStream()
      val buf = ByteArray(8192)
      while (true) {
        val r = input.read(buf)
        if (r <= 0) break
        out.write(buf, 0, r)
      }
      out.toString(StandardCharsets.UTF_8)
    }

  private fun detectEnvironment(): EnvDetection {
    val osName = System.getProperty("os.name")?.lowercase() ?: ""
    val os =
      when {
        osName.contains("win") -> OsKind.WINDOWS
        osName.contains("mac") || osName.contains("darwin") -> OsKind.MAC
        osName.contains("nux") || osName.contains("linux") -> OsKind.LINUX
        else -> OsKind.OTHER
      }
    val archProp = System.getProperty("os.arch")?.lowercase() ?: "amd64"
    val arch =
      when {
        archProp.contains("aarch64") || archProp.contains("arm64") -> "arm64"
        else -> "amd64"
      }
    val managers = mutableListOf<String>()
    if (os == OsKind.LINUX) {
      if (onPath("flatpak")) managers += "flatpak"
      if (onPath("snap")) managers += "snap"
      if (onPath("dpkg")) managers += "dpkg"
      if (onPath("rpm")) managers += "rpm"
    }
    return EnvDetection(os, arch, managers)
  }

  private fun onPath(cmd: String): Boolean {
    val path = System.getenv("PATH") ?: return false
    val sep = File.pathSeparatorChar
    return path.split(sep).any { dir ->
      val f = File(dir, cmd)
      val fExe =
        if (System.getProperty("os.name").lowercase().contains("win")) File(dir, "$cmd.exe")
        else null
      (f.exists() && f.canExecute()) || (fExe?.exists() == true && fExe.canExecute())
    }
  }

  private fun selectArtifact(info: CoreInfo, env: EnvDetection) {
    val pkgs = info.packages
    val arch = env.arch
    fun key(ext: String) = "$arch.$ext"

    val order: List<String> =
      when (env.os) {
        OsKind.WINDOWS -> listOf("exe")
        OsKind.MAC -> listOf("dmg")
        OsKind.LINUX ->
          buildList {
            if (env.availableManagers.contains("flatpak")) add("flatpak")
            if (env.availableManagers.contains("snap")) add("snap")
            if (env.availableManagers.contains("dpkg")) add("deb")
            if (env.availableManagers.contains("rpm")) add("rpm")
            // Always keep a direct package fallback order
            if (!contains("deb")) add("deb")
            if (!contains("rpm")) add("rpm")
          }
        else -> emptyList()
      }

    var chosenKey: String? = null
    var chosen: PackageSpec? = null
    for (ext in order) {
      val k = key(ext)
      val spec = pkgs[k]
      if (spec?.chk != null) {
        chosenKey = k
        chosen = spec
        break
      }
    }
    // Fallback: try any package for this arch
    if (chosen == null) {
      for ((k, v) in pkgs) {
        if (k.startsWith("${env.arch}.") && v.chk != null) {
          chosenKey = k
          chosen = v
          break
        }
      }
    }
    selectedKey = chosenKey
    selectedSpec = chosen
  }

  private fun updatesDir(): File =
    File(manager.getNode().nodeDir().dir(), "updates/core/${latestInfo?.version ?: "unknown"}")

  private fun downloadTarget(): File? {
    val key = selectedKey ?: return null
    val outDir = updatesDir()
    if (!outDir.exists()) outDir.mkdirs()
    val name = key.substringAfter('.') // ext
    return File(outDir, key)
  }

  private fun tryStartDownload() {
    val spec = selectedSpec ?: return
    val target = downloadTarget() ?: return
    val chk = spec.chk ?: return
    val uri = FreenetURI(chk)
    val f = PackageFetcher(target, uri)
    fetcher = f
    f.start()
  }

  /**
   * Start downloading the currently selected package if not already in progress. Triggered from the
   * Alerts page POST handler.
   */
  fun startDownloadFromUI() {
    if (fetcher != null) return
    tryStartDownload()
  }

  /** Absolute path to the downloaded file once complete, or null if not ready. */
  fun getDownloadedFile(): File? = fetcher?.completedFileOrNull()

  /**
   * Render a compact status and controls block inside the global Alerts panel.
   *
   * The content includes:
   * - Detected OS/arch and the selected artifact key.
   * - Optional “Release Notes” and “Open in Store” links.
   * - Either a Download button, or a progress line and Install button when ready.
   */
  fun renderProperties(alertNode: HTMLNode) {
    val info = latestInfo ?: return
    val envNow = env ?: detectEnvironment().also { env = it }
    val chosen = selectedKey

    val status = HTMLNode("p")
    status.addChild("#", "Core update available: version ${info.version ?: "?"}")
    alertNode.addChild(status)

    val det = HTMLNode("p")
    det.addChild(
      "#",
      "Detected: ${envNow.os} / ${envNow.arch}  •  Selected package: ${chosen ?: "n/a"}",
    )
    alertNode.addChild(det)

    val links = HTMLNode("p")
    if (!info.releasePageUrl.isNullOrEmpty()) {
      links.addChild("a", "href", ExternalLinkToadlet.escape(info.releasePageUrl), "Release Notes")
      links.addChild("#", "  ")
    }
    // Store links if present on chosen artifact
    val spec = selectedSpec
    if (spec?.storeUrl != null) {
      links.addChild("a", "href", ExternalLinkToadlet.escape(spec.storeUrl), "Open in Store")
      links.addChild("#", "  ")
    }
    alertNode.addChild(links)

    val f = fetcher
    if (f == null) {
      // Download button
      val form = HTMLNode("form", arrayOf("action", "method"), arrayOf("/core-update/", "post"))
      form.addChild(
        "input",
        arrayOf("type", "name", "value"),
        arrayOf("hidden", "action", "download"),
      )
      form.addChild(
        "input",
        arrayOf("type", "name", "value"),
        arrayOf("hidden", "formPassword", manager.getNode().getClientCore().formPassword),
      )
      form.addChild(
        "input",
        arrayOf("type", "name", "value"),
        arrayOf("submit", "start", "Download"),
      )
      alertNode.addChild(form)
    } else {
      // Progress + Install button
      val prog = HTMLNode("p")
      val pct = f.progressPercent()
      prog.addChild("#", if (pct >= 0) "Downloading: $pct%" else "Downloading…")
      alertNode.addChild(prog)

      val ready = f.isComplete()
      val installForm =
        HTMLNode("form", arrayOf("action", "method"), arrayOf("/core-update/", "post"))
      installForm.addChild(
        "input",
        arrayOf("type", "name", "value"),
        arrayOf("hidden", "action", "install"),
      )
      installForm.addChild(
        "input",
        arrayOf("type", "name", "value"),
        arrayOf("hidden", "path", (f.completedFileOrNull() ?: downloadTarget())?.absolutePath ?: ""),
      )
      installForm.addChild(
        "input",
        arrayOf("type", "name", "value"),
        arrayOf("hidden", "formPassword", manager.getNode().getClientCore().formPassword),
      )
      val attrs = if (ready) arrayOf("type", "value") else arrayOf("type", "value", "disabled")
      val vals =
        if (ready) arrayOf("submit", "Install") else arrayOf("submit", "Install", "disabled")
      installForm.addChild("input", attrs, vals)
      alertNode.addChild(installForm)
    }
  }

  /** Lightweight fetcher for a single CHK saved directly to a File. */
  inner class PackageFetcher(private val outFile: File, private val chk: FreenetURI) :
    ClientGetCallback, RequestClient, ClientEventListener {
    @Volatile private var getter: ClientGetter? = null
    @Volatile private var lastPct: Int = -1
    @Volatile private var complete: Boolean = false
    @Volatile private var successFile: File? = null

    fun start() {
      val ctx = manager.node.clientCore.makeClient(0.toShort(), true, false).fetchContext
      val fb = FileBucket(outFile, false, false, false, false)
      getter =
        ClientGetter(
          this,
          chk,
          ctx,
          RequestStarter.IMMEDIATE_SPLITFILE_PRIORITY_CLASS,
          fb,
          null,
          null,
        )
      ctx.eventProducer.addEventListener(this)
      try {
        manager.node.clientCore.clientContext.start(getter)
      } catch (e: FetchException) {
        Logger.error(this, "Failed to start package download: $e", e)
      } catch (e: Exception) {
        Logger.error(this, "Error starting package download: $e", e)
      }
    }

    /** Whether the CHK transfer has finished (success or failure). */
    fun isComplete(): Boolean = complete

    /** The downloaded file on success; null if the transfer failed or is running. */
    fun completedFileOrNull(): File? = successFile

    /** Integer 0–100 when known, or -1 if progress cannot be computed. */
    fun progressPercent(): Int = lastPct

    override fun onSuccess(result: FetchResult, state: ClientGetter) {
      complete = true
      successFile = outFile
    }

    override fun onFailure(e: FetchException, state: ClientGetter) {
      complete = true
      successFile = null
      if (e.mode == FetchExceptionMode.CANCELLED) return
      Logger.error(this, "Package download failed: $e", e)
    }

    override fun onResume(context: ClientContext) {}

    override fun realTimeFlag(): Boolean = false

    override fun persistent(): Boolean = false

    override fun getRequestClient(): RequestClient = this

    override fun receive(ce: ClientEvent, context: ClientContext) {
      // We don’t have splitfile events here (no type), keep placeholder.
      // Future: hook SplitfileProgressEvent to compute percent.
    }
  }
}

/** Minimal JSON parser for the CoreInfo schema used by CoreUpdater. */
internal object CoreJson {
  fun parse(json: String): CoreInfo {
    // Very small, permissive parser: only handles strings, numbers, booleans, null, and nested
    // objects with string keys. Arrays are not used by the schema.
    val map = JsonMini.parseObject(json)
    val version = map["version"] as? String
    val release = map["release_page_url"] as? String
    val pkgsRaw = map["packages"] as? Map<*, *> ?: emptyMap<String, Any>()
    val pkgs = mutableMapOf<String, PackageSpec>()
    for ((k, v) in pkgsRaw) {
      val key = k as? String ?: continue
      val o = v as? Map<*, *> ?: continue
      pkgs[key] =
        PackageSpec(
          chk = o["chk"] as? String,
          size = (o["size"] as? Number)?.toLong(),
          sha256 = o["sha256"] as? String,
          storeUrl = o["store_url"] as? String,
        )
    }
    val shortC = map["changelog_chk"] as? String
    val fullC = map["fullchangelog_chk"] as? String
    return CoreInfo(version, release, pkgs, shortC, fullC)
  }
}

/** Extremely small JSON reader sufficient for CoreInfo. Not a general-purpose JSON parser. */
internal object JsonMini {
  private class P(val s: String) {
    var i = 0
  }

  fun parseObject(s: String): Map<String, Any?> {
    val p = P(s)
    return parseObjectInPlace(p)
  }

  private fun parseObjectInPlace(p: P): Map<String, Any?> {
    skipWs(p)
    expect(p, '{')
    val m = mutableMapOf<String, Any?>()
    skipWs(p)
    if (peek(p) == '}') {
      p.i++
      return m
    }
    while (true) {
      skipWs(p)
      val k = parseString(p)
      skipWs(p)
      expect(p, ':')
      skipWs(p)
      val v = parseValue(p)
      m[k] = v
      skipWs(p)
      val ch = next(p)
      if (ch == '}') break
      if (ch != ',') error("Expected , or } at ${p.i}")
    }
    return m
  }

  private fun parseArrayInPlace(p: P): List<Any?> {
    expect(p, '[')
    val out = mutableListOf<Any?>()
    skipWs(p)
    if (peek(p) == ']') {
      p.i++
      return out
    }
    while (true) {
      val v = parseValue(p)
      out += v
      skipWs(p)
      val ch = next(p)
      if (ch == ']') break
      if (ch != ',') error("Expected , or ] at ${p.i}")
    }
    return out
  }

  private fun parseValue(p: P): Any? {
    skipWs(p)
    return when (val ch = peek(p)) {
      '"' -> parseString(p)
      '{' -> parseObjectInPlace(p)
      '[' -> parseArrayInPlace(p)
      't' -> {
        expectWord(p, "true")
        true
      }
      'f' -> {
        expectWord(p, "false")
        false
      }
      'n' -> {
        expectWord(p, "null")
        null
      }
      '-',
      in '0'..'9' -> parseNumber(p)
      else -> error("Unexpected char '$ch' at ${p.i}")
    }
  }

  private fun parseNumber(p: P): Number {
    val start = p.i
    var ch = peek(p)
    if (ch == '-') p.i++
    while (peek(p).isDigit()) p.i++
    if (peek(p) == '.') {
      p.i++
      while (peek(p).isDigit()) p.i++
    }
    val sub = p.s.substring(start, p.i)
    return sub.toDouble().let { d -> if (d % 1.0 == 0.0) d.toLong() else d }
  }

  private fun parseString(p: P): String {
    expect(p, '"')
    val sb = StringBuilder()
    while (true) {
      val ch = next(p)
      when (ch) {
        '"' -> return sb.toString()
        '\\' -> {
          val e = next(p)
          sb.append(
            when (e) {
              '"' -> '"'
              '\\' -> '\\'
              '/' -> '/'
              'b' -> '\b'
              'f' -> '\u000C'
              'n' -> '\n'
              'r' -> '\r'
              't' -> '\t'
              'u' -> {
                val hex = p.s.substring(p.i, p.i + 4)
                p.i += 4
                hex.toInt(16).toChar()
              }
              else -> error("Bad escape \\$e at ${p.i}")
            }
          )
        }
        else -> sb.append(ch)
      }
    }
  }

  private fun skipWs(p: P) {
    while (p.i < p.s.length && p.s[p.i].isWhitespace()) p.i++
  }

  private fun next(p: P): Char = p.s[p.i++]

  private fun peek(p: P): Char = if (p.i < p.s.length) p.s[p.i] else '\u0000'

  private fun expect(p: P, ch: Char) {
    val c = next(p)
    if (c != ch) error("Expected '$ch' got '$c' at ${p.i}")
  }

  private fun expectWord(p: P, w: String) {
    for (c in w) expect(p, c)
  }

  // no-op
}
