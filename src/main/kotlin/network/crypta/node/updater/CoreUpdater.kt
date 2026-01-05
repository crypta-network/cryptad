package network.crypta.node.updater

import java.io.File
import java.nio.charset.StandardCharsets
import network.crypta.client.FetchException
import network.crypta.client.FetchException.FetchExceptionMode
import network.crypta.client.FetchResult
import network.crypta.client.async.ClientContext
import network.crypta.client.async.ClientGetCallback
import network.crypta.client.async.ClientGetter
import network.crypta.client.events.ClientEvent
import network.crypta.client.events.ClientEventListener
import network.crypta.client.events.SplitfileProgressEvent
import network.crypta.clients.http.ExternalLinkToadlet
import network.crypta.fs.AppEnv
import network.crypta.keys.FreenetURI
import network.crypta.node.RequestClient
import network.crypta.node.RequestStarter
import network.crypta.support.HTMLNode
import network.crypta.support.SizeUtil
import network.crypta.support.io.FileBucket
import org.slf4j.LoggerFactory

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
 *
 * @param manager owning [NodeUpdateManager] orchestrating update lifecycles.
 * @param uri USK used to fetch manifest editions.
 * @param current current edition at construction time.
 * @param min minimum edition bound for subscriptions.
 * @param max maximum edition bound for subscriptions.
 * @param blobFilenamePrefix prefix applied to manifest blobs written by the base class.
 */
class CoreUpdater(
  manager: NodeUpdateManager,
  uri: FreenetURI,
  current: Int,
  min: Int,
  max: Int,
  blobFilenamePrefix: String,
) : NodeUpdater(manager, uri, current, min, max, blobFilenamePrefix) {
  private val LOG = LoggerFactory.getLogger(CoreUpdater::class.java)

  /** Internal constants used for logging and filesystem defaults. */
  private companion object {
    /** Prefix included in log statements emitted by this updater. */
    private const val LOG_TAG = "[CoreUpdater]"

    /** Fallback folder name when the descriptor omits a version string. */
    private const val UNKNOWN_VERSION = "unknown"
  }

  /** Shared environment detector reused across lifecycle callbacks. */
  private val appEnv = AppEnv()

  /** Latest descriptor fetched from the update USK, if available. */
  @Volatile private var latestInfo: CoreInfo? = null

  /** Currently selected package key in the form `<arch>.<ext>` or null when undecided. */
  @Volatile private var selectedKey: String? = null // "<arch>.<ext>"

  /** Metadata for the selected package, mirroring [selectedKey]. */
  @Volatile private var selectedSpec: PackageSpec? = null

  /** Active package fetcher responsible for downloading the chosen artifact. */
  @Volatile private var fetcher: PackageFetcher? = null

  /** Cached environment detection derived from [AppEnv.detectEnvironment]. */
  @Volatile private var env: AppEnv.EnvDetection? = null

  /** Root directory used for storing downloaded core packages. */
  private val updatesRoot: File
    get() = File(manager.getNode().nodeDir().dir(), "updates/core")

  /** Emit a minor-level log message scoped to this updater. */
  private fun logInfo(message: String) {
    LOG.info("$LOG_TAG $message")
  }

  /** Emit an error-level log message, optionally including a throwable. */
  private fun logError(message: String, throwable: Throwable? = null) {
    if (throwable != null) LOG.error("$LOG_TAG $message", throwable)
    else LOG.error("$LOG_TAG $message")
  }

  /**
   * Identifier passed to the base [NodeUpdater] to describe the manifest being fetched.
   *
   * @return constant file name used when logging manifest operations.
   */
  override fun artifactName(): String = "core-info.json"

  /** No-op hook because manifest fetching state is communicated through [renderProperties]. */
  override fun onStartFetching() {
    // No-op for UI; we render state via renderProperties.
  }

  /**
   * Updates internal selection state when the manifest download completes.
   *
   * @param result fetch result containing the manifest payload.
   * @param build last known build number from the subscription (unused).
   */
  override fun maybeParseManifest(result: FetchResult, build: Int) {
    // Parse JSON (treat fetched blob as UTF-8 text)
    val info = parseInfo(result)
    latestInfo = info
    // Detect environment and select an artifact to propose
    val e = appEnv.detectEnvironment()
    env = e
    selectArtifact(info, e)
    runCatching {
        val versionLabel = info.version ?: "?"
        val managers = e.availableManagers.joinToString(",")
        logInfo(
          "info.json parsed: version=$versionLabel, env=${e.os}/${e.arch} managers=$managers " +
            "selectedKey=${selectedKey ?: "none"}"
        )
        info.releasePageUrl?.takeIf { it.isNotBlank() }?.let { logInfo("release_page_url=$it") }
        if (!info.changelogChk.isNullOrEmpty() || !info.fullChangelogChk.isNullOrEmpty()) {
          logInfo(
            "changelogs: short=${info.changelogChk ?: "-"}, full=${info.fullChangelogChk ?: "-"}"
          )
        }
      }
      .onFailure {}
    // Optionally auto-download when autoupdate=true
    if (manager.isAutoUpdateAllowed && selectedSpec?.chk != null && !hasUsableFetcher()) {
      tryStartDownload()
    }
  }

  /** No-op because all manifest information is retained in-memory. */
  override fun processSuccess(fetched: Int, result: FetchResult, blobFile: File?) {
    // Nothing to persist from info JSON beyond in-memory state.
  }

  /** Short changelog CHK referenced by the descriptor, if available. */
  fun getShortChangelogCHK(): String? = latestInfo?.changelogChk

  /** Full changelog CHK referenced by the descriptor, if available. */
  fun getFullChangelogCHK(): String? = latestInfo?.fullChangelogChk

  /**
   * Converts the retrieved manifest payload into a strongly typed [CoreInfo].
   *
   * @param result manifest fetch payload.
   * @return parsed descriptor describing available packages.
   */
  private fun parseInfo(result: FetchResult): CoreInfo =
    result
      .asBucket()
      .inputStream
      .use { input -> input.reader(StandardCharsets.UTF_8).readText() }
      .let(CoreJson::parse)

  // Environment detection logic has been centralized in AppEnv.

  /**
   * Chooses the preferred package for the detected environment and updates internal state.
   *
   * @param info descriptor that lists platform-specific packages.
   * @param env detected runtime environment.
   */
  private fun selectArtifact(info: CoreInfo, env: AppEnv.EnvDetection) {
    val pkgs = info.packages
    val arch = env.arch
    val order = preferredExtensions(env)

    var chosen: Pair<String, PackageSpec>? = null
    // Prefer extensions in our order. For flatpak/snap, allow selection when only store_url exists
    // (no CHK), so that we can surface an Open in Store action instead of falling back to deb/rpm.
    loop@ for (ext in order) {
      val key = "$arch.$ext"
      val spec = pkgs[key] ?: continue
      if (spec.chk != null) {
        chosen = key to spec
        break@loop
      }
      if (
        env.os == AppEnv.OsKind.LINUX &&
          (ext == "flatpak" || ext == "snap") &&
          !spec.storeUrl.isNullOrEmpty()
      ) {
        chosen = key to spec
        break@loop
      }
    }
    if (chosen == null) {
      chosen = pkgs.firstAvailableForArch(arch)
    }

    selectedKey = chosen?.first
    selectedSpec = chosen?.second
  }

  /** Builds a priority-ordered list of preferred package extensions for the detected OS. */
  private fun preferredExtensions(env: AppEnv.EnvDetection): List<String> =
    when (env.os) {
      AppEnv.OsKind.WINDOWS -> listOf("exe")
      AppEnv.OsKind.MAC -> listOf("dmg")
      AppEnv.OsKind.LINUX -> linuxPreferredExtensions(env)
      else -> emptyList()
    }

  /** Determines the Linux-specific extension ordering, accounting for sandboxed environments. */
  private fun linuxPreferredExtensions(env: AppEnv.EnvDetection): List<String> {
    val managers = env.availableManagers
    val preferred = mutableListOf<String>()
    val fallback = listOf("rpm", "deb", "flatpak", "snap")
    when (runCatching { appEnv.isFlatpak() }.getOrNull()) {
      true -> preferred += "flatpak"
      else -> {
        if ("rpm" in managers) preferred += "rpm"
        if ("dpkg" in managers) preferred += "deb"
        if ("flatpak" in managers) preferred += "flatpak"
        if ("snap" in managers) preferred += "snap"
      }
    }
    // Always fall back to a stable order regardless of detection quirks.
    return (preferred + fallback).distinct()
  }

  /** Resolves the first registered package containing a CHK for the supplied architecture. */
  private fun Map<String, PackageSpec>.firstAvailableForArch(
    arch: String
  ): Pair<String, PackageSpec>? =
    entries
      .firstOrNull { (key, value) -> key.startsWith("$arch.") && value.chk != null }
      ?.let { it.key to it.value }

  /** Computes the version-specific folder underneath [updatesRoot]. */
  private fun updatesDir(): File = File(updatesRoot, latestInfo?.version ?: UNKNOWN_VERSION)

  /**
   * Derives the filesystem target for the currently selected package download.
   *
   * @return output file or null when the selection is incomplete or setup fails.
   */
  private fun downloadTarget(): File? {
    val key = selectedKey ?: return null
    val outDir = updatesDir()
    if (!outDir.exists() && !outDir.mkdirs()) {
      logError("Failed to create updates directory at ${outDir.absolutePath}")
      return null
    }
    return File(outDir, key)
  }

  /** Returns the active fetcher when it targets the currently selected package. */
  private fun fetcherMatchesSelection(): PackageFetcher? {
    val spec = selectedSpec ?: return null
    val chk = spec.chk ?: return null
    return fetcher?.takeIf { it.matchesChk(chk) }
  }

  /** Whether a usable fetcher (in-progress or successful) exists for the current selection. */
  private fun hasUsableFetcher(): Boolean {
    val f = fetcherMatchesSelection() ?: return false
    return !f.hasFailed()
  }

  /** Starts a background fetch using the currently selected package metadata. */
  private fun tryStartDownload() {
    val spec = selectedSpec ?: return
    val target = downloadTarget() ?: return
    val chk = spec.chk ?: return
    val uri = FreenetURI(chk)
    val f = PackageFetcher(target, uri, chk)
    fetcher = f
    logInfo("starting download: key=${selectedKey ?: "?"}, target=${target.absolutePath}, chk=$chk")
    f.start()
  }

  /**
   * Start downloading the currently selected package if not already in progress. Triggered from the
   * Alerts page POST handler.
   */
  fun startDownloadFromUI() {
    if (selectedSpec == null) return
    val matchingFetcher = fetcherMatchesSelection()
    if (matchingFetcher != null) {
      // If a download for the current selection is in progress or already finished, skip.
      if (!matchingFetcher.isComplete() || matchingFetcher.isSuccess()) return
    } else {
      // Prevent overlapping downloads when a different package is still being fetched.
      val inFlight = fetcher?.takeIf { !it.isComplete() }
      if (inFlight != null) {
        logInfo("Skipping download start: another package download is still running")
        return
      }
    }
    // Allow retry when the previous attempt failed or completed unsuccessfully.
    tryStartDownload()
  }

  /** Returns the completed download file on success or null when unavailable. */
  fun getDownloadedFile(): File? =
    fetcherMatchesSelection()?.takeIf { it.isSuccess() }?.completedFileOrNull()

  /**
   * Renders the updater status section into the supplied Alerts HTML node.
   *
   * @param alertNode parent node that receives generated markup.
   */
  fun renderProperties(alertNode: HTMLNode) {
    val info = latestInfo ?: return
    val envNow = env ?: appEnv.detectEnvironment().also { env = it }
    val chosen = selectedKey
    val spec = selectedSpec

    addHeader(alertNode, info, envNow, chosen, spec)
    alertNode.addChild(buildLinksNode(info, spec, chosen))

    val f = fetcherMatchesSelection()
    if (f == null) {
      if (spec?.chk != null) alertNode.addChild(buildDownloadForm())
      return
    }

    if (f.hasFailed()) {
      val msg = f.errorMessage() ?: "Download failed."
      val p = HTMLNode("p").also { it.addChild("#", "Download failed: $msg") }
      alertNode.addChild(p)
      alertNode.addChild(buildRetryForm(isRetry = !f.isFatalFailure()))
      return
    }

    alertNode.addChild(buildProgressNode(f))
    val ready = f.isSuccess()
    val path = getDownloadedFile()?.absolutePath
    alertNode.addChild(buildInstallForm(ready, path))
  }

  /** Adds summary paragraphs describing the selected package and environment. */
  private fun addHeader(
    alertNode: HTMLNode,
    info: CoreInfo,
    env: AppEnv.EnvDetection,
    chosen: String?,
    spec: PackageSpec?,
  ) {
    val status = HTMLNode("p")
    status.addChild("#", "Core update available: version ${info.version ?: "?"}")
    alertNode.addChild(status)

    val det = HTMLNode("p")
    det.addChild("#", "Detected: ${env.os} / ${env.arch}  •  Selected package: ${chosen ?: "n/a"}")
    alertNode.addChild(det)

    val sz = spec?.size
    if (sz != null && sz > 0) {
      val sizeLine = HTMLNode("p")
      sizeLine.addChild("#", "Package size: ${SizeUtil.formatSize(sz, true)}")
      alertNode.addChild(sizeLine)
    }
  }

  /** Creates the paragraph containing release notes and optional store actions. */
  private fun buildLinksNode(info: CoreInfo, spec: PackageSpec?, chosenKey: String?): HTMLNode {
    val links = HTMLNode("p")
    if (!info.releasePageUrl.isNullOrEmpty()) {
      links.addChild("a", "href", ExternalLinkToadlet.escape(info.releasePageUrl), "Release Notes")
      links.addChild("#", "  ")
    }
    // Wire "Open in Store" as a POST form for Linux Flatpak/Snap; otherwise keep external link
    val storeUrl = spec?.storeUrl
    val ext = chosenKey?.substringAfterLast('.')?.lowercase()
    val isLinux =
      env?.os == AppEnv.OsKind.LINUX || runCatching { appEnv.isLinux() }.getOrDefault(false)
    val kind =
      when (ext) {
        "flatpak" -> "flatpak"
        "snap" -> "snap"
        else -> null
      }
    if (!storeUrl.isNullOrEmpty() && kind != null && isLinux) {
      val id = deriveStoreId(kind, storeUrl)
      links.addChild(buildOpenStoreForm(kind, id, storeUrl))
      links.addChild("#", "  ")
    } else if (!storeUrl.isNullOrEmpty()) {
      links.addChild("a", "href", ExternalLinkToadlet.escape(storeUrl), "Open in Store")
      links.addChild("#", "  ")
    }
    return links
  }

  /** Builds a POST form that dispatches a store-opening request for the supplied content. */
  private fun buildOpenStoreForm(kind: String, id: String?, url: String?): HTMLNode =
    newPostForm().apply {
      hiddenInput("action", "openStore")
      hiddenInput("kind", kind)
      id?.takeIf { it.isNotEmpty() }?.let { hiddenInput("id", it) }
      url?.takeIf { it.isNotEmpty() }?.let { hiddenInput("url", it) }
      hiddenInput("formPassword", formPassword())
      submitButton("Open in Store", name = "openStore")
    }

  /** Extracts an identifier from a vendor-specific store URL when catalogued. */
  private fun deriveStoreId(kind: String, url: String): String? =
    try {
      val u = java.net.URI(url)
      val path = u.path ?: return null
      val segs = path.split('/')
      val last = segs.lastOrNull { it.isNotEmpty() } ?: return null
      when (kind.lowercase()) {
        "snap" -> last // snapcraft.io/<name>
        "flatpak" -> last // flathub.org/apps/<appId> (we also handle /apps/details/<appId>)
        else -> null
      }
    } catch (_: Throwable) {
      null
    }

  /** Provides the node form password required by POST submissions. */
  private fun formPassword(): String = manager.getNode().services().clientCore().getFormPassword()

  /** Creates a basic POST form addressed to [CORE_UPDATE_PATH]. */
  private fun newPostForm(): HTMLNode =
    HTMLNode("form", arrayOf("action", "method"), arrayOf(CORE_UPDATE_PATH, "post"))

  /** Adds a hidden input field to the receiver HTML node. */
  private fun HTMLNode.hiddenInput(name: String, value: String) {
    addChild("input", arrayOf("type", "name", "value"), arrayOf("hidden", name, value))
  }

  /** Adds a submit button input to the receiver with optional metadata. */
  private fun HTMLNode.submitButton(
    value: String,
    name: String? = null,
    disabled: Boolean = false,
  ) {
    val attrs = mutableListOf("type", "value")
    val vals = mutableListOf("submit", value)
    name?.let {
      attrs += "name"
      vals += it
    }
    if (disabled) {
      attrs += "disabled"
      vals += "disabled"
    }
    addChild("input", attrs.toTypedArray(), vals.toTypedArray())
  }

  /** Creates the initial download button form for the Alerts panel. */
  private fun buildDownloadForm(): HTMLNode =
    newPostForm().apply {
      hiddenInput("action", "download")
      hiddenInput("formPassword", formPassword())
      submitButton(defaultDownloadLabel(), name = "start")
    }

  /** Creates the retry/download form displayed after a failure. */
  private fun buildRetryForm(isRetry: Boolean): HTMLNode =
    newPostForm().apply {
      hiddenInput("action", "download")
      hiddenInput("formPassword", formPassword())
      val label = if (isRetry) "Retry" else defaultDownloadLabel()
      submitButton(label, name = "start")
    }

  /** Calculates the label for download buttons, including optional size hints. */
  private fun defaultDownloadLabel(): String {
    val bytes = selectedSpec?.size
    return if (bytes != null && bytes > 0) "Download (${SizeUtil.formatSize(bytes, true)})"
    else "Download"
  }

  /** Generates a progress paragraph summarizing current download status. */
  private fun buildProgressNode(f: PackageFetcher): HTMLNode =
    HTMLNode("p").apply {
      val pct = f.progressPercent()
      val blocks = f.blockProgressOrNull()
      val text =
        when {
          f.isSuccess() -> "Download Completed"
          pct >= 0 && blocks != null -> "Downloading: ${pct}% (${blocks.first}/${blocks.second})"
          pct >= 0 -> "Downloading: ${pct}%"
          else -> "Downloading…"
        }
      addChild("#", text)
    }

  /** Creates the Install button form, disabling it until the payload is available. */
  private fun buildInstallForm(ready: Boolean, path: String?): HTMLNode =
    newPostForm().apply {
      hiddenInput("action", "install")
      hiddenInput("path", path ?: "")
      hiddenInput("formPassword", formPassword())
      submitButton("Install", disabled = !ready)
    }

  /** Lightweight fetcher for a single CHK saved directly to a File. */
  inner class PackageFetcher(
    private val outFile: File,
    private val chk: FreenetURI,
    private val chkString: String,
  ) : ClientGetCallback, RequestClient, ClientEventListener {
    /** Active client getter driving the download, if started. */
    @Volatile private var getter: ClientGetter? = null

    /** Last reported percentage (0–100) or -1 when unknown. */
    @Volatile private var lastPct: Int = -1

    /** Last reported number of successfully retrieved blocks. */
    @Volatile private var lastDone: Int = -1

    /** Last reported number of required blocks to complete the transfer. */
    @Volatile private var lastNeed: Int = -1

    /** Flag indicating whether the transfer has finished (success or failure). */
    @Volatile private var complete: Boolean = false

    /** File produced on successful completion, null otherwise. */
    @Volatile private var successFile: File? = null

    /** Indicates that the fetch ended in failure. */
    @Volatile private var failed: Boolean = false

    /** Latest human-readable error message, if any. */
    @Volatile private var errorMsg: String? = null

    /** Tracks whether the last failure was fatal according to the client API. */
    @Volatile private var fatal: Boolean = false

    /** Begins the asynchronous fetch and registers this fetcher as an event listener. */
    fun start() {
      val ctx =
        manager.getNode().services().clientCore().makeClient(0.toShort(), true, false).fetchContext
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
        manager.getNode().services().clientCore().getClientContext().start(getter)
        this@CoreUpdater.logInfo(
          "download started (listener attached): target=${outFile.absolutePath}"
        )
      } catch (e: FetchException) {
        markStartFailure(e.message ?: e.javaClass.simpleName, fatalFlag = safeIsFatal(e))
        ctx.eventProducer.removeEventListener(this)
        getter = null
        this@CoreUpdater.logError(
          "Failed to start package download: ${errorMsg ?: e.javaClass.simpleName}",
          e,
        )
      } catch (e: Exception) {
        markStartFailure(e.message ?: e.javaClass.simpleName, fatalFlag = false)
        ctx.eventProducer.removeEventListener(this)
        getter = null
        this@CoreUpdater.logError(
          "Error starting package download: ${errorMsg ?: e.javaClass.simpleName}",
          e,
        )
      }
    }

    /** Whether the CHK transfer has finished (success or failure). */
    fun isComplete(): Boolean = complete

    /** The downloaded file on success; null if the transfer failed or is running. */
    fun completedFileOrNull(): File? = successFile

    /** Integer 0–100 when known, or -1 if progress cannot be computed. */
    fun progressPercent(): Int = lastPct

    /** Returns (done, needed) blocks when known, otherwise null. */
    fun blockProgressOrNull(): Pair<Int, Int>? =
      if (lastNeed > 0 && lastDone >= 0) Pair(lastDone, lastNeed) else null

    /** True only when the transfer completed successfully. */
    fun isSuccess(): Boolean = complete && !failed && successFile != null

    /** True when the transfer finished with an error. */
    fun hasFailed(): Boolean = complete && failed

    /** Short error message when failed, if any. */
    fun errorMessage(): String? = errorMsg

    /** True if the last failure was fatal according to FetchException.isFatal(). */
    fun isFatalFailure(): Boolean = failed && fatal

    /** Whether this fetcher corresponds to the supplied CHK string. */
    fun matchesChk(candidate: String?): Boolean = candidate != null && candidate == chkString

    /** Records successful completion and logs the saved file. */
    override fun onSuccess(result: FetchResult, state: ClientGetter) {
      complete = true
      successFile = outFile
      failed = false
      errorMsg = null
      this@CoreUpdater.logInfo(
        "download complete: ${outFile.absolutePath} (size=${outFile.length()})"
      )
    }

    /** Records failure information and forwards the exception to the logger. */
    override fun onFailure(e: FetchException, state: ClientGetter) {
      complete = true
      successFile = null
      failed = true
      fatal =
        try {
          e.isFatal
        } catch (_: Throwable) {
          false
        }
      errorMsg = e.message ?: e.javaClass.simpleName
      if (e.mode == FetchExceptionMode.CANCELLED) return
      this@CoreUpdater.logError("Package download failed: ${errorMsg ?: "unknown error"}", e)
    }

    /** Nothing to do when the request resumes; state is driven by client callbacks. */
    override fun onResume(context: ClientContext) {
      // Intentionally no-op: the fetcher relies on ClientGetter's own state and
      // our registered event listener to continue progress reporting after resumes.
      // No additional work is required here.
    }

    /** This request does not require realtime handling. */
    override fun realTimeFlag(): Boolean = false

    /** The request is not persistent beyond its initial scheduling. */
    override fun persistent(): Boolean = false

    /** Provides the [RequestClient] identity required by the async API. */
    override fun getRequestClient(): RequestClient = this

    /** Handles transfer progress events and stores percentage/block metadata for UI updates. */
    override fun receive(ce: ClientEvent, context: ClientContext) {
      // Hook SplitfileProgressEvent to compute percent and block counts.
      try {
        if (ce is SplitfileProgressEvent) {
          val done = ce.succeedBlocks
          var need = ce.minSuccessfulBlocks
          if (need <= 0) need = if (ce.totalBlocks > 0) ce.totalBlocks else 1
          val pctNow = (100 * done) / need
          if (pctNow != lastPct || done != lastDone || need != lastNeed) {
            lastPct = pctNow
            lastDone = done
            lastNeed = need
            this@CoreUpdater.logInfo("progress: ${pctNow}% ($done/$need, total=${ce.totalBlocks})")
          }
        }
      } catch (_: Throwable) {
        // ignore
      }
    }

    /** Guarded read of fatal status for FetchException instances. */
    private fun safeIsFatal(e: FetchException): Boolean =
      try {
        e.isFatal
      } catch (_: Throwable) {
        false
      }

    /** Marks the fetcher as failed during startup, exposing the error to the UI. */
    private fun markStartFailure(message: String?, fatalFlag: Boolean) {
      complete = true
      successFile = null
      failed = true
      fatal = fatalFlag
      errorMsg = message ?: "Failed to start download"
    }
  }
}

/** Minimal JSON parser for the CoreInfo schema used by CoreUpdater. */
internal object CoreJson {
  /** Parses raw JSON text into a [CoreInfo] structure. */
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
          storeUrl = o["store_url"] as? String,
        )
    }
    val shortC = map["changelog_chk"] as? String
    val fullC = map["fullchangelog_chk"] as? String
    return CoreInfo(version, release, pkgs, shortC, fullC)
  }
}

/** Minimal JSON reader sufficient for CoreInfo. Not a general-purpose JSON parser. */
internal object JsonMini {
  private class P(val s: String) {
    var i = 0
  }

  /** Parses a JSON object into a map using a new parser state. */
  fun parseObject(s: String): Map<String, Any?> {
    val p = P(s)
    return parseObjectInPlace(p)
  }

  /** Parses a JSON object from the current state, mutating the parser index. */
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

  /** Parses a JSON array from the current parser state. */
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

  /** Parses the next JSON value, dispatching to specialized helpers. */
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

  /** Parses a numeric literal into either [Long] or [Double]. */
  private fun parseNumber(p: P): Number {
    val start = p.i
    val ch = peek(p)
    if (ch == '-') p.i++
    while (peek(p).isDigit()) p.i++
    if (peek(p) == '.') {
      p.i++
      while (peek(p).isDigit()) p.i++
    }
    val sub = p.s.substring(start, p.i)
    return sub.toDouble().let { d -> if (d % 1.0 == 0.0) d.toLong() else d }
  }

  /** Parses a JSON string literal, handling escape sequences. */
  private fun parseString(p: P): String {
    expect(p, '"')
    val sb = StringBuilder()
    while (true) {
      when (val ch = next(p)) {
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

  /** Advances the parser past any whitespace characters. */
  private fun skipWs(p: P) {
    while (p.i < p.s.length && p.s[p.i].isWhitespace()) p.i++
  }

  /** Returns the next character from the input, advancing the index. */
  private fun next(p: P): Char = p.s[p.i++]

  /** Peeks at the next character or returns NUL when beyond the end. */
  private fun peek(p: P): Char = if (p.i < p.s.length) p.s[p.i] else '\u0000'

  /** Ensures that the next character matches [ch], throwing otherwise. */
  private fun expect(p: P, ch: Char) {
    val c = next(p)
    if (c != ch) error("Expected '$ch' got '$c' at ${p.i}")
  }

  /** Consumes the exact characters from [w], throwing on mismatch. */
  private fun expectWord(p: P, w: String) {
    for (c in w) expect(p, c)
  }

  // no-op
}
