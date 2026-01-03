package network.crypta.node.updater

import java.io.File
import java.net.URI
import network.crypta.client.HighLevelSimpleClient
import network.crypta.clients.http.PageMaker
import network.crypta.clients.http.PageNode
import network.crypta.clients.http.Toadlet
import network.crypta.clients.http.ToadletContext
import network.crypta.fs.AppEnv
import network.crypta.l10n.NodeL10n
import network.crypta.node.Node
import network.crypta.support.HTMLNode
import network.crypta.support.MultiValueTable
import network.crypta.support.api.HTTPRequest
import org.slf4j.LoggerFactory

/**
 * Lightweight HTTP endpoint that wires alert panel buttons to CoreUpdater actions.
 *
 * This toadlet is a thin bridge between the Alerts UI and the core update workflow. It exposes a
 * single, fixed mount path (`/core-update/`) that accepts browser posts initiated by the alert
 * panel. The handler validates the form password, resolves the current [CoreUpdater], and
 * dispatches to well-defined actions (download, install, openStore). Responses are kept
 * intentionally small: most requests redirect back to Alerts, while install/openStore return a
 * compact result page with guidance when an OS-specific manual step is required.
 *
 * Key invariants are defensive: file paths are canonicalized and required to live under the node's
 * `updates/core` subtree, and installation helpers are selected by OS and sandbox state. The class
 * is effectively stateless beyond its dependencies and does not perform blocking work itself;
 * process launches are delegated to the OS and treated as "started" or "manual guidance" outcomes.
 *
 * Responsibilities:
 * <ul>
 * <li>Validate incoming actions and form passwords.</li>
 * <li>Translate alert UI requests into CoreUpdater or installer intents.</li>
 * <li>Render success/failure result pages with targeted guidance.</li>
 * </ul>
 *
 * @param client HTTP client used by the base [Toadlet] implementation.
 * @param node backing node instance that exposes updater state.
 */
class CoreActionToadlet(client: HighLevelSimpleClient, private val node: Node) : Toadlet(client) {
  private val log = LoggerFactory.getLogger(CoreActionToadlet::class.java)

  /** Shared environment detector used for installer heuristics. */
  private val appEnv = AppEnv()
  private val l10n = NodeL10n.getBase()

  /** Resolves CoreActionToadlet strings from the localization bundle. */
  private fun t(key: String, replacements: Map<String, String> = emptyMap()): String {
    if (replacements.isEmpty()) return l10n.getString("CoreActionToadlet.$key")
    val entries = replacements.entries.toList()
    val patterns = entries.map { it.key }.toTypedArray()
    val values = entries.map { it.value }.toTypedArray()
    return l10n.getString("CoreActionToadlet.$key", patterns, values)
  }

  private data class LocalMessage(
    val key: String,
    val replacements: Map<String, String> = emptyMap(),
  )

  private fun msg(key: String, replacements: Map<String, String> = emptyMap()): LocalMessage =
    LocalMessage(key, replacements.toMap())

  private fun LocalMessage.render(): String = t(this.key, this.replacements)

  /** Internal constants that coordinate logging and format-specific handling. */
  private companion object {
    /** Prefix included in log statements emitted by this toadlet. */
    private const val LOG_TAG = "[CoreActionToadlet]"

    /** File extension for flatpak bundles. */
    private const val EXT_FLATPAK = ".flatpak"

    /** File extension for flatpak references. */
    private const val EXT_FLATPAKREF = ".flatpakref"

    /** File extension for snap packages. */
    private const val EXT_SNAP = ".snap"

    /** Command name used to bridge out of Flatpak sandboxes. */
    private const val CMD_FLATPAK_SPAWN = "flatpak-spawn"

    /** Command name for portal-friendly open invocation. */
    private const val CMD_XDG_OPEN = "xdg-open"

    /** Argument enabling non-interactive acknowledgement for package managers. */
    private const val ARG_ASSUME_YES = "--assumeyes"

    /** Argument requesting per-user scope for Flatpak installs. */
    private const val ARG_USER = "--user"

    /** Argument used to target the host environment when bridging out of Flatpak sandboxes. */
    private const val ARG_HOST = "--host"

    /** Marker string representing rpm-ostree systems. */
    private const val TAG_RPM_OSTREE = "RPM-OSTREE"

    /** CSS class used for informational infoboxes. */
    private const val INFOBOX_INFORMATION = "infobox-information"
  }

  /** Emits a minor-level log line for CoreActionToadlet operations. */
  private fun logInfo(message: String) {
    log.info("$LOG_TAG $message")
  }

  /**
   * Exposes the HTTP mount point served by this toadlet.
   *
   * The mount path is stable (`/core-update/`) so the Alerts UI can post actions without needing to
   * discover the URL at runtime. Callers should treat this as read-only metadata; it has no side
   * effects and does not depend on node state. Tests and log statements can also rely on this value
   * remaining constant across releases because alert wiring assumes a fixed endpoint.
   *
   * @return constant path segment used to route requests for this toadlet instance.
   */
  override fun path(): String = CORE_UPDATE_PATH

  /**
   * Handles GET requests by redirecting users back to the Alerts page.
   *
   * This endpoint is not intended for direct browsing. A GET request is answered with a 302 to
   * `/alerts/` so the user returns to the main status view. The handler does not read parameters
   * and does not mutate state; it simply returns an HTTP redirect with a Location header.
   *
   * @param uri absolute request URI for logging/debugging context only.
   * @param request HTTP request wrapper; ignored aside from standard toadlet dispatch.
   * @param ctx context used to emit the redirect response.
   */
  override fun handleMethodGET(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    // Redirect to alerts page by default
    val headers = MultiValueTable.from("Location", "/alerts/")
    ctx.sendReplyHeaders(302, "Found", headers, null, 0)
  }

  /**
   * Handles download, install, and store-opening POST actions from the Alerts UI.
   *
   * The request must include a valid form password; otherwise no action is taken and the call
   * returns silently to avoid leaking status. The `action` field controls the dispatch path and is
   * limited to a small whitelist (`download`, `install`, `openStore`). The implementation delegates
   * to specific helpers that validate inputs and emit either a redirect or a small result page with
   * user guidance. This method is not idempotent for download/install actions; callers should avoid
   * automatic retries if the user already confirmed the action in the UI.
   *
   * @param uri absolute request URI used only for log context.
   * @param request HTTP request providing action parameters and form password.
   * @param ctx toadlet context used to send redirects or HTML result pages.
   */
  fun handleMethodPOST(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    logInfo("POST /core-update uri=$uri")
    if (!ctx.checkFormPassword(request)) {
      logInfo("POST /core-update rejected: invalid form password")
      return
    }
    val updater = node.nodeUpdater.coreUpdater ?: return redirect(ctx)
    when (request.getPartAsStringFailsafe("action", 32)) {
      "download" -> handleDownload(updater, ctx)
      "install" -> handleInstall(request, ctx)
      "openStore" -> handleOpenStore(request, ctx)
      else -> redirect(ctx)
    }
  }

  /** Triggers a download through [CoreUpdater] and redirects back to Alerts. */
  private fun handleDownload(updater: CoreUpdater, ctx: ToadletContext) {
    logInfo("POST /core-update action=download")
    updater.startDownloadFromUI()
    redirect(ctx)
  }

  /** Validates the requested path and initiates OS-specific installation behavior. */
  private fun handleInstall(request: HTTPRequest, ctx: ToadletContext) {
    val path = request.getPartAsStringFailsafe("path", 4096)
    logInfo("POST /core-update action=install path=$path")
    val okPath = validatePath(path)
    if (okPath == null) {
      logInfo("install rejected: invalid path")
      writeMessage(ctx, false, t("invalidPath"))
      return
    }
    val outcome = tryInstall(okPath)
    val logReplacements = outcome.message.replacements.filterKeys { it != "extra" }
    logInfo(
      "install result: success=${outcome.success}, messageKey=${outcome.message.key}, replacements=${logReplacements}"
    )
    writeInstallResult(ctx, outcome.success, outcome.message.render(), okPath)
  }

  /** Processes store-opening requests, launching either GUI or CLI helpers. */
  private fun handleOpenStore(request: HTTPRequest, ctx: ToadletContext) {
    val kind = request.getPartAsStringFailsafe("kind", 32)
    val id = request.getPartAsStringFailsafe("id", 256)
    val url = request.getPartAsStringFailsafe("url", 2048)
    logInfo("POST /core-update action=openStore kind=$kind id=$id url=$url")
    val delegate =
      when (appEnv.osKind()) {
        AppEnv.OsKind.LINUX -> linuxOpenStore(kind, id.ifBlank { null }, url.ifBlank { null })
        AppEnv.OsKind.MAC ->
          if (url.isNotBlank())
            InstallerDelegate.Spawn(ProcessBuilder("open", url), msg("store.openingPage"))
          else InstallerDelegate.Manual(msg("store.invalidUrl.mac"))
        AppEnv.OsKind.WINDOWS ->
          if (url.isNotBlank())
            InstallerDelegate.Spawn(
              ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url),
              msg("store.openingPage"),
            )
          else InstallerDelegate.Manual(msg("store.invalidUrl.windows"))
        else -> InstallerDelegate.Manual(msg("store.unsupportedPlatform"))
      }
    when (delegate) {
      is InstallerDelegate.Spawn -> {
        try {
          delegate.pb.start()
          writeMessage(ctx, true, delegate.message.render())
        } catch (throwable: Throwable) {
          val reason = throwable.message ?: throwable.javaClass.simpleName
          writeMessage(ctx, false, msg("store.openFailed", mapOf("reason" to reason)).render())
        }
      }
      is InstallerDelegate.Manual -> writeMessage(ctx, false, delegate.message.render())
    }
  }

  /**
   * Ensure the provided file path resolves inside `nodeDir/updates/core`. Returns the canonical
   * `File` or null when invalid/untrusted.
   */
  /** Performs canonical path validation to ensure downloads reside under the node updates tree. */
  private fun validatePath(path: String): File? {
    if (path.isBlank()) return null
    val base = File(node.nodeDir, "updates/core").canonicalFile
    val canonical = runCatching { File(path).canonicalFile }.getOrNull() ?: return null
    val basePath = base.toPath()
    val candidatePath = canonical.toPath()
    return canonical.takeIf { candidatePath.startsWith(basePath) }
  }

  /**
   * Best‑effort attempt to launch the OS installer for the given file. Returns `(success, message)`
   * where message is suitable for user display.
   */
  /** Attempts to launch an OS-appropriate installer for the provided file. */
  private data class InstallOutcome(val success: Boolean, val message: LocalMessage)

  private fun tryInstall(file: File): InstallOutcome {
    val delegate =
      when (appEnv.osKind()) {
        AppEnv.OsKind.WINDOWS ->
          InstallerDelegate.Spawn(
            ProcessBuilder("cmd", "/c", "\"${file.absolutePath}\""),
            msg("installer.launched.windows"),
          )
        AppEnv.OsKind.MAC -> macInstaller(file)
        AppEnv.OsKind.LINUX -> linuxInstaller(file)
        else -> InstallerDelegate.Manual(msg("installer.unsupportedOs"))
      }
    return runCatching {
        when (delegate) {
          is InstallerDelegate.Spawn -> {
            delegate.pb.start()
            InstallOutcome(true, delegate.message)
          }
          is InstallerDelegate.Manual -> InstallOutcome(false, delegate.message)
        }
      }
      .getOrElse { throwable ->
        val reason = throwable.message ?: throwable.javaClass.simpleName
        InstallOutcome(false, msg("installer.launchFailed", mapOf("reason" to reason)))
      }
  }

  /** Builds a delegate that opens `.dmg` images with Finder on macOS. */
  private fun macInstaller(file: File): InstallerDelegate {
    val escapedPath = file.absolutePath.replace("\\", "\\\\").replace("\"", "\\\"")
    val script =
      listOf(
        """tell application "Finder" to open POSIX file "$escapedPath"""",
        """tell application "Finder" to activate""",
      )
    val command = buildList {
      add("osascript")
      script.forEach {
        add("-e")
        add(it)
      }
    }
    return InstallerDelegate.Spawn(ProcessBuilder(command), msg("installer.launched.mac"))
  }

  /**
   * Linux installer strategy that aims to provide a native, polkit‑backed desktop UX when available
   * and safe fallbacks when not. It does not prompt for credentials in‑app.
   *
   * Rules (summarized):
   * - Desktop host (non‑sandboxed): prefer GUI hand‑off (xdg-open/gio open). Fallback to PackageKit
   *   CLI (pkcon install-local) which triggers a polkit prompt.
   * - Desktop sandboxed (Flatpak/Snap): prefer host hand‑off via `flatpak-spawn --host` where
   *   available, else rely on xdg-desktop-portal (xdg-open) to open the host Software Center.
   * - Headless/service: do not attempt an interactive installation. Return guidance for the admin
   *   with a concrete command to run as root.
   * - Immutable rpm-ostree: suggest `rpm-ostree install` flow and note reboot.
   */
  /** Determines the appropriate Linux installation strategy for the provided file. */
  private fun linuxInstaller(file: File): InstallerDelegate {
    val lowerName = file.name.lowercase()
    val isService = appEnv.isServiceMode()
    val inFlatpak = appEnv.isFlatpak()
    val ostree = isOstree()

    // Headless/systemd service: prefer oneshot helper unit; if unavailable, return guidance.
    if (isService) {
      val unitDelegate = headlessUnitDelegate(file)
      return unitDelegate ?: InstallerDelegate.Manual(headlessGuidance(lowerName, file, ostree))
    }

    // Desktop: prefer native GUI hand-off for most types, but NEVER for .snap (Ubuntu will mount
    // snaps as disk images). For snaps, we always use `snap install --dangerous`.
    val isSnapPkg = lowerName.endsWith(EXT_SNAP)
    var guiOpenCmd: ProcessBuilder? =
      if (isSnapPkg) null else guiOpenCommand(file, preferHost = inFlatpak)
    // If running in Flatpak and opener not available, try host Software Center with
    // --local-filename
    if (
      guiOpenCmd == null &&
        inFlatpak &&
        (lowerName.endsWith(EXT_FLATPAK) || lowerName.endsWith(EXT_FLATPAKREF)) &&
        appEnv.onPath(CMD_FLATPAK_SPAWN)
    ) {
      guiOpenCmd = hostSoftwareCenterOpen(file)
    }

    // Per-format fallbacks when GUI hand-off is unavailable.
    val fallback: InstallerDelegate =
      when {
        lowerName.endsWith(".deb") -> debFallback(file)
        lowerName.endsWith(".rpm") -> rpmFallback(file, ostree)
        lowerName.endsWith(EXT_FLATPAKREF) || lowerName.endsWith(EXT_FLATPAK) ->
          flatpakFallback(file)
        lowerName.endsWith(EXT_SNAP) -> snapFallback(file)
        else ->
          InstallerDelegate.Manual(msg("installer.unsupportedPackage", mapOf("name" to file.name)))
      }

    // Prefer GUI if we have a way to open it. Otherwise, return fallback command.
    return if (guiOpenCmd != null) {
      InstallerDelegate.Spawn(guiOpenCmd, msg("installer.guiHandOff"))
    } else fallback
  }

  /** Try opening a local Flatpak bundle/ref via the host's app center. */
  /** Builds a command that launches the host software center for Flatpak content. */
  private fun hostSoftwareCenterOpen(file: File): ProcessBuilder {
    val path = file.absolutePath
    // Prefer GNOME Software, then Plasma Discover; fall back to xdg-open.
    val cmd =
      """
        command -v gnome-software >/dev/null 2>&1 && exec gnome-software --local-filename '$path' ||
        command -v plasma-discover >/dev/null 2>&1 && exec plasma-discover --local-filename '$path' ||
        exec xdg-open '$path'
      """
        .trimIndent()
    return ProcessBuilder("flatpak-spawn", ARG_HOST, "sh", "-lc", cmd)
  }

  /** Represents how to carry out an installation action on Linux. */
  private sealed interface InstallerDelegate {
    /** Executes an external process and reports success when it launches. */
    data class Spawn(val pb: ProcessBuilder, val message: LocalMessage) : InstallerDelegate

    /** Communicates manual instructions when automation is not possible. */
    data class Manual(val message: LocalMessage) : InstallerDelegate
  }

  /** Detects rpm-ostree based systems (immutable operating environments). */
  private fun isOstree(): Boolean {
    // Prefer runtime marker file; fall back to presence of rpm-ostree tool
    return File("/run/ostree-booted").exists() || appEnv.onPath("rpm-ostree")
  }

  /**
   * Build a GUI "open this package" command, using host bridging when inside Flatpak. Returns null
   * when neither xdg-open nor gio is available.
   */
  /** Builds a GUI opener command for local files, considering sandbox constraints. */
  private fun guiOpenCommand(file: File, preferHost: Boolean): ProcessBuilder? {
    return guiOpenCommandForTarget(file.absolutePath, preferHost)
  }

  /** Choose preferred GUI opener available on PATH, including subcommand args. */
  /** Chooses the first available GUI opener command from the current environment. */
  private fun pickGuiOpener(): List<String>? {
    return when {
      appEnv.onPath("gio") -> listOf("gio", "open")
      appEnv.onPath(CMD_XDG_OPEN) -> listOf(CMD_XDG_OPEN)
      else -> null
    }
  }

  /** Build a GUI opener for a URL (not a local file). */
  /** Builds a GUI opener for URLs, preferring portal-aware commands when sandboxed. */
  private fun guiOpenUrlCommand(url: String, preferHost: Boolean): ProcessBuilder? {
    return guiOpenCommandForTarget(url, preferHost)
  }

  /** Builds a GUI opener command for an arbitrary target string. */
  private fun guiOpenCommandForTarget(target: String, preferHost: Boolean): ProcessBuilder? {
    // In Flatpak, prefer opening via the portal from inside the sandbox (xdg-open), which will
    // hand off to the host GUI safely. Fall back to host bridging only when needed.
    if (preferHost && appEnv.onPath(CMD_XDG_OPEN)) {
      return ProcessBuilder(CMD_XDG_OPEN, target)
    }
    val opener = pickGuiOpener() ?: return null
    if (preferHost && appEnv.onPath(CMD_FLATPAK_SPAWN)) {
      return ProcessBuilder(mutableListOf(CMD_FLATPAK_SPAWN, ARG_HOST) + opener + target)
    }
    return ProcessBuilder(opener + target)
  }

  /** Cross‑distro fallback sequence for local DEB packages using PackageKit or apt/dpkg flows. */
  private fun debFallback(file: File): InstallerDelegate {
    val path = file.absolutePath
    return when {
      appEnv.onPath("pkcon") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkcon", "install-local", "-y", path),
          msg("linux.packagekitInstall"),
        )
      // As a last resort: apt-get with pkexec, resolving deps via ./file.deb syntax
      appEnv.onPath("pkexec") && appEnv.onPath("apt-get") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "apt-get", "install", "-y", "./${file.name}")
            .directory(file.parentFile),
          msg("linux.aptInstall"),
        )
      appEnv.onPath("dpkg") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "dpkg", "-i", path),
          msg("linux.dpkgInstall"),
        )
      else -> InstallerDelegate.Manual(manualMsg("DEB", path))
    }
  }

  /** Cross‑distro fallback sequence for local RPM packages with rpm-ostree awareness. */
  private fun rpmFallback(file: File, ostree: Boolean): InstallerDelegate {
    val path = file.absolutePath
    if (ostree) {
      return InstallerDelegate.Manual(msg("linux.rpmOstreeManual", mapOf("path" to path)))
    }
    return when {
      appEnv.onPath("pkcon") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkcon", "install-local", "-y", path),
          msg("linux.packagekitInstall"),
        )
      appEnv.onPath("pkexec") && appEnv.onPath("dnf") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "dnf", "install", "-y", path),
          msg("linux.dnfInstall"),
        )
      appEnv.onPath("pkexec") && appEnv.onPath("zypper") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "zypper", "--non-interactive", "install", path),
          msg("linux.zypperInstall"),
        )
      appEnv.onPath("rpm") && appEnv.onPath("pkexec") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "rpm", "-Uvh", path),
          msg("linux.rpmInstall"),
        )
      else -> InstallerDelegate.Manual(manualMsg("RPM", path))
    }
  }

  /** Prefer per‑user Flatpak installs on desktops when the Flatpak runtime is available. */
  private fun flatpakFallback(file: File): InstallerDelegate {
    val path = file.absolutePath
    if (!appEnv.onPath("flatpak")) return InstallerDelegate.Manual(manualMsg("Flatpak", path))
    val sub = listOf("install", ARG_ASSUME_YES, ARG_USER, path)
    return InstallerDelegate.Spawn(
      ProcessBuilder(listOf("flatpak") + sub),
      msg("linux.flatpakInstall"),
    )
  }

  /** Snap fallback for local `.snap` files, preferring GUI when allowed and pkexec otherwise. */
  private fun snapFallback(file: File): InstallerDelegate {
    val path = file.absolutePath
    // Always use 'snap install --dangerous' for local snap files.
    // IMPORTANT: When running inside a Snap sandbox, we cannot call pkexec or elevate privileges
    // on the host. In that case we only provide manual guidance to run the command on the host.
    if (appEnv.isSnap()) {
      return InstallerDelegate.Manual(msg("linux.snapSandboxManualHost"))
    }
    // Desktop host (non-snap): require polkit via pkexec. If pkexec/snap are unavailable, do not
    // attempt unprivileged installs; provide manual guidance instead.
    return if (appEnv.onPath("pkexec") && appEnv.onPath("snap")) {
      InstallerDelegate.Spawn(
        ProcessBuilder("pkexec", "snap", "install", "--dangerous", path),
        msg("linux.snapInstall"),
      )
    } else {
      InstallerDelegate.Manual(msg("linux.snapManualHost", mapOf("path" to path)))
    }
  }

  /** Builds guidance text for headless or service-mode installations. */
  private fun headlessGuidance(nameLower: String, file: File, ostree: Boolean): LocalMessage {
    val path = file.absolutePath
    val tag =
      when {
        nameLower.endsWith(".deb") -> "DEB"
        nameLower.endsWith(".rpm") -> if (ostree) TAG_RPM_OSTREE else "RPM"
        nameLower.endsWith(EXT_FLATPAK) || nameLower.endsWith(EXT_FLATPAKREF) -> "Flatpak"
        nameLower.endsWith(".snap") -> "Snap"
        else -> "Package"
      }
    val suggestion =
      when (tag) {
        "DEB" -> "pkcon install-local -y '${path}'"
        TAG_RPM_OSTREE -> "rpm-ostree install '${path}'"
        "RPM" -> "pkcon install-local -y '${path}'"
        "Flatpak" -> "flatpak install $ARG_ASSUME_YES --system '${path}'"
        "Snap" -> "snap install --dangerous '${path}'"
        else -> "<install-command> '${path}'"
      }
    val extra = if (tag == TAG_RPM_OSTREE) " " + t("linux.headlessGuidanceExtra") else ""
    return msg("linux.headlessGuidance", mapOf("command" to suggestion, "extra" to extra))
  }

  /** Creates a generic manual-installation message for unsupported automation. */
  private fun manualMsg(kind: String, path: String): LocalMessage =
    msg("linux.manualGuidance", mapOf("kind" to kind, "path" to path))

  /** Attempts to start the systemd helper unit that performs headless installations. */
  private fun headlessUnitDelegate(file: File): InstallerDelegate? {
    if (!appEnv.onPath("systemctl") || !appEnv.onPath("systemd-escape")) return null
    return try {
      val escaped =
        ProcessBuilder("systemd-escape", "--path", file.absolutePath)
          .redirectErrorStream(true)
          .start()
          .let { p ->
            val out = p.inputStream.bufferedReader().readText().trim()
            p.waitFor()
            if (p.exitValue() == 0 && out.isNotEmpty()) out else null
          } ?: return null
      val unit = "cryptad-core-install@${escaped}.service"
      val pb = ProcessBuilder("systemctl", "start", unit)
      InstallerDelegate.Spawn(pb, msg("linux.headlessUnit", mapOf("unit" to unit)))
    } catch (_: Throwable) {
      null
    }
  }

  /** Handles store installations by name or explicit URLs. */
  private fun linuxOpenStore(kind: String, id: String?, url: String?): InstallerDelegate {
    // Prefer explicit URL when provided.
    val preferHost = appEnv.isFlatpak()
    // Snap sandbox: do not attempt automatic install or store hand-off for Snap from within Snap.
    if (kind.equals("snap", ignoreCase = true) && appEnv.isSnap()) {
      val name = id ?: "<package>"
      return InstallerDelegate.Manual(msg("store.snapSandboxManual", mapOf("package" to name)))
    }
    val targetUrl =
      when {
        !url.isNullOrBlank() -> url
        kind.equals("snap", ignoreCase = true) && !id.isNullOrBlank() -> "snap://${id}"
        kind.equals("flatpak", ignoreCase = true) && !id.isNullOrBlank() ->
          // appstream is widely handled by GNOME/KDE software centers; fallback to flathub page
          if (appEnv.onPath("gio") || appEnv.onPath(CMD_XDG_OPEN)) "appstream://${id}"
          else "https://flathub.org/apps/${id}"
        else -> null
      }
    if (targetUrl != null) {
      val opener = guiOpenUrlCommand(targetUrl, preferHost)
      if (opener != null)
        return InstallerDelegate.Spawn(
          opener,
          msg("store.openingSpecificPage", mapOf("url" to targetUrl)),
        )
    }
    // Fallback to CLI store install when GUI handoff isn't available
    return when {
      kind.equals("flatpak", true) && !id.isNullOrBlank() && appEnv.onPath("flatpak") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("flatpak", "install", ARG_ASSUME_YES, ARG_USER, "flathub", id),
          msg("store.installFlathub", mapOf("id" to id)),
        )
      kind.equals("snap", true) &&
        !id.isNullOrBlank() &&
        appEnv.onPath("pkexec") &&
        appEnv.onPath("snap") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "snap", "install", id),
          msg("store.installSnap", mapOf("id" to id)),
        )
      else ->
        InstallerDelegate.Manual(msg("store.unableToOpen", mapOf("idOrUrl" to (id ?: url ?: "?"))))
    }
  }

  /** Issues a 302 redirect back to the Alerts page. */
  private fun redirect(ctx: ToadletContext) {
    val headers = MultiValueTable.from("Location", "/alerts/")
    ctx.sendReplyHeaders(302, "Found", headers, null, 0)
  }

  /** Renders a compact result page conveying success or failure for store actions. */
  private fun writeMessage(ctx: ToadletContext, success: Boolean, msg: String) {
    val view = renderResultPage(ctx, success, msg)
    addHomepageLink(view.content)
    // Allow JS on result page; CSP was previously too strict here.
    this.writeHTMLReply(ctx, 200, "OK", null, view.page.generate(), false)
  }

  /** Renders the installation result page, appending platform-specific guidance. */
  private fun writeInstallResult(ctx: ToadletContext, success: Boolean, msg: String, file: File) {
    val view = renderResultPage(ctx, success, msg)

    // Add OS/package-specific guidance below the result for a better UX.
    addInstallGuidance(view.content, view.pageMaker, file)

    addHomepageLink(view.content)
    this.writeHTMLReply(ctx, 200, "OK", null, view.page.generate(), false)
  }

  private data class ResultPage(
    val pageMaker: PageMaker,
    val page: PageNode,
    val content: HTMLNode,
  )

  private fun renderResultPage(ctx: ToadletContext, success: Boolean, msg: String): ResultPage {
    val pm = ctx.pageMaker
    val title = if (success) t("install.titleSuccess") else t("install.titleFailure")
    val page =
      pm.getPageNode(
        title,
        ctx,
        PageMaker.RenderParameters().renderNavigationLinks(true).renderStatus(true),
      )
    val content: HTMLNode = page.contentNode
    val box =
      pm.getInfobox(
        if (success) "infobox-success" else "infobox-warning",
        title,
        content,
        "core-installer-result",
        true,
      )
    box.addChild("p").addChild("#", msg)
    return ResultPage(pm, page, content)
  }

  /** Appends guidance boxes for common edge cases (e.g., macOS Gatekeeper). */
  private fun addInstallGuidance(content: HTMLNode, pm: PageMaker, file: File) {
    when (appEnv.osKind()) {
      AppEnv.OsKind.MAC -> if (file.name.lowercase().endsWith(".dmg")) macDmgGuidance(content, pm)
      AppEnv.OsKind.LINUX ->
        if (file.name.lowercase().endsWith(EXT_SNAP))
          linuxSnapGuidance(content, pm, file, appEnv.onPath("snap"))
      AppEnv.OsKind.WINDOWS ->
        if (file.name.lowercase().endsWith(".exe")) windowsExeGuidance(content, pm)
      else -> Unit
    }
  }

  /** Provides detailed steps for macOS Gatekeeper when handling unsigned builds. */
  private fun macDmgGuidance(content: HTMLNode, pm: PageMaker) {
    val box =
      pm.getInfobox(
        INFOBOX_INFORMATION,
        t("macGuidance.title"),
        content,
        "core-install-guidance-macos",
        true,
      )
    box.addChild("p").addChild("#", t("macGuidance.intro"))
    val steps = box.addChild("ul")
    steps.addChild("li").addChild("#", t("macGuidance.stepDrag"))
    steps.addChild("li").addChild("#", t("macGuidance.stepOpenConfirm"))
    steps.addChild("li").addChild("#", t("macGuidance.stepSettings"))
    val alt = box.addChild("li")
    alt.addChild("#", t("macGuidance.advancedIntro"))
    val pre = box.addChild("pre")
    pre.addChild("#", t("macGuidance.commandXattr"))
    val verify = box.addChild("p")
    verify.addChild("#", t("macGuidance.verifyLabel"))
    val pre2 = box.addChild("pre")
    pre2.addChild("#", t("macGuidance.commandSpctl"))
  }

  /** Supplies tips for Windows SmartScreen when launching unsigned installers. */
  private fun windowsExeGuidance(content: HTMLNode, pm: PageMaker) {
    val box =
      pm.getInfobox(
        INFOBOX_INFORMATION,
        t("windowsGuidance.title"),
        content,
        "core-install-guidance-windows",
        true,
      )
    box.addChild("p").addChild("#", t("windowsGuidance.intro"))
    val ul = box.addChild("ul")
    ul.addChild("li").addChild("#", t("windowsGuidance.stepRunAnyway"))
    ul.addChild("li").addChild("#", t("windowsGuidance.stepUnblock"))
    val li3 = ul.addChild("li")
    li3.addChild("#", t("windowsGuidance.powershellLabel"))
    val pre = box.addChild("pre")
    pre.addChild("#", t("windowsGuidance.commandUnblock"))
    val li4 = ul.addChild("li")
    li4.addChild("#", t("windowsGuidance.hashLabel"))
    val pre2 = box.addChild("pre")
    pre2.addChild("#", t("windowsGuidance.commandHash"))
  }

  /** Presents extra information for Snap installs, including snapd setup commands. */
  private fun linuxSnapGuidance(content: HTMLNode, pm: PageMaker, file: File, hasSnap: Boolean) {
    val box =
      pm.getInfobox(
        INFOBOX_INFORMATION,
        t("linuxSnapGuidance.title"),
        content,
        "core-install-guidance-snap",
        true,
      )
    box.addChild("p").addChild("#", t("linuxSnapGuidance.intro"))
    val ul = box.addChild("ul")
    if (!hasSnap) {
      ul.addChild("li").addChild("#", t("linuxSnapGuidance.installSnapd"))
      val pre = box.addChild("pre")
      pre.addChild("#", t("linuxSnapGuidance.commandInstallSnapd"))
      val pre2 = box.addChild("pre")
      pre2.addChild("#", t("linuxSnapGuidance.commandEnableSnapd"))
    }
    // Separate copy-friendly row with the exact command for this file
    val cmdRow = box.addChild("div", "class", "copy-row")
    cmdRow.addChild("span", "class", "label", t("linuxSnapGuidance.runCommandLabel"))
    val command = t("linuxSnapGuidance.commandRun", mapOf("path" to file.absolutePath))
    cmdRow.addChild(
      "input",
      arrayOf("type", "readonly", "value", "class"),
      arrayOf("text", "readonly", command, "copy-input"),
    )
  }
}
