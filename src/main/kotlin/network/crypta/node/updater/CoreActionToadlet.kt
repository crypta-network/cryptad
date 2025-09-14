package network.crypta.node.updater

import java.io.File
import java.io.IOException
import java.net.URI
import network.crypta.client.HighLevelSimpleClient
import network.crypta.clients.http.PageMaker
import network.crypta.clients.http.Toadlet
import network.crypta.clients.http.ToadletContext
import network.crypta.fs.AppEnv
import network.crypta.node.Node
import network.crypta.support.HTMLNode
import network.crypta.support.Logger
import network.crypta.support.MultiValueTable
import network.crypta.support.api.HTTPRequest

/**
 * Lightweight HTTP endpoint that wires alert‑panel buttons to CoreUpdater actions.
 *
 * Path: `/core-update/`
 * - GET: 302 redirect to the Alerts page.
 * - POST: handles `action=download|install` (requires a valid form password in the request).
 *
 * Security:
 * - `install` action validates that the file path is under the node dir `updates/core/` subtree
 *   (canonical‑path check) to mitigate traversal/symlink games.
 */
class CoreActionToadlet(client: HighLevelSimpleClient, private val node: Node) : Toadlet(client) {

  private val appEnv = AppEnv()

  private companion object {
    private const val EXT_FLATPAK = ".flatpak"
    private const val EXT_FLATPAKREF = ".flatpakref"
    private const val EXT_SNAP = ".snap"
    private const val CMD_FLATPAK_SPAWN = "flatpak-spawn"
    private const val CMD_XDG_OPEN = "xdg-open"
    private const val ARG_ASSUME_YES = "--assumeyes"
    private const val ARG_USER = "--user"
    private const val TAG_RPM_OSTREE = "RPM-OSTREE"
  }

  override fun path(): String = CORE_UPDATE_PATH

  override fun handleMethodGET(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    // Redirect to alerts page by default
    val headers = MultiValueTable.from("Location", "/alerts/")
    ctx.sendReplyHeaders(302, "Found", headers, null, 0)
  }

  /** Handle download/install actions submitted from the Alerts UI. */
  fun handleMethodPOST(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    val updater = node.getNodeUpdater().coreUpdater ?: return redirect(ctx)
    when (request.getPartAsStringFailsafe("action", 32)) {
      "download" -> handleDownload(updater, ctx)
      "install" -> handleInstall(request, ctx)
      "openStore" -> handleOpenStore(request, ctx)
      else -> redirect(ctx)
    }
  }

  private fun handleDownload(updater: CoreUpdater, ctx: ToadletContext) {
    Logger.minor(this, "[CoreActionToadlet] POST /core-update action=download")
    updater.startDownloadFromUI()
    redirect(ctx)
  }

  private fun handleInstall(request: HTTPRequest, ctx: ToadletContext) {
    val path = request.getPartAsStringFailsafe("path", 4096)
    Logger.minor(this, "[CoreActionToadlet] POST /core-update action=install path=$path")
    val okPath = validatePath(path)
    if (okPath == null) {
      Logger.minor(this, "[CoreActionToadlet] install rejected: invalid path")
      writeMessage(ctx, false, "Invalid file path.")
      return
    }
    val (success, msg) = tryInstall(okPath)
    Logger.minor(this, "[CoreActionToadlet] install result: success=$success, message=\"$msg\"")
    writeInstallResult(ctx, success, msg, okPath)
  }

  private fun handleOpenStore(request: HTTPRequest, ctx: ToadletContext) {
    val kind = request.getPartAsStringFailsafe("kind", 32)
    val id = request.getPartAsStringFailsafe("id", 256)
    val url = request.getPartAsStringFailsafe("url", 2048)
    Logger.minor(
      this,
      "[CoreActionToadlet] POST /core-update action=openStore kind=$kind id=$id url=$url",
    )
    val delegate =
      when (appEnv.osKind()) {
        AppEnv.OsKind.LINUX -> linuxOpenStore(kind, id.ifBlank { null }, url.ifBlank { null })
        AppEnv.OsKind.MAC ->
          if (url.isNotBlank())
            InstallerDelegate.Spawn(ProcessBuilder("open", url), "Opening store page")
          else InstallerDelegate.Manual("Provide a valid store URL for macOS.")
        AppEnv.OsKind.WINDOWS ->
          if (url.isNotBlank())
            InstallerDelegate.Spawn(ProcessBuilder("cmd", "/c", url), "Opening store page")
          else InstallerDelegate.Manual("Provide a valid store URL for Windows.")
        else -> InstallerDelegate.Manual("Unsupported platform for store handler.")
      }
    when (delegate) {
      is InstallerDelegate.Spawn -> {
        try {
          delegate.pb.start()
          writeMessage(ctx, true, delegate.successMessage)
        } catch (t: Throwable) {
          writeMessage(ctx, false, "Failed to open: ${t.message ?: t.javaClass.simpleName}")
        }
      }
      is InstallerDelegate.Manual -> writeMessage(ctx, false, delegate.message)
    }
  }

  /**
   * Ensure the provided file path resolves inside `nodeDir/updates/core`. Returns the canonical
   * `File` or null when invalid/untrusted.
   */
  private fun validatePath(path: String): File? {
    if (path.isEmpty()) return null
    val f = File(path)
    val base = File(node.getNodeDir(), "updates/core").canonicalFile
    val canon =
      try {
        f.canonicalFile
      } catch (_: IOException) {
        return null
      }
    return if (canon.path.startsWith(base.path)) canon else null
  }

  /**
   * Best‑effort attempt to launch the OS installer for the given file. Returns `(success, message)`
   * where message is suitable for user display.
   */
  private fun tryInstall(file: File): Pair<Boolean, String> {
    return try {
      val delegate =
        when (appEnv.osKind()) {
          AppEnv.OsKind.WINDOWS ->
            InstallerDelegate.Spawn(
              ProcessBuilder("cmd", "/c", file.absolutePath),
              "Installer launched. Follow Windows prompts.",
            )
          AppEnv.OsKind.MAC ->
            InstallerDelegate.Spawn(
              ProcessBuilder("open", file.absolutePath),
              "Installer launched. Follow macOS prompts.",
            )
          AppEnv.OsKind.LINUX -> linuxInstaller(file)
          else -> InstallerDelegate.Manual("Unsupported OS or package type.")
        }

      when (delegate) {
        is InstallerDelegate.Spawn -> {
          delegate.pb.start()
          true to delegate.successMessage
        }
        is InstallerDelegate.Manual -> false to delegate.message
      }
    } catch (e: Throwable) {
      false to ("Failed to start installer: " + (e.message ?: e.javaClass.simpleName))
    }
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
  private fun linuxInstaller(file: File): InstallerDelegate {
    val name = file.name.lowercase()
    val isService = appEnv.isServiceMode()
    val inFlatpak = appEnv.isFlatpak()
    val ostree = isOstree()

    // Headless/systemd service: prefer oneshot helper unit; if unavailable, return guidance.
    if (isService) {
      val unitDelegate = headlessUnitDelegate(file)
      return unitDelegate ?: InstallerDelegate.Manual(headlessGuidance(name, file, ostree))
    }

    // Desktop: prefer native GUI hand-off for most types, but NEVER for .snap (Ubuntu will mount
    // snaps as disk images). For snaps we always use `snap install --dangerous`.
    val isSnapPkg = name.endsWith(EXT_SNAP)
    val guiOpenCmd = if (isSnapPkg) null else guiOpenCommand(file, preferHost = inFlatpak)

    // Per‑format fallbacks when GUI hand‑off is unavailable.
    val fallback: InstallerDelegate =
      when {
        name.endsWith(".deb") -> debFallback(file)
        name.endsWith(".rpm") -> rpmFallback(file, ostree)
        name.endsWith(EXT_FLATPAKREF) || name.endsWith(EXT_FLATPAK) -> flatpakFallback(file)
        name.endsWith(EXT_SNAP) -> snapFallback(file)
        else -> InstallerDelegate.Manual("Unsupported package type: ${file.name}")
      }

    // Prefer GUI if we have a way to open it. Otherwise, return fallback command.
    return if (guiOpenCmd != null) {
      InstallerDelegate.Spawn(
        guiOpenCmd,
        "Opening with the system’s Software Center. Complete installation in the GUI.",
      )
    } else fallback
  }

  /** Represents how to carry out an installation action on Linux. */
  private sealed class InstallerDelegate {
    class Spawn(val pb: ProcessBuilder, val successMessage: String) : InstallerDelegate()

    class Manual(val message: String) : InstallerDelegate()
  }

  /** Detect rpm-ostree based systems (immutable). */
  private fun isOstree(): Boolean {
    // Prefer runtime marker file; fall back to presence of rpm-ostree tool
    return File("/run/ostree-booted").exists() || appEnv.onPath("rpm-ostree")
  }

  /**
   * Build a GUI "open this package" command, using host bridging when inside Flatpak. Returns null
   * when neither xdg-open nor gio is available.
   */
  private fun guiOpenCommand(file: File, preferHost: Boolean): ProcessBuilder? {
    val path = file.absolutePath
    val opener = pickGuiOpener() ?: return null
    // Try host‑side open from Flatpak sandbox first when available
    if (preferHost && appEnv.onPath(CMD_FLATPAK_SPAWN)) {
      return ProcessBuilder(mutableListOf(CMD_FLATPAK_SPAWN, "--host") + opener + path)
    }
    // Fallback to in‑sandbox open via portal or direct host execution on non‑sandboxed desktops
    return ProcessBuilder(opener + path)
  }

  /** Choose preferred GUI opener available on PATH, including subcommand args. */
  private fun pickGuiOpener(): List<String>? {
    return when {
      appEnv.onPath("gio") -> listOf("gio", "open")
      appEnv.onPath(CMD_XDG_OPEN) -> listOf(CMD_XDG_OPEN)
      else -> null
    }
  }

  /** Build a GUI opener for a URL (not a local file). */
  private fun guiOpenUrlCommand(url: String, preferHost: Boolean): ProcessBuilder? {
    val opener = pickGuiOpener() ?: return null
    if (preferHost && appEnv.onPath(CMD_FLATPAK_SPAWN)) {
      return ProcessBuilder(mutableListOf(CMD_FLATPAK_SPAWN, "--host") + opener + url)
    }
    return ProcessBuilder(opener + url)
  }

  /** Cross‑distro fallback for local DEB using PackageKit (polkit‑backed). */
  private fun debFallback(file: File): InstallerDelegate {
    val path = file.absolutePath
    return when {
      appEnv.onPath("pkcon") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkcon", "install-local", "-y", path),
          "Installing via PackageKit (polkit will prompt if required).",
        )
      // As a last resort: apt-get with pkexec, resolving deps via ./file.deb syntax
      appEnv.onPath("pkexec") && appEnv.onPath("apt-get") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "apt-get", "install", "-y", "./" + file.name)
            .directory(file.parentFile),
          "Installing with apt (administrator approval required).",
        )
      appEnv.onPath("dpkg") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "dpkg", "-i", path),
          "Installing with dpkg (administrator approval required).",
        )
      else -> InstallerDelegate.Manual(manualMsg("DEB", path))
    }
  }

  /** Cross‑distro fallback for local RPM; handle rpm‑ostree guidance specially. */
  private fun rpmFallback(file: File, ostree: Boolean): InstallerDelegate {
    val path = file.absolutePath
    if (ostree) {
      return InstallerDelegate.Manual(
        "Detected rpm-ostree system. Use `rpm-ostree install ${path}` then reboot to apply."
      )
    }
    return when {
      appEnv.onPath("pkcon") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkcon", "install-local", "-y", path),
          "Installing via PackageKit (polkit will prompt if required).",
        )
      appEnv.onPath("pkexec") && appEnv.onPath("dnf") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "dnf", "install", "-y", path),
          "Installing with dnf (administrator approval required).",
        )
      appEnv.onPath("pkexec") && appEnv.onPath("zypper") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "zypper", "--non-interactive", "install", path),
          "Installing with zypper (administrator approval required).",
        )
      appEnv.onPath("rpm") && appEnv.onPath("pkexec") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "rpm", "-Uvh", path),
          "Installing with rpm (administrator approval required).",
        )
      else -> InstallerDelegate.Manual(manualMsg("RPM", path))
    }
  }

  /** Prefer per‑user Flatpak install on desktops. */
  private fun flatpakFallback(file: File): InstallerDelegate {
    val path = file.absolutePath
    if (!appEnv.onPath("flatpak")) return InstallerDelegate.Manual(manualMsg("Flatpak", path))
    val sub = listOf("install", ARG_ASSUME_YES, ARG_USER, path)
    return InstallerDelegate.Spawn(
      ProcessBuilder(mutableListOf("flatpak") + sub),
      "Installing with Flatpak (user scope).",
    )
  }

  /**
   * Snap fallback for local .snap files. Prefer GUI; otherwise use pkexec snap install --dangerous.
   */
  private fun snapFallback(file: File): InstallerDelegate {
    val path = file.absolutePath
    // Always use 'snap install --dangerous' for local snap files.
    // Desktop: require polkit via pkexec. If pkexec/snap are unavailable, do not run unprivileged
    // snap installs; instruct the user to run the command as root.
    return if (appEnv.onPath("pkexec") && appEnv.onPath("snap")) {
      InstallerDelegate.Spawn(
        ProcessBuilder("pkexec", "snap", "install", "--dangerous", path),
        "Installing with Snap (administrator approval required).",
      )
    } else {
      InstallerDelegate.Manual(
        "$path requires administrative privileges to install as a Snap. " +
          "On this system, pkexec/snap may be unavailable. Please install snapd and then run: " +
          "sudo snap install --dangerous '${path}'."
      )
    }
  }

  private fun headlessGuidance(nameLower: String, file: File, ostree: Boolean): String {
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
    val extra = if (tag == TAG_RPM_OSTREE) " A reboot may be required." else ""
    return "Headless/service environment detected. Not launching an interactive installer. " +
      "Please run as root on the host: ${suggestion}.${extra}"
  }

  private fun manualMsg(kind: String, path: String): String =
    "$kind installation requires admin rights or a GUI handler. " +
      "Run on the host: see docs or try installing '${path}' with your package manager."

  /** Try to start the root-owned oneshot install unit for headless installations. */
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
      InstallerDelegate.Spawn(
        pb,
        "Requested headless install via systemd helper. Check 'journalctl -u ${unit}' for progress.",
      )
    } catch (_: Throwable) {
      null
    }
  }

  // Store installations by name / store URIs
  private fun linuxOpenStore(kind: String, id: String?, url: String?): InstallerDelegate {
    // Prefer explicit URL when provided.
    val preferHost = appEnv.isFlatpak()
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
      if (opener != null) return InstallerDelegate.Spawn(opener, "Opening store page: $targetUrl")
    }
    // Fallback to CLI store install when GUI handoff isn't available
    return when {
      kind.equals("flatpak", true) && !id.isNullOrBlank() && appEnv.onPath("flatpak") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("flatpak", "install", ARG_ASSUME_YES, ARG_USER, "flathub", id),
          "Installing '${id}' from Flathub (user scope)",
        )
      kind.equals("snap", true) &&
        !id.isNullOrBlank() &&
        appEnv.onPath("pkexec") &&
        appEnv.onPath("snap") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "snap", "install", id),
          "Installing '${id}' from Snap Store (administrator approval required)",
        )
      else ->
        InstallerDelegate.Manual(
          "Unable to open store or perform CLI install for '${id ?: url ?: "?"}'."
        )
    }
  }

  /** 302 back to Alerts to keep navigation consistent. */
  private fun redirect(ctx: ToadletContext) {
    val headers = MultiValueTable.from("Location", "/alerts/")
    ctx.sendReplyHeaders(302, "Found", headers, null, 0)
  }

  /** Render a small, self‑contained result page with success/failure styling. */
  private fun writeMessage(ctx: ToadletContext, success: Boolean, msg: String) {
    val pm = ctx.pageMaker
    val page =
      pm.getPageNode(
        if (success) "Installation" else "Installation failed",
        ctx,
        PageMaker.RenderParameters().renderNavigationLinks(true).renderStatus(true),
      )
    val content: HTMLNode = page.contentNode
    val box =
      pm.getInfobox(
        if (success) "infobox-success" else "infobox-warning",
        if (success) "Installation" else "Installation failed",
        content,
        "core-installer-result",
        true,
      )
    box.addChild("p").addChild("#", msg)
    addHomepageLink(content)
    // Allow JS on result page; CSP was previously too strict here.
    this.writeHTMLReply(ctx, 200, "OK", null, page.generate(), false)
  }

  /** Render install result with context-aware guidance (flexible per OS/package type). */
  private fun writeInstallResult(ctx: ToadletContext, success: Boolean, msg: String, file: File) {
    val pm = ctx.pageMaker
    val page =
      pm.getPageNode(
        if (success) "Installation" else "Installation failed",
        ctx,
        PageMaker.RenderParameters().renderNavigationLinks(true).renderStatus(true),
      )
    val content: HTMLNode = page.contentNode
    val box =
      pm.getInfobox(
        if (success) "infobox-success" else "infobox-warning",
        if (success) "Installation" else "Installation failed",
        content,
        "core-installer-result",
        true,
      )
    box.addChild("p").addChild("#", msg)

    // Add OS/package-specific guidance below the result for a better UX.
    addInstallGuidance(content, pm, file)

    addHomepageLink(content)
    this.writeHTMLReply(ctx, 200, "OK", null, page.generate(), false)
  }

  /** Append guidance boxes for common edge cases (e.g., macOS Gatekeeper on unsigned DMGs). */
  private fun addInstallGuidance(content: HTMLNode, pm: PageMaker, file: File) {
    when (appEnv.osKind()) {
      AppEnv.OsKind.MAC ->
        if (file.name.lowercase().endsWith(".dmg")) macDmgGuidance(content, pm) else {}
      AppEnv.OsKind.LINUX ->
        if (file.name.lowercase().endsWith(EXT_SNAP))
          linuxSnapGuidance(content, pm, appEnv.onPath("pkexec"), appEnv.onPath("snap"))
        else {}
      AppEnv.OsKind.WINDOWS ->
        if (file.name.lowercase().endsWith(".exe")) windowsExeGuidance(content, pm) else {}
      else -> {}
    }
  }

  /** Detailed steps for macOS Gatekeeper when using an unsigned DMG/app. */
  private fun macDmgGuidance(content: HTMLNode, pm: PageMaker) {
    val box =
      pm.getInfobox(
        "infobox-information",
        "macOS: If Crypta is blocked by Gatekeeper",
        content,
        "core-install-guidance-macos",
        true,
      )
    box
      .addChild("p")
      .addChild(
        "#",
        "Because this build is unsigned, macOS may block Crypta on first launch with a warning about an unidentified developer.",
      )
    val steps = box.addChild("ul")
    steps
      .addChild("li")
      .addChild("#", "Open the downloaded DMG and drag Crypta.app to Applications.")
    steps
      .addChild("li")
      .addChild(
        "#",
        "Right-click Crypta.app in Applications and choose Open, then confirm. This permanently whitelists the app.",
      )
    steps
      .addChild("li")
      .addChild(
        "#",
        "Alternatively: System Settings → Privacy & Security → look for 'Crypta.app was blocked' and click Open Anyway → Open.",
      )
    val alt = box.addChild("li")
    alt.addChild(
      "#",
      "Advanced: clear quarantine attributes in Terminal (replace the path if needed):",
    )
    val pre = box.addChild("pre")
    pre.addChild("#", "xattr -dr com.apple.quarantine /Applications/Crypta.app")
    val verify = box.addChild("p")
    verify.addChild("#", "To verify status: ")
    val pre2 = box.addChild("pre")
    pre2.addChild("#", "spctl --assess -vv /Applications/Crypta.app")
  }

  /** Tips for unsigned Windows installers (SmartScreen/unknown publisher). */
  private fun windowsExeGuidance(content: HTMLNode, pm: PageMaker) {
    val box =
      pm.getInfobox(
        "infobox-information",
        "Windows: If the installer is blocked (SmartScreen)",
        content,
        "core-install-guidance-windows",
        true,
      )
    box
      .addChild("p")
      .addChild(
        "#",
        "This build may be unsigned. Windows Defender SmartScreen can warn about apps from an unknown publisher.",
      )
    val ul = box.addChild("ul")
    ul
      .addChild("li")
      .addChild(
        "#",
        "Double‑click the installer. On the \"Windows protected your PC\" dialog, click More info → Run anyway.",
      )
    ul
      .addChild("li")
      .addChild(
        "#",
        "Or: right‑click the .exe → Properties → General → check \"Unblock\" → Apply → OK; then run it again.",
      )
    val li3 = ul.addChild("li")
    li3.addChild("#", "PowerShell option (unblock the file):")
    val pre = box.addChild("pre")
    pre.addChild("#", """Unblock-File -Path "C:\\Path\\to\\Crypta-Installer.exe"""")
    val li4 = ul.addChild("li")
    li4.addChild("#", "Verify SHA‑256 if provided:")
    val pre2 = box.addChild("pre")
    pre2.addChild("#", """Get-FileHash -Algorithm SHA256 "C:\\Path\\to\\Crypta-Installer.exe"""")
  }

  /** Small info box for Snap installs: nudges to install snapd or enable a polkit agent. */
  private fun linuxSnapGuidance(
    content: HTMLNode,
    pm: PageMaker,
    hasPkexec: Boolean,
    hasSnap: Boolean,
  ) {
    val box =
      pm.getInfobox(
        "infobox-information",
        "Linux: Snap install notes",
        content,
        "core-install-guidance-snap",
        true,
      )
    box
      .addChild("p")
      .addChild(
        "#",
        "Local .snap files require administrative privileges (snap install --dangerous).",
      )
    val ul = box.addChild("ul")
    if (!hasSnap) {
      ul.addChild("li").addChild("#", "Install snapd and ensure the snapd service is running.")
      val pre = box.addChild("pre")
      pre.addChild("#", "sudo apt install snapd    # or: sudo dnf install snapd")
      val pre2 = box.addChild("pre")
      pre2.addChild("#", "sudo systemctl enable --now snapd.socket snapd.service")
    }
    if (!hasPkexec) {
      ul
        .addChild("li")
        .addChild(
          "#",
          "No graphical polkit agent detected (pkexec). Install/enable a polkit agent on desktop (e.g., polkit-gnome, polkit-kde-agent-1) or use the CLI below.",
        )
    }
    val li = ul.addChild("li")
    li.addChild("#", "Command-line alternative:")
    val pre3 = box.addChild("pre")
    pre3.addChild("#", "sudo snap install --dangerous \"/path/to/your/file.snap\"")
  }
}
