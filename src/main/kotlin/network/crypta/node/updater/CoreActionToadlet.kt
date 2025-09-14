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

  override fun path(): String = CORE_UPDATE_PATH

  override fun handleMethodGET(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    // Redirect to alerts page by default
    val headers = MultiValueTable.from("Location", "/alerts/")
    ctx.sendReplyHeaders(302, "Found", headers, null, 0)
  }

  /** Handle download/install actions submitted from the Alerts UI. */
  fun handleMethodPOST(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    val action = request.getPartAsStringFailsafe("action", 32)
    val updater = node.getNodeUpdater().coreUpdater
    if (updater == null) {
      redirect(ctx)
      return
    }
    when (action) {
      "download" -> {
        Logger.minor(this, "[CoreActionToadlet] POST /core-update action=download")
        updater.startDownloadFromUI()
        redirect(ctx)
      }
      "install" -> {
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
        writeMessage(ctx, success, msg)
      }
      "openStore" -> {
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
      else -> redirect(ctx)
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
   * - Headless/service: do not attempt an interactive install. Return guidance for the admin with a
   *   concrete command to run as root.
   * - Immutable rpm-ostree: suggest `rpm-ostree install` flow and note reboot.
   */
  private fun linuxInstaller(file: File): InstallerDelegate {
    val name = file.name.lowercase()
    val isService = appEnv.isServiceMode()
    val inFlatpak = appEnv.isFlatpak()
    val inSnap = appEnv.isSnap()
    val ostree = isOstree()

    // Headless/systemd service: prefer oneshot helper unit; if unavailable, return guidance.
    if (isService) {
      val unitDelegate = headlessUnitDelegate(file)
      return unitDelegate ?: InstallerDelegate.Manual(headlessGuidance(name, file, ostree))
    }

    // Desktop: prefer native GUI hand-off. If we are running inside Flatpak, try host bridge.
    val guiOpenCmd = guiOpenCommand(file, preferHost = inFlatpak)

    // Per‑format fallbacks when GUI hand‑off is unavailable.
    val fallback: InstallerDelegate =
      when {
        name.endsWith(".deb") -> debFallback(file)
        name.endsWith(".rpm") -> rpmFallback(file, ostree)
        name.endsWith(".flatpakref") || name.endsWith(".flatpak") -> flatpakFallback(file)
        name.endsWith(".snap") -> snapFallback(file)
        else -> InstallerDelegate.Manual("Unsupported package type: ${file.name}")
      }

    // Prefer GUI if we have a way to open it. Otherwise return fallback command.
    return if (guiOpenCmd != null) {
      InstallerDelegate.Spawn(
        guiOpenCmd,
        "Opening with the system’s Software Center. Complete installation in the GUI.",
      )
    } else fallback
  }

  /** Represents how to carry out an install action on Linux. */
  private sealed class InstallerDelegate {
    class Spawn(val pb: ProcessBuilder, val successMessage: String) : InstallerDelegate()

    class Manual(val message: String) : InstallerDelegate()
  }

  /** Detect rpm-ostree based systems (immutable). */
  private fun isOstree(): Boolean {
    // Prefer runtime marker file; fall back to presence of rpm-ostree tool
    return java.io.File("/run/ostree-booted").exists() || appEnv.onPath("rpm-ostree")
  }

  /**
   * Build a GUI "open this package" command, using host bridging when inside Flatpak. Returns null
   * when neither xdg-open nor gio is available.
   */
  private fun guiOpenCommand(file: File, preferHost: Boolean): ProcessBuilder? {
    val path = file.absolutePath
    val opener = pickGuiOpener() ?: return null
    // Try host‑side open from Flatpak sandbox first when available
    if (preferHost && appEnv.onPath("flatpak-spawn")) {
      return ProcessBuilder(mutableListOf("flatpak-spawn", "--host") + opener + path)
    }
    // Fallback to in‑sandbox open via portal or direct host execution on non‑sandboxed desktops
    return ProcessBuilder(opener + path)
  }

  /** Choose preferred GUI opener available on PATH, including subcommand args. */
  private fun pickGuiOpener(): List<String>? {
    return when {
      appEnv.onPath("gio") -> listOf("gio", "open")
      appEnv.onPath("xdg-open") -> listOf("xdg-open")
      else -> null
    }
  }

  /** Build a GUI opener for a URL (not a local file). */
  private fun guiOpenUrlCommand(url: String, preferHost: Boolean): ProcessBuilder? {
    val opener = pickGuiOpener() ?: return null
    if (preferHost && appEnv.onPath("flatpak-spawn")) {
      return ProcessBuilder(mutableListOf("flatpak-spawn", "--host") + opener + url)
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
    val sub =
      if (file.name.endsWith(".flatpak")) listOf("install", "--assumeyes", "--user", path)
      else listOf("install", "--assumeyes", "--user", path)
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
    return when {
      appEnv.onPath("pkexec") && appEnv.onPath("snap") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("pkexec", "snap", "install", "--dangerous", path),
          "Installing with Snap (administrator approval required).",
        )
      else -> InstallerDelegate.Manual(manualMsg("Snap", path))
    }
  }

  private fun headlessGuidance(nameLower: String, file: File, ostree: Boolean): String {
    val path = file.absolutePath
    val tag =
      when {
        nameLower.endsWith(".deb") -> "DEB"
        nameLower.endsWith(".rpm") -> if (ostree) "RPM-OSTREE" else "RPM"
        nameLower.endsWith(".flatpak") || nameLower.endsWith(".flatpakref") -> "Flatpak"
        nameLower.endsWith(".snap") -> "Snap"
        else -> "Package"
      }
    val suggestion =
      when (tag) {
        "DEB" -> "pkcon install-local -y '${path}'"
        "RPM-OSTREE" -> "rpm-ostree install '${path}'"
        "RPM" -> "pkcon install-local -y '${path}'"
        "Flatpak" -> "flatpak install --assumeyes --system '${path}'"
        "Snap" -> "snap install --dangerous '${path}'"
        else -> "<install-command> '${path}'"
      }
    val extra = if (tag == "RPM-OSTREE") " A reboot may be required." else ""
    return "Headless/service environment detected. Not launching an interactive installer. " +
      "Please run as root on the host: ${suggestion}.${extra}"
  }

  private fun manualMsg(kind: String, path: String): String =
    "$kind installation requires admin rights or a GUI handler. " +
      "Run on the host: see docs or try installing '${path}' with your package manager."

  /** Try to start the root-owned oneshot install unit for headless installs. */
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

  // Store installs by name / store URIs
  private fun linuxOpenStore(kind: String, id: String?, url: String?): InstallerDelegate {
    // Prefer explicit URL when provided.
    val preferHost = appEnv.isFlatpak()
    val targetUrl =
      when {
        !url.isNullOrBlank() -> url
        kind.equals("snap", ignoreCase = true) && !id.isNullOrBlank() -> "snap://${id}"
        kind.equals("flatpak", ignoreCase = true) && !id.isNullOrBlank() ->
          // appstream is widely handled by GNOME/KDE software centers; fallback to flathub page
          if (appEnv.onPath("gio") || appEnv.onPath("xdg-open")) "appstream://${id}"
          else "https://flathub.org/apps/${id}"
        else -> null
      }
    if (targetUrl != null) {
      val opener = guiOpenUrlCommand(targetUrl, preferHost)
      if (opener != null) return InstallerDelegate.Spawn(opener, "Opening store page: ${targetUrl}")
    }
    // Fallback to CLI store install when GUI handoff isn't available
    return when {
      kind.equals("flatpak", true) && !id.isNullOrBlank() && appEnv.onPath("flatpak") ->
        InstallerDelegate.Spawn(
          ProcessBuilder("flatpak", "install", "--assumeyes", "--user", "flathub", id),
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
}
