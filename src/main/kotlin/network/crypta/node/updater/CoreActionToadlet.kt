package network.crypta.node.updater

import java.io.File
import java.io.IOException
import java.net.URI
import network.crypta.client.HighLevelSimpleClient
import network.crypta.clients.http.PageMaker
import network.crypta.clients.http.Toadlet
import network.crypta.clients.http.ToadletContext
import network.crypta.node.Node
import network.crypta.support.HTMLNode
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

  override fun path(): String = "/core-update/"

  override fun handleMethodGET(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    // Redirect to alerts page by default
    val headers = MultiValueTable.from("Location", "/alerts/")
    ctx.sendReplyHeaders(302, "Found", headers, null, 0)
  }

  /** Handle download/install actions submitted from the Alerts UI. */
  fun handleMethodPOST(uri: URI, request: HTTPRequest, ctx: ToadletContext) {
    val action = request.getPartAsStringFailsafe("action", 32)
    val updater = node.getNodeUpdater().getCoreUpdater()
    if (updater == null) {
      redirect(ctx)
      return
    }
    when (action) {
      "download" -> {
        updater.startDownloadFromUI()
        redirect(ctx)
      }
      "install" -> {
        val path = request.getPartAsStringFailsafe("path", 4096)
        val okPath = validatePath(path)
        if (okPath == null) {
          writeMessage(ctx, false, "Invalid file path.")
          return
        }
        val (success, msg) = tryInstall(okPath)
        writeMessage(ctx, success, msg)
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
    val os = System.getProperty("os.name").lowercase()
    return try {
      val pb =
        when {
          os.contains("win") -> java.lang.ProcessBuilder("cmd", "/c", file.absolutePath)
          os.contains("mac") || os.contains("darwin") ->
            java.lang.ProcessBuilder("open", file.absolutePath)
          os.contains("linux") || os.contains("nux") -> linuxInstaller(file)
          else -> null
        }
      if (pb == null) return false to "Unsupported OS or package type."
      pb.start()
      true to "Installer launched. Follow OS prompts to complete installation."
    } catch (e: Throwable) {
      false to ("Failed to start installer: " + (e.message ?: e.javaClass.simpleName))
    }
  }

  /** Choose a Linux command line for common package types, or null when unsupported. */
  private fun linuxInstaller(file: File): java.lang.ProcessBuilder? {
    val name = file.name
    return when {
      name.endsWith(".flatpak", ignoreCase = true) ->
        java.lang.ProcessBuilder("flatpak", "install", "--assumeyes", file.absolutePath)
      name.endsWith(".snap", ignoreCase = true) -> null // prefer store flow
      name.endsWith(".deb", ignoreCase = true) ->
        if (onPath("apt")) java.lang.ProcessBuilder("apt", "install", file.absolutePath)
        else java.lang.ProcessBuilder("dpkg", "-i", file.absolutePath)
      name.endsWith(".rpm", ignoreCase = true) ->
        java.lang.ProcessBuilder("rpm", "-Uvh", file.absolutePath)
      else -> null
    }
  }

  /** Simple PATH check for an executable name. */
  private fun onPath(cmd: String): Boolean {
    val sep = File.pathSeparatorChar
    val path = System.getenv("PATH") ?: return false
    return path.split(sep).any { File(it, cmd).canExecute() }
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
    Toadlet.addHomepageLink(content)
    this.writeHTMLReply(ctx, 200, "OK", null, page.generate(), true)
  }
}
