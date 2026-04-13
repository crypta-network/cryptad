package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.LineReadingInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared welcome-page rendering helpers for the legacy HTTP shell.
 *
 * <p>This helper keeps the small portion of welcome-page rendering that still belongs to the
 * admin-owned shell after the browse/admin split. The browse leaf still owns the concrete welcome
 * toadlet, but startup, shutdown, and panic-button flows in the admin module need two specific
 * behaviors that must remain byte-for-byte compatible with the historical UI: the restart page and
 * the wrapper-log tail shown while the node is still coming up. Moving those behaviors here avoids
 * an admin-to-browse dependency without forcing each caller to duplicate HTML structure, log-file
 * handling, or localization lookup.
 *
 * <p>The class is stateless and safe for repeated use across requests. Callers provide the current
 * {@link ToadletContext} and destination content node, and the helper fills in the same infobox and
 * meta-refresh structure that operators already expect during startup and restart transitions. It
 * deliberately fails soft when the wrapper log is unreadable, because the absence of log text
 * should not block the surrounding status page from rendering.
 *
 * <ul>
 *   <li>Builds the restart page fragment used by shutdown and panic flows.
 *   <li>Streams the tail of {@code wrapper.log} into startup pages when it is readable.
 *   <li>Resolves welcome-page localization keys without importing the browse-owned toadlet.
 * </ul>
 */
final class LegacyWelcomePageSupport {
  /** Logger used only for restart-page state and wrapper-log read failures. */
  private static final Logger LOG = LoggerFactory.getLogger(LegacyWelcomePageSupport.class);

  /** Prevents instantiation of this static helper holder. */
  private LegacyWelcomePageSupport() {}

  /**
   * Builds the HTML shell for the legacy restart page.
   *
   * <p>The returned node contains the historical infobox text plus a meta-refresh directive that
   * causes the browser to poll the root path again after a short delay. Admin callers use this when
   * the node is restarting or panicking, so the method keeps navigation links disabled and emits
   * the same localization keys as the former welcome-toadlet implementation.
   *
   * @param ctx active toadlet context that provides page-building helpers and localization-aware UI
   *     services.
   * @return outer page node ready to be serialized into an HTML reply by the caller.
   */
  static HTMLNode sendRestartingPageInner(ToadletContext ctx) {
    PageNode page =
        ctx.getPageMaker()
            .getPageNode("Node Restart", ctx, new RenderParameters().renderNavigationLinks(false));
    HTMLNode pageNode = page.getOuterNode();
    HTMLNode headNode = page.getHeadNode();
    headNode.addChild(
        "meta", new String[] {"http-equiv", "content"}, new String[] {"refresh", "20; url="});
    HTMLNode contentNode = page.getContentNode();
    ctx.getPageMaker()
        .getInfobox(
            "infobox-information",
            l10n("restartingTitle"),
            contentNode,
            "shutdown-progressing",
            true)
        .addChild("#", l10n("restarting"));
    LOG.info("Node is restarting");
    return pageNode;
  }

  /**
   * Appends the readable tail of {@code wrapper.log} to a startup-style infobox when available.
   *
   * <p>The helper is intentionally conservative: it only attempts to read the file when it exists,
   * is a regular readable file, and contains at least one byte. At most the final portion of the
   * log is streamed, matching the previous startup-page behavior and avoiding large in-memory
   * responses. If the file cannot be read, the method logs at debug level and leaves the page
   * otherwise unchanged so startup status rendering can continue.
   *
   * @param ctx active toadlet context used to create the wrapper-log infobox.
   * @param contentNode destination content node that should receive the infobox when log text is
   *     available.
   */
  static void maybeDisplayWrapperLogfile(ToadletContext ctx, HTMLNode contentNode) {
    File logs = new File("wrapper.log");
    long logSize = logs.length();
    if (logs.exists() && logs.isFile() && logs.canRead() && logSize > 0) {
      HTMLNode logInfoboxContent =
          ctx.getPageMaker()
              .getInfobox("infobox-info", "Current status", contentNode, "start-progress", true);
      try (LineReadingInputStream logreader = FileUtil.getLogTailReader(logs, 2000)) {
        String line;
        while ((line = logreader.readLine(100000, 200, true)) != null) {
          logInfoboxContent.addChild("#", line);
          logInfoboxContent.addChild("br");
        }
      } catch (IOException e) {
        LOG.debug("Failed to read wrapper log tail", e);
      }
    }
  }

  /**
   * Resolves a localized welcome-page string from the shared node bundle.
   *
   * @param key suffix of the {@code WelcomeToadlet.<key>} localization entry to resolve.
   * @return localized welcome-page text associated with the requested key.
   */
  private static String l10n(String key) {
    return NodeL10n.getBase().getString("WelcomeToadlet." + key);
  }
}
