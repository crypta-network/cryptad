package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Toadlet that renders the landing page for community chat and forum resources.
 *
 * <p>This handler produces a simple informational page that points new users to curated discussion
 * tools such as FSNG, FMS, and Sone. It relies solely on localization strings and static USK/SSK
 * links, so responses are deterministic and do not depend on mutable node state. The toadlet keeps
 * only a reference to the {@link PluginManager}, making it effectively stateless and safe to share
 * across requests as long as the underlying dependencies are thread-safe. Because it subclasses
 * {@link Toadlet}, it integrates with the node's HTTP routing and inherits common behaviors such as
 * alert rendering and response framing.
 *
 * <p>Typical usage registers the toadlet during node startup so the page appears at {@code /chat/}.
 * The page is intentionally lightweight: it does not initiate background lookups and performs no
 * outbound network access itself; instead, it advertises entry points that users can fetch on
 * demand. The view is suppressed when the Freetalk plugin is active to avoid showing duplicate chat
 * functionality.
 *
 * <ul>
 *   <li>Provides a localized headline and summary of chat ecosystem options.
 *   <li>Lists stable USK/SSK links for bundled or recommended chat tools.
 *   <li>Omits rendering when Freetalk is present, deferring to the plugin UI.
 * </ul>
 */
public class ChatForumsToadlet extends Toadlet implements LinkEnabledCallback {

  private final PluginManager plugins;

  /**
   * Creates a toadlet that can render the chat/forums landing page using the provided dependencies.
   *
   * <p>The constructor stores the supplied {@link PluginManager} for later feature gating while
   * passing the {@link HighLevelSimpleClient} to the {@link Toadlet} base class. No network
   * operations occur here; the instance is ready for registration immediately after construction
   * and may be reused across requests because it contains no per-request state.
   *
   * @param client high-level client used by the superclass to perform standard toadlet duties; must
   *     be non-null and already initialized for HTTP routing.
   * @param plugins plugin manager that determines whether chat listings should be shown; must be
   *     non-null and reflect the current plugin load status.
   */
  protected ChatForumsToadlet(HighLevelSimpleClient client, PluginManager plugins) {
    super(client);
    this.plugins = plugins;
  }

  /**
   * Handles an HTTP GET by emitting a localized list of chat and forum entry points.
   *
   * <p>The method builds a standard page via the {@link network.crypta.clients.http.PageMaker}
   * obtained from the supplied context, adds the node's alert summary, and appends an infobox that
   * links to well-known chat/forum resources. All links are static USK/SSK targets so the handler
   * avoids additional lookups or background work. The response is written immediately to the
   * provided context and finishes with a 200 status code when successful. The method does not
   * mutate shared state and is idempotent for the same inputs.
   *
   * @param uri original request URI, preserved for compatibility with the Toadlet contract; may
   *     include query parameters but is not modified.
   * @param req parsed HTTP request carrying headers and form data; the handler reads only to
   *     satisfy interface expectations and does not alter it.
   * @param ctx active toadlet context that supplies page-making utilities and the output stream;
   *     must be open for writing throughout the call.
   * @throws ToadletContextClosedException if the context is closed before the HTML reply is fully
   *     emitted or the client disconnects mid-response.
   * @throws IOException if writing the generated page to the response stream fails for any I/O
   *     reason, including downstream transport errors.
   */
  @Override
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("title"), ctx);
    HTMLNode contentNode = page.getContentNode();

    contentNode.addChild(ctx.getAlertManager().createSummary());

    HTMLNode contentBox =
        ctx.getPageMaker()
            .getInfobox("infobox-information", l10n("title"), contentNode, "chat-list", true);

    NodeL10n.getBase()
        .addL10nSubstitution(
            contentBox.addChild("p"),
            "ChatForumsToadlet.fsng",
            new String[] {"fsng"},
            new HTMLNode[] {
              HTMLNode.link(
                  "/USK@t5zaONbYd5DvGNNSokVnDCdrIEytn9U5SSD~pYF0RTE,guWyS9aCMcywU5PFBrKsMiXs7LzwKfQlGSRi17fpffc,AQACAAE/fsng/-56/")
            });

    HTMLNode ul = contentBox.addChild("ul");
    HTMLNode li = ul.addChild("li");
    NodeL10n.getBase()
        .addL10nSubstitution(
            li,
            "ChatForumsToadlet.fms",
            new String[] {"fms", "fms-help"},
            new HTMLNode[] {
              HTMLNode.link(
                  "/USK@0npnMrqZNKRCRoGojZV93UNHCMN-6UU3rRSAmP6jNLE,~BG-edFtdCC1cSH4O3BWdeIYa8Sw5DfyrSV-TKdO5ec,AQACAAE/fms/-137/"),
              HTMLNode.link(
                  "/SSK@ugb~uuscsidMI-Ze8laZe~o3BUIb3S50i25RIwDH99M,9T20t3xoG-dQfMO94LGOl9AxRTkaz~TykFY-voqaTQI,AQACAAE/FAFS-49/files/fms.htm")
            });
    li = ul.addChild("li");
    NodeL10n.getBase()
        .addL10nSubstitution(
            li,
            "ChatForumsToadlet.sone",
            new String[] {"sone"},
            new HTMLNode[] {
              HTMLNode.link(
                  "/USK@nwa8lHa271k2QvJ8aa0Ov7IHAV-DFOCFgmDt3X6BpCI,DuQSUZiI~agF8c-6tjsFFGuZ8eICrzWCILB60nT8KKo,AQACAAE/sone/-72/")
            });
    contentBox.addChild("p", l10n("content2"));

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("ChatForumsToadlet." + string);
  }

  /**
   * Returns the mount path under which this toadlet is exposed to HTTP clients.
   *
   * <p>The value is constant and ends with a trailing slash so relative links on the rendered page
   * resolve correctly. Consumers typically register the toadlet with the HTTP server using this
   * path verbatim.
   *
   * @return canonical path segment {@code "/chat/"} identifying the chat landing page endpoint.
   */
  @Override
  public String path() {
    return "/chat/";
  }

  /**
   * Reports whether this toadlet should be reachable based on the current plugin state.
   *
   * <p>The method suppresses the chat/forums listing when the Freetalk plugin is loaded, thereby
   * avoiding duplicate navigation entries. It performs a lightweight lookup against the provided
   * {@link ToadletContext}, which is accepted to satisfy the interface but not inspected in the
   * current implementation. The decision is deterministic for a given plugin manager snapshot and
   * safe to call from multiple threads provided the {@link PluginManager} implementation supports
   * concurrent reads.
   *
   * @param ctx current toadlet context, unused but available for future environment checks; may be
   *     {@code null} depending on caller conventions.
   * @return {@code true} when Freetalk is absent and the landing page should be linked, otherwise
   *     {@code false} to hide the entry point.
   */
  @Override
  public boolean isEnabled(ToadletContext ctx) {
    return !plugins.isPluginLoaded("plugins.Freetalk.Freetalk");
  }
}
