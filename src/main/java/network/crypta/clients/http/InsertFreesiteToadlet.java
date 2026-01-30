package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * Renders the informational page that guides users through inserting a freesite into Crypta via the
 * browser interface. The toadlet builds a static set of localized instructions, curated links to
 * helper tools (jSite, FlogHelper, Thingamablog), and direct pointers to on-network tutorials that
 * explain freesite publishing. It does not perform any network I/O itself; instead it acts purely
 * as a documentation surface so users can choose the workflow that fits their experience level.
 *
 * <p>Usage pattern:
 *
 * <ul>
 *   <li>The containing {@link ToadletContainer} routes {@code GET /insertsite/} to this instance.
 *   <li>{@link #handleMethodGET(URI, HTTPRequest, ToadletContext)} builds a {@link PageNode}, adds
 *       alert summaries, and emits a single HTML reply.
 *   <li>No mutable state is retained between invocations; the class is safe for reuse across
 *       requests as long as callers provide a fresh {@link ToadletContext}.
 * </ul>
 *
 * <p>Thread-safety: instances are stateless and rely on the provided context for per-request data,
 * so they are safe to use concurrently when the container hands each request its own context. The
 * localization and link content is fixed at compile time, which avoids runtime variability and
 * keeps the rendered HTML deterministic for testing.
 */
public class InsertFreesiteToadlet extends Toadlet {

  /**
   * Create a new freesite help toadlet bound to the shared high-level client.
   *
   * @param client non-null helper used by the base {@link Toadlet}; retained for parity with other
   *     toadlets even though this class performs only static rendering
   */
  protected InsertFreesiteToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Handle {@code GET /insertsite/} by emitting a localized help page that explains how to publish
   * a freesite. The method assembles a {@link PageNode}, injects the current alert summary, builds
   * an infobox with helper links (plugins page, jSite downloads, on-network tutorials, and
   * Thingamablog), and returns a 200 OK HTML response via {@link #writeHTMLReply(ToadletContext,
   * int, String, String)}. No request parameters are inspected and no state is modified.
   *
   * @param uri resolved request URI; used only for signature parity and may be {@code null} in
   *     tests
   * @param req HTTP request wrapper; not read by this implementation but must be non-null to comply
   *     with the dispatch contract
   * @param ctx active request context providing page construction utilities and output streams;
   *     must be open and non-null
   * @throws ToadletContextClosedException if the client disconnects before headers or body are
   *     written
   * @throws IOException if header emission or HTML streaming fails while writing the reply
   */
  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(l10n("title"), ctx);
    HTMLNode contentNode = page.getContentNode();

    contentNode.addChild(ctx.getAlertManager().createSummary());

    HTMLNode contentBox =
        ctx.getPageMaker()
            .getInfobox("infobox-information", l10n("title"), contentNode, "freesite-insert", true);

    contentBox.addChild("p", l10n("content1"));

    NodeL10n.getBase()
        .addL10nSubstitution(
            contentBox.addChild("p"),
            "InsertFreesiteToadlet.contentFlogHelper",
            new String[] {"plugins"},
            new HTMLNode[] {HTMLNode.link(PproxyToadlet.PLUGINS_PATH)});

    NodeL10n.getBase()
        .addL10nSubstitution(
            contentBox.addChild("p"),
            "InsertFreesiteToadlet.content2",
            new String[] {"jsite-http", "jsite-freenet", "jsite-freenet-version", "jsite-info"},
            new HTMLNode[] {
              HTMLNode.link(
                  ExternalLinkToadlet.escape("http://downloads.freenetproject.org/alpha/jSite/")),
              HTMLNode.link(
                  "/SSK@1waTsw46L9-JEQ8yX1khjkfHcn--g0MlMsTlYHax9zQ,oYyxr5jyFnaTsVGDQWk9e3ddOWGKnqEASxAk08MHT2Y,AQACAAE/jSite-15/jSite-0.14-jar-with-dependencies.jar"),
              HTMLNode.text("0.14"),
              HTMLNode.link(
                  "/SSK@1waTsw46L9-JEQ8yX1khjkfHcn--g0MlMsTlYHax9zQ,oYyxr5jyFnaTsVGDQWk9e3ddOWGKnqEASxAk08MHT2Y,AQACAAE/jSite-15/"),
            });
    contentBox.addChild("p", l10n("content3"));
    HTMLNode ul = contentBox.addChild("ul");
    HTMLNode li = ul.addChild("li");
    li.addChild(
        "a",
        "href",
        "/SSK@940RYvj1-aowEHGsb5HeMTigq8gnV14pbKNsIvUO~-0,FdTbR3gIz21QNfDtnK~MiWgAf2kfwHe-cpyJXuLHdOE,AQACAAE/publish-3/",
        "Publish!");
    li.addChild("#", " - " + l10n("publishExplanation"));
    li = ul.addChild("li");
    li.addChild(
        "a",
        "href",
        "/SSK@8r-uSRcJPkAr-3v3YJR16OCx~lyV2XOKsiG4MOQQBMM,P42IgNemestUdaI7T6z3Og6P-Hi7g9U~e37R3kWGVj8,AQACAAE/freesite-HOWTO-4/",
        "Freesite HOWTO");
    li.addChild("#", " - " + l10n("freesiteHowtoExplanation"));

    NodeL10n.getBase()
        .addL10nSubstitution(
            contentBox.addChild("p"),
            "InsertFreesiteToadlet.contentThingamablog",
            new String[] {"thingamablog", "thingamablog-freenet"},
            new HTMLNode[] {
              HTMLNode.link(
                  ExternalLinkToadlet.escape(
                      "http://downloads.freenetproject.org/alpha/thingamablog/thingamablog.zip")),
              HTMLNode.link(
                  "/CHK@o8j9T2Ghc9cfKMLvv9aLrHbvW5XiAMEGwGDqH2UANTk,sVxLdxoNL-UAsvrlXRZtI5KyKlp0zv3Ysk4EcO627V0,AAIC--8/thingamablog.zip")
            });

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  /**
   * Localized string helper scoped to this toadlet.
   *
   * @param string suffix key appended to {@code InsertFreesiteToadlet.} in the localization bundle
   * @return resolved localization value or the key itself if missing; never {@code null}
   */
  private static String l10n(String string) {
    return NodeL10n.getBase().getString("InsertFreesiteToadlet." + string);
  }

  /**
   * Return the mount path used by the toadlet container to route freesite help requests.
   *
   * @return absolute path {@code "/insertsite/"}; stable for bookmarks and menu entries
   */
  @Override
  public String path() {
    return "/insertsite/";
  }
}
