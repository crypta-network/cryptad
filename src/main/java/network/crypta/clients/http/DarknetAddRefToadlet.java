package network.crypta.clients.http;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeFile;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.FileBucket;

/**
 * Serves the “Add Friend” HTTP endpoint for darknet peers, including helper links to packaged node
 * installers and the current public node reference.
 *
 * <p>This toadlet is invoked when a remote browser navigates to the add-friend URL exposed by the
 * node. It renders explanatory text about darknet peering, inserts the alert summary, and offers
 * OS-specific installer downloads if they are already present on disk. The handler also embeds the
 * current darknet noderef so that users can import it directly into compatible clients. Typical
 * call flow is: the UI router dispatches to this toadlet, {@link #handleMethodGET(URI, HTTPRequest,
 * ToadletContext)} builds the page via {@link PageMaker}, and {@link #getNoderef()} supplies the
 * serialized public fields.
 *
 * <p>Thread safety: the class is stateless beyond references to {@link Node} and the companion
 * toadlet; it relies on the surrounding HTTP framework for synchronization. Instances are usually
 * constructed once at node startup and reused for many requests. It assumes the {@link Node}
 * provides up-to-date installers and noderefs and that callers perform access checks via the
 * provided {@link ToadletContext}.
 *
 * <ul>
 *   <li>Renders localized explanations and guidance for adding a friend.
 *   <li>Streams prebuilt installers when available to simplify onboarding.
 *   <li>Publishes the node’s darknet reference for import by trusted peers.
 * </ul>
 *
 * @see DarknetConnectionsToadlet
 * @see Node#exportDarknetPublicFieldSet()
 */
public class DarknetAddRefToadlet extends Toadlet {

  private final Node node;
  private final DarknetConnectionsToadlet friendsToadlet;

  /**
   * Creates the toadlet with the dependencies required to generate darknet onboarding pages.
   *
   * <p>The constructor wires the owning {@link Node} for state such as installer paths and noderef
   * export, the high-level client for inherited toadlet functionality, and the companion
   * connections toadlet used to draw peer-related UI sections. Callers typically instantiate this
   * once during HTTP handler setup and keep it alive for the lifetime of the node so that cached
   * installers remain accessible and localization resources stay loaded.
   *
   * @param n node instance supplying installer access and noderef export; must not be {@code null}
   *     and should outlive the toadlet.
   * @param client high-level HTTP client the superclass relies on for responses and redirects; may
   *     share the lifecycle of the enclosing HTTP server.
   * @param friendsToadlet companion toadlet used to render friend lists and noderef boxes within
   *     this page; should correspond to the same node instance.
   */
  protected DarknetAddRefToadlet(
      Node n, HighLevelSimpleClient client, DarknetConnectionsToadlet friendsToadlet) {
    super(client);
    this.node = n;
    this.friendsToadlet = friendsToadlet;
  }

  /**
   * Handles a GET request to the add-friend page, streaming installers or rendering guidance as
   * appropriate.
   *
   * <p>The method first enforces full-access permissions through the supplied {@link
   * ToadletContext}. When the requested path matches a platform-specific installer filename, it
   * streams the file directly with the correct MIME type. Otherwise, it generates an HTML page with
   * localized explanations, download links, and the node’s exported darknet reference. The response
   * always terminates with a 200 status unless access is denied or a redirect is triggered by the
   * framework.
   *
   * <pre>{@code
   * // Typical usage from routing layer
   * toadlet.handleMethodGET(uri, request, context);
   * }</pre>
   *
   * @param uri requested URI used to detect installer downloads and to build relative links; must
   *     include the path component.
   * @param request HTTP request carrying headers and parameters; not modified by this method.
   * @param ctx toadlet context providing authorization checks, page rendering helpers, and reply
   *     writers; must be open for the duration of the call.
   * @throws ToadletContextClosedException if the context is closed before the response is written
   *     or when permission checks cannot complete.
   * @throws IOException if reading installer files or writing the response stream fails due to
   *     underlying I/O issues.
   * @throws RedirectException if the framework requests a redirect instead of returning content in
   *     this handler.
   */
  public void handleMethodGET(URI uri, final HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (!ctx.checkFullAccess(this)) return;

    String path = uri.getPath();
    if (path.endsWith(NodeFile.INSTALLER_WINDOWS.getFilename())) {
      File installer = node.getNodeUpdater().getInstallerWindows();
      if (installer != null) {
        FileBucket bucket = new FileBucket(installer, true, false, false, false);
        this.writeReply(ctx, 200, "application/x-msdownload", "OK", bucket);
        return;
      }
    }

    if (path.endsWith(NodeFile.INSTALLER_NON_WINDOWS.getFilename())) {
      File installer = node.getNodeUpdater().getInstallerNonWindows();
      if (installer != null) {
        FileBucket bucket = new FileBucket(installer, true, false, false, false);
        this.writeReply(ctx, 200, "application/x-java-archive", "OK", bucket);
        return;
      }
    }

    PageMaker pageMaker = ctx.getPageMaker();

    PageNode page = pageMaker.getPageNode(l10n("title"), ctx);
    HTMLNode contentNode = page.getContentNode();

    contentNode.addChild(ctx.getAlertManager().createSummary());

    HTMLNode boxContent =
        pageMaker.getInfobox(
            "infobox-information",
            l10n("explainBoxTitle"),
            contentNode,
            "darknet-explanations",
            true);
    boxContent.addChild("p", l10n("explainBox1"));
    boxContent.addChild("p", l10n("explainBox2"));

    File installer = node.getNodeUpdater().getInstallerWindows();
    String shortFilename = NodeFile.INSTALLER_WINDOWS.getFilename();

    HTMLNode p = boxContent.addChild("p");

    if (installer != null)
      NodeL10n.getBase()
          .addL10nSubstitution(
              p,
              "DarknetAddRefToadlet.explainInstallerWindows",
              new String[] {"filename", "get-windows"},
              new HTMLNode[] {
                HTMLNode.text(installer.getCanonicalPath()), HTMLNode.link(path() + shortFilename)
              });
    else
      NodeL10n.getBase()
          .addL10nSubstitution(
              p,
              "DarknetAddRefToadlet.explainInstallerWindowsNotYet",
              new String[] {"link"},
              new HTMLNode[] {
                HTMLNode.link("/" + node.getNodeUpdater().getInstallerWindowsURI().toString())
              });

    installer = node.getNodeUpdater().getInstallerNonWindows();
    shortFilename = NodeFile.INSTALLER_NON_WINDOWS.getFilename();

    boxContent.addChild("#", " ");

    p = boxContent.addChild("p");

    if (installer != null)
      NodeL10n.getBase()
          .addL10nSubstitution(
              p,
              "DarknetAddRefToadlet.explainInstallerNonWindows",
              new String[] {"filename", "get-nonwindows", "shortfilename"},
              new HTMLNode[] {
                HTMLNode.text(installer.getCanonicalPath()),
                HTMLNode.link(path() + shortFilename),
                HTMLNode.text(shortFilename)
              });
    else
      NodeL10n.getBase()
          .addL10nSubstitution(
              p,
              "DarknetAddRefToadlet.explainInstallerNonWindowsNotYet",
              new String[] {"link", "shortfilename"},
              new HTMLNode[] {
                HTMLNode.link("/" + node.getNodeUpdater().getInstallerNonWindowsURI().toString()),
                HTMLNode.text(shortFilename)
              });

    ConnectionsToadlet.drawAddPeerBox(contentNode, ctx, false, friendsToadlet.path());

    friendsToadlet.drawNoderefBox(contentNode, getNoderef());

    this.writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  /**
   * Exposes the public darknet noderef for this node as a field set suitable for embedding in
   * responses.
   *
   * <p>The returned {@link SimpleFieldSet} contains only public fields and is constructed by the
   * underlying {@link Node} at call time, ensuring that peers receive up-to-date routing and key
   * material. Callers should treat the object as read-only and avoid persisting it beyond the
   * immediate HTTP response, because it reflects the node’s current configuration and may change
   * when peers or keys are rotated.
   *
   * @return immutable view of the node’s exported darknet reference fields; ownership remains with
   *     the caller for serialization but should not be mutated.
   */
  protected SimpleFieldSet getNoderef() {
    return node.exportDarknetPublicFieldSet();
  }

  private static String l10n(String string) {
    return NodeL10n.getBase().getString("DarknetAddRefToadlet." + string);
  }

  private static String buildPath() {
    return "/" + "addfriend" + "/";
  }

  static final String PATH = buildPath();

  /**
   * Returns the routing path under which this toadlet is exposed to clients.
   *
   * <p>The path is stable for the lifetime of the application and is derived from a static helper
   * to keep URL construction centralized. Callers can rely on this value to build links to the
   * add-friend page or to register the toadlet with the HTTP router. The returned string always
   * includes leading and trailing slashes to match the expected endpoint shape.
   *
   * @return canonical toadlet path beginning and ending with {@code /} for router registration and
   *     link generation.
   */
  @Override
  public String path() {
    return PATH;
  }
}
