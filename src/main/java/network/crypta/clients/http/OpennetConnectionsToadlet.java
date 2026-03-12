package network.crypta.clients.http;

import java.util.Comparator;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.OpennetPeerNodeStatus;
import network.crypta.node.PeerNodeStatus;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;

/**
 * Toadlet that renders the opennet peer list for the FProxy UI, focusing on anonymous stranger
 * connections rather than trust-based friend links. It delegates common table layout to the {@link
 * ConnectionsToadlet} base while stripping features that depend on identities, such as names or
 * user-supplied notes. The handler exposes a noderef box only in advanced mode, surfaces the
 * last-success metric for troubleshooting, and otherwise provides a minimal, read-only view of
 * current opennet connectivity. It assumes the surrounding node keeps peer status up to date and is
 * enabled for opennet operation.
 *
 * <p>Typical callers rely on the base routing that maps {@link #path()} to the stranger list. The
 * instance is stateless between requests: it reads fresh peer snapshots for each render and does
 * not cache noderefs or per-peer actions. The table is intentionally sparse to discourage behavior
 * that could deanonymize peers or encourage targeted management.
 *
 * <p>Thread-safety mirrors the base toadlet: instances are expected to be used on the request
 * thread managed by the HTTP layer, and no shared mutable state is introduced here. It is suitable
 * for multithreaded servlet environments as long as the injected {@link Node} and supporting
 * collaborators are themselves thread-safe.
 */
public class OpennetConnectionsToadlet extends ConnectionsToadlet implements LinkEnabledCallback {

  /**
   * Builds an opennet-specific toadlet using the shared node components required to render peer
   * state. Callers supply the node, client core, and a high-level client wrapper; the constructor
   * merely stores them for the base class without adding additional side effects. The instance can
   * be created eagerly during UI wiring because it defers all data retrieval to per-request
   * handlers, avoiding heavy startup costs.
   *
   * @param n node that owns the peer set and opennet configuration; must remain reachable
   *     throughout the toadlet lifetime.
   * @param core client core used by the base toadlet for noderef export and related helpers; not
   *     null when opennet is enabled.
   * @param client high-level client for UI links and redirects; expected to be configured for
   *     opennet-safe operations.
   */
  protected OpennetConnectionsToadlet(Node n, NodeClientCore core, HighLevelSimpleClient client) {
    super(n, core, client);
  }

  /**
   * Suppresses name rendering for opennet peers because identities are intentionally unavailable.
   * This override keeps the table layout consistent with the base class while ensuring no empty
   * cells or misleading headings are produced when names cannot be derived safely.
   *
   * @param peerRow table row node that would normally receive the name cell output.
   * @param peerNodeStatus status snapshot for the peer whose row is being rendered in the table.
   * @param advanced whether advanced UI mode is active; retained for signature compatibility only.
   */
  @Override
  protected void drawNameColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean advanced) {
    // Do nothing - no names on opennet
  }

  /**
   * Disables the private-note column because the opennet model lacks user-managed trust metadata.
   * Keeping this method as a no-op prevents accidental rendering of fields that would suggest
   * mutable annotations on strangers, which the UI and persistence layers do not support.
   *
   * @param peerRow table row node for the current peer being rendered in the list view.
   * @param peerNodeStatus status object describing connectivity and performance for the peer.
   * @param fProxyJavascriptEnabled flag indicating whether JavaScript helpers are available in the
   *     browser session; unused because the column is suppressed unconditionally.
   */
  @Override
  protected void drawPrivateNoteColumn(
      HTMLNode peerRow, PeerNodeStatus peerNodeStatus, boolean fProxyJavascriptEnabled) {
    // Do nothing - no private notes either (no such thing as negative trust in cyberspace)
  }

  /**
   * Indicates that the opennet table omits the name column entirely.
   *
   * <p>Opennet peers present only cryptographic identifiers, so exposing a name column would either
   * remain blank or mislead users into thinking a stable label exists. Keeping this flag false also
   * simplifies column counts elsewhere in the table layout and prevents localization strings for
   * names from being loaded unnecessarily.
   *
   * @return always {@code false} because opennet peers are not associated with human-readable
   *     names.
   */
  @Override
  protected boolean hasNameColumn() {
    return false;
  }

  /**
   * Reports that the private note column is unavailable for opennet peers.
   *
   * <p>The design intentionally removes ad hoc annotations on strangers to reduce risk of leaking
   * identifiable hints or encouraging user-managed reputation for anonymous participants.
   * Downstream renderers and CSV exporters can rely on this flag to avoid allocating unused cells
   * or headers and to align other columns correctly when opennet mode is active.
   *
   * @return always {@code false} because private annotations are not supported in opennet mode.
   */
  @Override
  protected boolean hasPrivateNoteColumn() {
    return false;
  }

  /**
   * Exports the public opennet noderef from the hosting node so that advanced users can copy it.
   * The returned field set reflects the node's current opennet identity and is fetched fresh for
   * each request to avoid stale values.
   *
   * @return field set containing the opennet noderef, ready for serialization into the response
   *     page.
   */
  @Override
  protected SimpleFieldSet getNoderef() {
    return node.network().exportOpennetPublicFieldSet();
  }

  /**
   * Retrieves the current opennet peer status snapshots used to populate the table rows. The caller
   * controls whether heavy data (such as bandwidth histories) should be excluded to reduce
   * rendering cost when the page is not in advanced mode.
   *
   * @param noHeavy when {@code true}, request lightweight status objects that omit expensive
   *     metrics to keep UI responses fast.
   * @return array of {@link PeerNodeStatus} entries describing each opennet peer known to the node;
   *     never {@code null} but may be empty.
   */
  @Override
  protected PeerNodeStatus[] getPeerNodeStatuses(boolean noHeavy) {
    return node.network().peers().statusBook().getOpennetPeerNodeStatuses(noHeavy);
  }

  /**
   * Checks whether opennet support is currently enabled on the hosting node before serving the
   * toadlet. Requests are only allowed when opennet is active, preventing exposure of partial UI
   * state while the feature is disabled or unavailable.
   *
   * @param ctx HTTP context passed by the caller; used by the base class for permission checks and
   *     locale selection.
   * @return {@code true} when opennet is enabled on the node and the page may be rendered.
   */
  @Override
  public boolean isEnabled(ToadletContext ctx) {
    return node.network().isOpennetEnabled();
  }

  /**
   * Builds the localized page title string, embedding the formatted peer count supplied by the base
   * class. The title is used by the surrounding FProxy layout and should remain short while still
   * distinguishing opennet content from friend connections.
   *
   * @param titleCountString pre-formatted text representing the current peer counts shown in the
   *     header.
   * @return localized title string describing the opennet connections page with embedded counts.
   */
  @Override
  protected String getPageTitle(String titleCountString) {
    return NodeL10n.getBase()
        .getString(
            "OpennetConnectionsToadlet.fullTitle",
            new String[] {"counts"},
            new String[] {titleCountString});
  }

  /**
   * Determines whether to show the noderef export box. The box is only shown when advanced mode is
   * enabled to avoid overwhelming casual users and to reduce accidental sharing of noderefs.
   *
   * @param advancedModeEnabled {@code true} when the UI is in advanced mode, typically toggled by
   *     the user.
   * @return {@code true} if the noderef box should be displayed for the current request.
   */
  @Override
  protected boolean shouldDrawNoderefBox(boolean advancedModeEnabled) {
    return advancedModeEnabled;
  }

  /**
   * Indicates that per-peer action controls are hidden for opennet peers. The opennet model makes
   * peer-specific management ineffective because peers can reconnect with fresh identities, and the
   * UI avoids exposing controls that could be misused for targeted spam.
   *
   * @return always {@code false}, meaning no action box is rendered for any peer row.
   */
  @Override
  protected boolean showPeerActionsBox() {
    // No per-peer actions supported on opennet - there's no point, they'll only reconnect,
    // possibly as a different identity. And we don't want to be able to send N2NTM spam either.
    return false;
  }

  /**
   * Omits the peer action select box because opennet peers do not support direct actions. The
   * method remains to satisfy the base class contract and to document why the UI intentionally
   * leaves this area blank.
   *
   * @param peerForm table row form node that would ordinarily host action controls for the peer.
   * @param advancedModeEnabled flag indicating advanced mode; unused because the box is always
   *     suppressed.
   */
  @Override
  protected void drawPeerActionSelectBox(HTMLNode peerForm, boolean advancedModeEnabled) {
    // Do nothing, see showPeerActionsBox().
  }

  /**
   * Supplies the localized title for the opennet peers list. The title appears above the table and
   * clarifies that entries correspond to stranger connections rather than friend nodes.
   *
   * <p>Localization is resolved on each request so the title reflects the active language choice of
   * the current user, and separating the text from code keeps the wording aligned with the rest of
   * the UI. The returned string is short to fit within common header constraints while remaining
   * distinct from friend connection screens.
   *
   * @return localized list title pulled from the node localization bundle.
   */
  @Override
  protected String getPeerListTitle() {
    return NodeL10n.getBase().getString("OpennetConnectionsToadlet.peersListTitle");
  }

  /**
   * Accepts posted noderefs so opennet peers can be added from the web interface. The base class
   * uses this flag to determine whether to parse and handle submission payloads on this toadlet.
   * Accepting posts keeps the page functional for bootstrap and manual additions where peers share
   * their references out-of-band, while still letting higher layers enforce authentication and CSRF
   * protections applicable to FProxy forms.
   *
   * @return {@code true} to allow noderef form submissions for opennet stranger connections.
   */
  @Override
  protected boolean acceptRefPosts() {
    return true;
  }

  /**
   * Provides the redirect target used when the toadlet needs to bounce the user after processing a
   * form or encountering an error. It always returns the opennet landing path to keep navigation
   * consistent.
   *
   * <p>Using a fixed location avoids leaking intermediate URLs and reduces the chance of confusing
   * users with partial states after submitting a noderef. The target matches the canonical entry
   * point of this page so refreshed state is immediately visible after the redirect completes.
   *
   * @return fixed redirect path {@code "/opennet/"} for opennet UI flows.
   */
  @Override
  protected String defaultRedirectLocation() {
    return "/opennet/";
  }

  /**
   * Identifies this toadlet as serving opennet content. The base class uses this to branch between
   * friend and stranger behaviors when shared hooks are invoked.
   *
   * <p>Returning a hardcoded {@code true} keeps downstream logic simple: caching layers, menu
   * builders, and link helpers can specialize styling or wording without re-inspecting the class
   * hierarchy. This method should remain consistent with {@link #path()} and other opennet-specific
   * toggles.
   *
   * @return always {@code true} to mark the opennet flavor of the connections page.
   */
  @Override
  protected boolean isOpennet() {
    return true;
  }

  /**
   * Comparator tailored to opennet peers that optionally prioritizes the time of last successful
   * communication. It augments the base {@link ComparatorByStatus} sorting logic with opennet-only
   * metrics while preserving support for reversed ordering when requested by the caller.
   *
   * <p>The comparator is created per request to encapsulate the active sort key and direction,
   * ensuring thread-safety and allowing multiple concurrent sorts without shared mutable state.
   */
  protected class OpennetComparator extends ComparatorByStatus {

    OpennetComparator(String sortBy, boolean reversed) {
      super(sortBy, reversed);
    }

    /**
     * Adds custom comparison for the {@code successTime} sort key by inspecting the
     * opennet-specific last-success timestamps. When the key does not match, the method falls back
     * to the base comparator behavior, preserving existing ordering semantics for other columns.
     *
     * @param firstNode first peer node considered by the comparison routine; expected to be an
     *     {@link OpennetPeerNodeStatus} instance.
     * @param secondNode second peer node considered by the comparison routine; expected to be an
     *     {@link OpennetPeerNodeStatus} instance.
     * @return negative, zero, or positive according to the configured ordering and reversal flag,
     *     using last-success timestamps when available.
     */
    @Override
    protected int customCompare(PeerNodeStatus firstNode, PeerNodeStatus secondNode) {
      if (this.sortBy.equals("successTime")) {
        long t1 = ((OpennetPeerNodeStatus) firstNode).timeLastSuccess;
        long t2 = ((OpennetPeerNodeStatus) secondNode).timeLastSuccess;
        if (t1 > t2) return reversed ? 1 : -1;
        else if (t2 > t1) return reversed ? -1 : 1;
      }
      return super.customCompare(firstNode, secondNode);
    }
  }

  /**
   * Creates the comparator to be used for sorting the opennet peer list. The method instantiates a
   * fresh {@link OpennetComparator} so caller-specific sort keys and directions do not interfere
   * across requests or threads.
   *
   * @param sortBy column identifier specifying which property to sort on, such as {@code
   *     \"successTime\"}.
   * @param reversed when {@code true}, invert the natural ordering produced by the comparator.
   * @return comparator that respects the provided sort key and reversal flag for opennet peers.
   */
  @Override
  protected Comparator<PeerNodeStatus> comparator(String sortBy, boolean reversed) {
    return new OpennetComparator(sortBy, reversed);
  }

  /**
   * Defines the trailing columns for the peer table. In advanced mode the method adds a single
   * column showing the elapsed time since the last successful communication with each peer; in
   * basic mode it returns an empty array to keep the layout compact.
   *
   * @param advancedMode flag indicating whether advanced UI elements should be included in the
   *     response.
   * @return array of simple column definitions to append to the table; never {@code null}.
   */
  @Override
  SimpleColumn[] endColumnHeaders(boolean advancedMode) {
    if (!advancedMode) return new SimpleColumn[0];
    return new SimpleColumn[] {
      new SimpleColumn() {

        @Override
        protected void drawColumn(HTMLNode peerRow, PeerNodeStatus peerNodeStatus) {
          OpennetPeerNodeStatus status = (OpennetPeerNodeStatus) peerNodeStatus;
          long tLastSuccess = status.timeLastSuccess;
          peerRow.addChild(
              "td",
              "class",
              "peer-last-success",
              tLastSuccess > 0
                  ? TimeUtil.formatTime(System.currentTimeMillis() - tLastSuccess)
                  : "NEVER");
        }

        @Override
        public String getExplanationKey() {
          return "OpennetConnectionsToadlet.successTime";
        }

        @Override
        public String getSortString() {
          return "successTime";
        }

        @Override
        public String getTitleKey() {
          return "OpennetConnectionsToadlet.successTimeTitle";
        }
      }
    };
  }

  /**
   * Returns the relative path that maps HTTP requests to this toadlet within the FProxy routing
   * tree. The path is intentionally distinct from friend connections to help users differentiate
   * stranger links.
   *
   * <p>The trailing slash matches existing routing conventions and helps browser refreshes stay on
   * the same page even when query parameters are stripped. External links and navigation menus
   * should treat this path as stable while the opennet feature set remains available.
   *
   * @return constant path string {@code "/strangers/"} identifying the opennet connections page.
   */
  @Override
  public String path() {
    return "/strangers/";
  }
}
