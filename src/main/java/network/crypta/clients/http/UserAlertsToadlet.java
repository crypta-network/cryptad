package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.util.NoSuchElementException;
import java.util.Objects;
import javax.naming.SizeLimitExceededException;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.AbstractNodeToNodeFileOfferUserAlert;
import network.crypta.node.useralerts.NodeToNodeMessageUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;

/**
 * Serves the user alerts HTTP toadlet that lists, dismisses, and deletes locally generated alerts.
 *
 * <p>This toadlet renders a dedicated alerts page for browser clients. The page shows the current
 * queue of {@link UserAlert} instances produced by the running node, optionally providing bulk
 * controls to dismiss every dismissible alert or to permanently delete node-to-node messages after
 * explicit confirmation. When no alerts exist it renders a localized infobox explaining that the
 * inbox is empty. The class is stateless apart from its injected client, so each invocation uses
 * the request-scoped {@link ToadletContext} and the alert manager it exposes.
 *
 * <p>Typical callers route GET requests through {@link #handleMethodGET(URI, HTTPRequest,
 * ToadletContext)} to display alerts and POST requests through {@link #handleMethodPOST(URI,
 * HTTPRequest, ToadletContext)} to process user actions before redirecting back to a safe target.
 * The toadlet assumes the caller already enforces authentication; it performs a final full-access
 * check on entry. All HTML is generated via {@link network.crypta.support.HTMLNode} helpers to keep
 * markup consistent with the surrounding UI.
 *
 * <ul>
 *   <li>Responsibilities: render alert list, expose bulk dismiss/delete controls, perform safe
 *       redirects after mutation.
 *   <li>Thread safety: relies on request-scoped context; no mutable state stored on the instance.
 * </ul>
 *
 * @author toad
 */
public class UserAlertsToadlet extends Toadlet {

  private static final String DISMISS_ALL_ALERTS_PART = "dismissAllAlerts";
  private static final String DELETE_ALL_MESSAGES_PART = "deleteAllMessages";
  private static final String REALLY_DELETE_AFFIRMED = "reallyDeleteAffirmed";
  private static final String ATTRIBUTE_CLASS = "class";
  private static final String TITLE = "title";
  private static final String INPUT_TAG = "input";

  UserAlertsToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  /**
   * Handles GET requests to render the alerts page and present available bulk actions.
   *
   * <p>The method first enforces full-access requirements for the current user, then constructs a
   * page using the {@link PageMaker} provided by the context. When alerts exist it attaches
   * localized buttons to dismiss every dismissible alert or delete eligible node-to-node messages;
   * otherwise it renders a friendly infobox explaining that no messages are pending. The resulting
   * HTML is written with a 200 OK status and without modifying alert state.
   *
   * @param uri absolute request URI that should point to the "alerts" endpoint.
   * @param request HTTP request carrying any query parameters; body content is ignored.
   * @param ctx request-scoped toadlet context supplying alert manager, page maker, and security.
   * @throws ToadletContextClosedException if the client connection closes before the response
   *     completes writing.
   * @throws IOException if the response cannot be generated or sent to the client successfully.
   */
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!ctx.checkFullAccess(this)) return;

    PageNode page = ctx.getPageMaker().getPageNode(l10n(TITLE), ctx);
    HTMLNode contentNode = page.getContentNode();
    HTMLNode alertsNode = ctx.getAlertManager().createAlerts(false);
    if (alertsNode.getFirstTag() == null) {
      alertsNode = new HTMLNode("div", ATTRIBUTE_CLASS, "infobox");
      alertsNode
          .addChild("div", ATTRIBUTE_CLASS, "infobox-content")
          .addChild("div", NodeL10n.getBase().getString("UserAlertsToadlet.noMessages"));
    } else {
      addDismissAllButtons(ctx, contentNode);
    }
    contentNode.addChild(alertsNode);

    writeHTMLReply(ctx, 200, "OK", page.generate());
  }

  private void addDismissAllButtons(ToadletContext ctx, HTMLNode contentNode) {
    HTMLNode dismissAlertsContainer =
        contentNode.addChild("div", ATTRIBUTE_CLASS, "dismiss-all-alerts-container");
    HTMLNode dismissAlertsForm =
        ctx.addFormChild(dismissAlertsContainer, "", "deleteAllNotificationsForm");
    dismissAlertsForm.addChild(
        INPUT_TAG,
        new String[] {"name", "type", TITLE, "value"},
        new String[] {
          DISMISS_ALL_ALERTS_PART,
          "submit",
          l10n("dismissAlertsButtonTitle"),
          l10n("dismissAlertsButtonContent")
        });
    HTMLNode deleteMessagesForm =
        ctx.addFormChild(dismissAlertsContainer, "", "deleteAllNotificationsForm");
    deleteMessagesForm.addChild(
        INPUT_TAG,
        new String[] {"name", "type", TITLE, "value"},
        new String[] {
          DELETE_ALL_MESSAGES_PART,
          "submit",
          l10n("deleteMessagesButtonTitle"),
          l10n("deleteMessagesButtonContent")
        });
    String deleteMessagesReallyCheckboxId = "reallyDeleteAllMessagesCheckbox";
    deleteMessagesForm.addChild(
        INPUT_TAG,
        new String[] {"type", "name", "id", "required"},
        new String[] {"checkbox", REALLY_DELETE_AFFIRMED, deleteMessagesReallyCheckboxId, "true"});
    deleteMessagesForm.addChild(
        "label",
        "for",
        deleteMessagesReallyCheckboxId,
        l10n("deleteMessagesButtonReallyDeleteLabel"));
  }

  /**
   * Processes POST submissions that dismiss single alerts, dismiss all alerts, or delete messages.
   *
   * <p>The handler inspects submitted form parts to determine which action to execute. It supports
   * dismissing a single alert by hash code, bulk dismissing every user-dismissible alert, and
   * deleting all node-to-node message alerts after the caller affirms a dedicated confirmation
   * checkbox. After mutating state it redirects to a constrained, validated location to avoid
   * untrusted redirects.
   *
   * @param uri absolute request URI for the alerts endpoint; not directly mutated.
   * @param request HTTP request containing form parts that indicate the desired alert action.
   * @param ctx toadlet context providing alert management facilities and redirect helpers.
   * @throws ToadletContextClosedException if the client disconnects before the redirect headers are
   *     written.
   * @throws IOException if writing the redirect response fails for any transport-level reason.
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    Objects.requireNonNull(uri, "uri");
    if (request.isPartSet("dismiss-user-alert")) {
      dismissSingleAlert(request, ctx);
    }
    if (request.isPartSet(DISMISS_ALL_ALERTS_PART)) {
      dismissAllDismissibleAlerts(ctx);
    }

    if (request.isPartSet(DELETE_ALL_MESSAGES_PART) && request.isPartSet(REALLY_DELETE_AFFIRMED)) {
      deleteAllNodeMessages(ctx);
    }

    sendRedirectAfterDisable(request, ctx);
  }

  private void dismissSingleAlert(HTTPRequest request, ToadletContext ctx) {
    int userAlertHashCode = request.getIntPart("disable", -1);
    ctx.getAlertManager().dismissAlert(userAlertHashCode);
  }

  private void dismissAllDismissibleAlerts(ToadletContext ctx) {
    for (UserAlert alert : ctx.getAlertManager().getAlerts()) {
      if (shouldSkipAlertDismissal(alert)) {
        continue;
      }
      ctx.getAlertManager().dismissAlert(alert.hashCode());
    }
  }

  private boolean shouldSkipAlertDismissal(UserAlert alert) {
    return !alert.userCanDismiss() || alert instanceof NodeToNodeMessageUserAlert;
  }

  private void deleteAllNodeMessages(ToadletContext ctx) {
    for (UserAlert alert : ctx.getAlertManager().getAlerts()) {
      if (shouldSkipMessageDeletion(alert)) {
        continue;
      }
      ctx.getAlertManager().dismissAlert(alert.hashCode());
    }
  }

  private boolean shouldSkipMessageDeletion(UserAlert alert) {
    return !(alert instanceof NodeToNodeMessageUserAlert)
        || alert instanceof AbstractNodeToNodeFileOfferUserAlert
        || !alert.userCanDismiss();
  }

  private void sendRedirectAfterDisable(HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    String redirect = safeRedirect(request);
    MultiValueTable<String, String> headers = MultiValueTable.from("Location", redirect);
    ctx.sendReplyHeaders(302, "Found", headers, null, 0);
  }

  private String safeRedirect(HTTPRequest request) {
    String redirect;
    try {
      redirect = request.getPartAsStringThrowing("redirectToAfterDisable", 1024);
    } catch (SizeLimitExceededException | NoSuchElementException _) {
      redirect = ".";
    }
    if (!isAllowedRedirect(redirect)) {
      redirect = ".";
    }
    return redirect;
  }

  private boolean isAllowedRedirect(String redirect) {
    return "/alerts/".equals(redirect) || "/".equals(redirect) || "/#bookmarks".equals(redirect);
  }

  private static String l10n(String name) {
    return NodeL10n.getBase().getString("UserAlertsToadlet." + name);
  }

  /**
   * Returns the canonical HTTP path served by this toadlet.
   *
   * <p>The path is used by routing code and by safe-redirect checks inside this class to ensure
   * callers are returned to the correct alerts landing page after POST actions. It is a constant
   * string and does not vary by configuration or locale.
   *
   * @return immutable path string {@code "/alerts/"} that identifies the "alerts" endpoint.
   */
  @Override
  public String path() {
    return "/alerts/";
  }
}
