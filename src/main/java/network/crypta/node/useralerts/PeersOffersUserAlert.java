package network.crypta.node.useralerts;

import java.io.File;
import network.crypta.clients.http.complexhtmlnodes.PeerTrustInputForAddPeerBoxNode;
import network.crypta.clients.http.complexhtmlnodes.PeerVisibilityInputForAddPeerBoxNode;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.support.HTMLNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User alert that proposes connecting to peers discovered via {@code .fref} offer files.
 *
 * <p>This alert is registered when the node finds one or more files with the {@code .fref}
 * extension inside the {@code peers-offers} directory under the node's run directory. The alert
 * renders explanatory text and an HTML form that posts to the {@code /friends/} endpoint so a user
 * may import the offered peers in a single action. The form includes hidden authentication ({@code
 * formPassword}) and fields for peer trust and visibility created by {@link
 * network.crypta.clients.http.complexhtmlnodes.PeerTrustInputForAddPeerBoxNode} and {@link
 * network.crypta.clients.http.complexhtmlnodes.PeerVisibilityInputForAddPeerBoxNode}.
 *
 * <p>Typical usage is indirect: clients call {@link #createAlert(Node)} to scan for offers and, if
 * any are found, this class registers itself with the alert subsystem. The alert can be dismissed
 * by the user; dismissal persists a configuration flag so the prompt is not repeatedly shown until
 * new offer files appear. Instances are short‑lived and constructed only when content needs to be
 * displayed.
 *
 * <p>Thread-safety: instances are not explicitly synchronized. The alert is created and used on the
 * node's management/UI threads, and relies on the underlying configuration and localization
 * facilities for concurrency guarantees. No mutable state is exposed outside the class.
 *
 * @see AbstractUserAlert
 * @see Node
 */
public class PeersOffersUserAlert extends AbstractUserAlert {
  private static final Logger LOG = LoggerFactory.getLogger(PeersOffersUserAlert.class);

  private static final String TAG_INPUT = "input";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";

  private final String frefFiles;

  private final Node node;

  private PeersOffersUserAlert(Node node, String frefFiles) {
    this.frefFiles = frefFiles;
    this.node = node;
  }

  /**
   * Detects peer offer files and registers an alert when appropriate.
   *
   * <p>The method scans the {@code peers-offers} directory beneath the node's run directory and
   * collects the names of files ending with {@code .fref}. If at least one file is present, a new
   * alert instance is created and registered with the node's alert manager. The method performs no
   * I/O beyond listing the directory and does not delete or move files; it simply advertises their
   * presence to the user.
   *
   * @param node the running {@link Node} whose run directory is searched and whose alert manager is
   *     used to register the alert; must not be {@code null} and is expected to be initialized.
   */
  public static void createAlert(Node node) {
    File[] files = node.runDir().file("peers-offers").listFiles();
    if (files != null && files.length > 0) {
      StringBuilder frefFiles = new StringBuilder();
      String prefix = "";
      for (final File file : files) {
        if (file.isFile()) {
          String filename = file.getName();
          if (filename.endsWith(".fref")) {
            frefFiles.append(prefix).append(file.getName());
            prefix = ", ";
          }
        }
      }
      node.services()
          .clientCore()
          .getAlerts()
          .register(new PeersOffersUserAlert(node, frefFiles.toString()));
    }
  }

  /**
   * Returns the localized title displayed for this alert.
   *
   * <p>The title is resolved via the node localization bundle using the key {@code
   * PeersOffersUserAlert.title}. Implementations should keep this short for use in headers and
   * lists of alerts.
   *
   * @return a non-null, possibly localized human‑readable title suitable for UI display
   */
  @Override
  public String getTitle() {
    return l10n("title");
  }

  /**
   * Builds the HTML body describing the alert and the input form to add peers.
   *
   * <p>The returned node contains explanatory text plus a {@code form} that posts to {@code
   * /friends/}. The form includes: a hidden {@code formPassword} for CSRF/authentication, a hidden
   * marker indicating the presence of offer files, controls to select trust and visibility for the
   * new peers, and a submit button labeled {@code Connect}. The list of detected {@code .fref}
   * filenames is also included for user awareness. The returned tree is ready for server-side
   * rendering and contains no client-side scripts.
   *
   * @return a newly constructed {@link HTMLNode} tree representing the alert’s content and form;
   *     callers should treat it as immutable after creation
   */
  @Override
  public HTMLNode getHTMLText() {
    HTMLNode content = new HTMLNode("div");
    content.addChild("p", l10n("text"));
    content.addChild("p", frefFiles);
    HTMLNode form =
        content.addChild(
            "form", new String[] {"action", "method"}, new String[] {"/friends/", "post"});
    form.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {"hidden", "formPassword", node.services().clientCore().getFormPassword()});
    form.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {"hidden", "peers-offers-files", "true"});

    form.addChild(new PeerTrustInputForAddPeerBoxNode());
    form.addChild(new PeerVisibilityInputForAddPeerBoxNode());

    form.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {"submit", "add", "Connect"});

    return content;
  }

  /**
   * Returns the localized label for the dismiss button.
   *
   * <p>This implementation uses a shared base localization key (mapped to a short {@code No}) that
   * keeps the dismiss affordance consistent with other alerts in the UI. The text is intended for a
   * button control and should remain concise.
   *
   * @return a non-null, localized string suitable for a button that dismisses the alert
   */
  @Override
  public String dismissButtonText() {
    return NodeL10n.getBase().getString("Toadlet.no");
  }

  /**
   * Applies the user's dismissal action and records the preference in configuration.
   *
   * <p>On dismissal, the configuration key {@code node.peersOffersDismissed} is set to {@code
   * true}. If validation fails or a restart is required, the alert is marked invalid to avoid
   * repeatedly presenting a broken control surface. Failures are logged at debug level using the
   * localized exception message.
   */
  @Override
  public void onDismiss() {
    try {
      node.getConfig().get("node").set("peersOffersDismissed", true);
    } catch (InvalidConfigValueException | NodeNeedRestartException e) {
      if (LOG.isDebugEnabled()) LOG.debug(e.getLocalizedMessage());
      valid = false;
    }
  }

  /**
   * Indicates that users are permitted to dismiss this alert.
   *
   * <p>The alert supports a user-driven dismissal flow that persists a configuration flag so the UI
   * does not continue showing the prompt unnecessarily. Returning {@code true} enables the UI to
   * display a standard dismiss control.
   *
   * @return {@code true} because dismissal is supported for this alert type
   */
  @Override
  public boolean userCanDismiss() {
    return true;
  }

  /**
   * Requests automatic unregistration when the alert is dismissed.
   *
   * <p>When {@code true}, the alert subsystem should remove this alert from its registry upon a
   * successful dismissal so it no longer appears in subsequent listings. This does not delete any
   * underlying {@code .fref} files; it only affects presentation.
   *
   * @return {@code true} to unregister this alert after dismissal
   */
  @Override
  public boolean shouldUnregisterOnDismiss() {
    return true;
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("PeersOffersUserAlert." + key);
  }
}
