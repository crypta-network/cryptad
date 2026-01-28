package network.crypta.node.useralerts;

import java.io.File;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.updater.RevocationChecker;
import network.crypta.support.HTMLNode;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * User alert shown when a newer stable version of Crypta is available.
 *
 * <p>This alert aggregates state from the {@link network.crypta.node.updater.NodeUpdateManager} and
 * presents it to end users in both plain-text and HTML forms. It communicates whether an update is
 * being downloaded, has been verified, or is ready to install, and it may offer a simple action
 * button to proceed. The alert also embeds links to release notes and developer changelogs when
 * available. The text and priority adapt to the updater's state so that more urgent conditions
 * surface with higher visibility.
 *
 * <p>Instances are lightweight and read-only with respect to updater state; they derive all text
 * and flags on demand. The class is not thread-safe in isolation but relies on the updater to
 * provide consistent snapshots. Typical usage is within UI flows that periodically render alerts
 * for the node and refresh their content as updater progress changes.
 *
 * <ul>
 *   <li>Renders concise status via {@link #getShortText()} for summaries.
 *   <li>Provides detailed text via {@link #getText()} and structured HTML via {@link
 *       #getHTMLText()}.
 *   <li>Surfaces urgency using {@link #getPriorityClass()} to integrate with alert ranking.
 * </ul>
 *
 * @see network.crypta.node.updater.NodeUpdateManager
 * @see network.crypta.support.HTMLNode
 * @see network.crypta.node.useralerts.UserAlert
 */
public class UpdatedVersionAvailableUserAlert extends AbstractUserAlert {
  private static final Logger LOG = LoggerFactory.getLogger(UpdatedVersionAvailableUserAlert.class);
  private static final String L10N_PREFIX = "UpdatedVersionAvailableUserAlert.";

  private final NodeUpdateManager updater;

  /**
   * Creates an alert bound to the given updater.
   *
   * <p>The updater supplies all state used to compose user-facing strings, determine whether the
   * alert is currently valid, and compute its priority. The constructor does not perform I/O and
   * does not capture mutable snapshots; instead, methods query the updater each time they are
   * called so the alert reflects the most recent progress.
   *
   * @param updater the {@link NodeUpdateManager} providing update status, progress, and actions;
   *     must be non-null and remain valid for the lifetime of this alert instance
   */
  public UpdatedVersionAvailableUserAlert(NodeUpdateManager updater) {
    super(
        false,
        null,
        null,
        (short) 0,
        false,
        new AbstractUserAlert.DismissOptions(
            NodeL10n.getBase().getString("UserAlert.hide"), false));
    this.updater = updater;
  }

  /**
   * Returns the localized title for this alert.
   *
   * <p>The title is a short, stable string intended for list headers and dialog banners.
   * Localization keys are resolved via {@link network.crypta.l10n.NodeL10n}.
   *
   * @return a human-readable, localized title suitable for display in headers
   */
  @Override
  public String getTitle() {
    return l10n("title");
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key);
  }

  private String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString(L10N_PREFIX + key, pattern, value);
  }

  // Dedicated helper for the only multi-pattern key used here.
  private String l10nFinalCheck(String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(L10N_PREFIX + "finalCheck", patterns, values);
  }

  /**
   * Builds a detailed, human-readable message describing the update state.
   *
   * <p>The returned string can include a minimal HTML {@code <form>} snippet with a submit button
   * when an immediate action is available (for example, “Update Now” or “Update ASAP”). Callers
   * that cannot render HTML should prefer {@link #getShortText()} or sanitize the markup before
   * display.
   *
   * @return a localized message describing current update status, optionally including a simple
   *     HTML form with an action button
   */
  @Override
  public String getText() {

    UpdateThingy ut = createUpdateThingy();

    StringBuilder sb = new StringBuilder();

    sb.append(ut.firstBit());

    if (ut.formText() != null) {
      sb.append(
          " <form action=\"/\" method=\"post\"><input type=\"submit\" name=\"update\" value=\"");
      sb.append(ut.formText());
      sb.append("\" /></form>");
    }

    return sb.toString();
  }

  /**
   * Returns a concise, plain-text summary of the current update state.
   *
   * <p>This form is designed for compact UI surfaces such as notification lists or status bars. It
   * never includes HTML and prioritizes brevity over detail.
   *
   * @return a short, localized summary indicating readiness or ongoing download
   */
  @Override
  public String getShortText() {
    if (!updater.isArmed()) {
      if (updater.canUpdateNow()) {
        return l10n("shortReadyNotArmed");
      } else {
        return l10n("shortNotReadyNotArmed");
      }
    } else {
      return l10n("shortArmed");
    }
  }

  private record UpdateThingy(String firstBit, String formText) {}

  /**
   * Produces a structured HTML representation of this alert.
   *
   * <p>The returned {@link network.crypta.support.HTMLNode} contains the detailed message text and
   * may also include a small HTML {@code <form>} with a submit button when an action is available.
   * It appends links to changelogs and renders progress indicators when present.
   *
   * @return an {@code HTMLNode} tree suitable for rendering within the web UI
   */
  @Override
  public HTMLNode getHTMLText() {

    UpdateThingy ut = createUpdateThingy();

    HTMLNode alertNode = new HTMLNode("div");

    alertNode.addChild("#", ut.firstBit());

    if (ut.formText() != null) {
      alertNode
          .addChild("form", new String[] {"action", "method"}, new String[] {"/", "post"})
          .addChild(
              "input",
              new String[] {"type", "name", "value"},
              new String[] {"submit", "update", ut.formText()});
      alertNode.addChild(
          "input",
          new String[] {"type", "name", "value"},
          new String[] {
            "hidden", "formPassword", updater.getNode().services().clientCore().getFormPassword()
          });
    }

    // Ensure a visual separation between the armed/form message and the changelog links.
    alertNode.addChild("br");

    int version;
    if (updater.hasNewMainJar()) {
      version = updater.newMainJarVersion();
    } else if (updater.fetchingNewMainJar()) {
      version = updater.fetchingNewMainJarVersion();
    } else {
      LOG.debug("Showing version available notification but not fetching or fetched.");
      // Fallback
      version = updater.getMainVersion();
    }
    updater.addChangelogLinks(version, alertNode);

    updater.renderProgress(alertNode);

    return alertNode;
  }

  private UpdateThingy createUpdateThingy() {
    StringBuilder sb = new StringBuilder();
    sb.append(l10n("notLatest")).append(' ');

    if (updater.isArmed() && updater.inFinalCheck()) {
      appendFinalCheckInfo(sb);
      return new UpdateThingy(sb.toString(), null);
    }

    if (updater.isArmed()) {
      sb.append(l10n("armed"));
      return new UpdateThingy(sb.toString(), null);
    }

    return buildNotArmedMessage(sb);
  }

  private void appendFinalCheckInfo(StringBuilder sb) {
    sb.append(
            l10nFinalCheck(
                new String[] {"count", "max", "time"},
                new String[] {
                  Integer.toString(updater.getRevocationDNFCounter()),
                  Integer.toString(RevocationChecker.REVOCATION_DNF_MIN),
                  TimeUtil.formatTime(updater.timeRemainingOnCheck())
                }))
        .append(' ');
  }

  private UpdateThingy buildNotArmedMessage(StringBuilder sb) {
    String formText;
    if (updater.canUpdateNow()) {
      formText = appendCanUpdateNowText(sb);
    } else {
      formText = appendNotReadyText(sb);
    }

    if (updater.getNode().network().updateIsUrgent()) {
      sb.append(' ').append(l10n("updateIsUrgent"));
    }

    if (updater.brokenDependencies()) {
      sb.append(' ')
          .append(
              l10n("brokenDependencies", "version", Integer.toString(updater.newMainJarVersion())));
    }

    return new UpdateThingy(sb.toString(), formText);
  }

  private String appendCanUpdateNowText(StringBuilder sb) {
    if (updater.hasNewMainJar()) {
      sb.append(l10n("downloadedNewJar", "version", Integer.toString(updater.newMainJarVersion())))
          .append(' ');
    }
    if (updater.canUpdateImmediately()) {
      sb.append(l10n("clickToUpdateNow"));
      return l10n("updateNowButton");
    } else {
      sb.append(l10n("clickToUpdateASAP"));
      return l10n("updateASAPButton");
    }
  }

  private String appendNotReadyText(StringBuilder sb) {
    if (updater.fetchingFromUOM()) {
      sb.append(l10n("fetchingUOM", "updateScript", getUpdateScriptName()));
    } else if (updater.fetchingNewMainJar()) {
      sb.append(
          l10n(
              "fetchingNewNode",
              "versionNumber",
              Long.toString(updater.fetchingNewMainJarVersion())));
    }
    sb.append(' ').append(l10n("updateASAPQuestion"));
    return l10n("updateASAPButton");
  }

  private String getUpdateScriptName() {
    String name;
    if (File.separatorChar == '\\') {
      name = "update.cmd";
    } else {
      name = "update.sh";
    }
    File f = new File(updater.getNode().getNodeDir(), name);
    if (f.exists()) return f.toString();
    f = new File(new File(updater.getNode().getNodeDir(), "bin"), name);
    if (f.exists()) return f.toString();
    return name;
  }

  /**
   * Returns the alert priority used for ordering and emphasis.
   *
   * <p>The value maps to {@link network.crypta.node.useralerts.UserAlert} severity constants and
   * reflects urgency based on updater state. Urgent updates may be classified as critical to ensure
   * visibility.
   *
   * @return a priority constant such as {@code UserAlert.CRITICAL_ERROR}, {@code UserAlert.ERROR},
   *     or {@code UserAlert.MINOR}
   */
  @Override
  public short getPriorityClass() {
    Node node = updater.getNode();
    if (node.network().updateIsUrgent()) return UserAlert.CRITICAL_ERROR;
    if (updater.inFinalCheck() || updater.canUpdateNow() || !updater.isArmed())
      return UserAlert.ERROR;
    else return UserAlert.MINOR;
  }

  /**
   * Indicates whether this alert should currently be shown to the user.
   *
   * <p>The alert is considered valid when the updater is enabled and either an update is being
   * fetched, has been fetched, or a legacy UOM path is in progress. When invalid, callers may omit
   * the alert from UI listings.
   *
   * @return {@code true} when the alert has relevant content to display; {@code false} otherwise
   */
  @Override
  public boolean isValid() {
    return updater.isEnabled()
        && !updater.isBlown()
        && (updater.fetchingNewMainJar() || updater.hasNewMainJar() || updater.fetchingFromUOM());
  }

  /**
   * No-op setter for validity.
   *
   * <p>The validity of this alert is derived from the updater and cannot be forced externally. This
   * method is present to satisfy the superclass contract and is intentionally ignored.
   *
   * @param b requested validity flag; ignored
   */
  @Override
  public void isValid(boolean b) {
    // Ignore
  }
}
