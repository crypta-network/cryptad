package network.crypta.clients.http.wizardsteps;

import java.io.IOException;
import network.crypta.clients.http.ExternalLinkToadlet;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.FileUtil.OperatingSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Wizard step that lets a user choose and apply the node's physical threat level.
 *
 * <p>This step renders the “physical security” page in the first-time setup wizard and processes
 * the corresponding form submission. The UI presents the available {@link
 * network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL physical threat levels}, and for the
 * “high” level it additionally collects and validates a master password. On POST, it may prompt
 * again for a password (for example when upgrading to high with an empty password, when the
 * confirmation does not match, or when downgrading from high requires decrypting existing master
 * keys).
 *
 * <p>Notable behaviors:
 *
 * <ul>
 *   <li>Re-renders a dedicated error/password prompt page when {@code error=} parameters are
 *       present and valid.
 *   <li>Performs password-file maintenance for the maximum level (master keys file removal) and
 *       persists configuration changes immediately.
 *   <li>Delegates presentation and localization to {@link PageHelper}, {@link WizardL10n}, and
 *       {@link NodeL10n}; this class focuses on control flow and state transitions.
 * </ul>
 *
 * <p>This type is a request-scoped handler: it is not designed for concurrent use across requests,
 * but it is safe when each request uses its own instance (the typical toadlet pattern).
 *
 * @see FirstTimeWizardToadlet.WIZARD_STEP#SECURITY_PHYSICAL
 * @see SecurityLevelsToadlet
 */
public class SecurityPhysical implements Step {
  private static final Logger LOG = LoggerFactory.getLogger(SecurityPhysical.class);
  private static final String PARAM_PHYSICAL_THREAT_LEVEL = "security-levels.physicalThreatLevel";
  private static final String TAG_INPUT = "input";
  private static final String TAG_LABEL = "label";
  private static final String ATTR_VALUE = "value";
  private static final String INPUT_TYPE_SUBMIT = "submit";
  private static final String PASSWORD_FOR_DECRYPT_TITLE_KEY = "passwordForDecryptTitle";

  private final NodeClientCore core;

  private enum PASSWORD_PROMPT {
    SET_BLANK, // Requested new password was blank
    DECRYPT_WRONG, // Decryption password was wrong
    DECRYPT_BLANK, // Decryption password was blank
    SET_NO_MATCH // The new password pair that was requested does not match.
  }

  /**
   * Creates a new wizard step handler backed by the provided node client core.
   *
   * <p>The step reads and mutates security-related node state via {@link NodeClientCore} and the
   * associated {@link Node}. The instance retains the reference for the lifetime of a single HTTP
   * request/response cycle; callers typically construct a new step instance per request.
   *
   * @param core core services used to read/write security levels and password state; must be
   *     non-null and already initialized.
   */
  public SecurityPhysical(NodeClientCore core) {
    this.core = core;
  }

  /**
   * Renders the physical security wizard page for a GET request.
   *
   * <p>If the request carries {@code error=} parameters, this method attempts to render a dedicated
   * error or password prompt page via {@link #errorHandler(HTTPRequest, PageHelper)}. Otherwise, it
   * renders the standard selection form, including the swap-file warning text and the available
   * {@link SecurityLevels.PHYSICAL_THREAT_LEVEL} radio options.
   *
   * <p>When the user selects the {@link SecurityLevels.PHYSICAL_THREAT_LEVEL#HIGH} option and the
   * node is not already at high physical security, the form includes password and confirmation
   * inputs for setting the master password.
   *
   * @param request HTTP request providing query parameters that influence rendering (for example
   *     {@code error}, {@code type}, and the requested threat level).
   * @param helper page construction helper responsible for creating the content and form nodes.
   */
  @Override
  public void getStep(HTTPRequest request, PageHelper helper) {

    if (request.isParameterSet("error") && errorHandler(request, helper)) {
      // Error page generated successfully.
      return;
    }

    HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("physicalSecurityPageTitle"));
    HTMLNode infoboxContent =
        helper.getInfobox(
            "infobox-normal",
            WizardL10n.l10nSec("physicalThreatLevelShort"),
            contentNode,
            null,
            false);
    infoboxContent.addChild("p", WizardL10n.l10nSec("physicalThreatLevel"));

    HTMLNode form = helper.addFormChild(infoboxContent, ".", "physicalSecurityForm");
    HTMLNode div = form.addChild("div", "class", "opennetDiv");
    String controlName = PARAM_PHYSICAL_THREAT_LEVEL;
    HTMLNode swapWarning = div.addChild("p").addChild("i");
    NodeL10n.getBase()
        .addL10nSubstitution(
            swapWarning,
            "SecurityLevels.physicalThreatLevelTruecrypt",
            new String[] {"bold", "truecrypt"},
            new HTMLNode[] {
              HTMLNode.STRONG,
              HTMLNode.linkInNewWindow(ExternalLinkToadlet.escape("http://www.truecrypt.org/"))
            });
    OperatingSystem os = FileUtil.detectedOS;
    div.addChild(
        "p",
        NodeL10n.getBase()
            .getString(
                "SecurityLevels.physicalThreatLevelSwapfile",
                "operatingSystem",
                NodeL10n.getBase().getString("OperatingSystemName." + os.name())));
    if (os == FileUtil.OperatingSystem.WINDOWS) {
      swapWarning.addChild("#", " " + WizardL10n.l10nSec("physicalThreatLevelSwapfileWindows"));
    }
    for (SecurityLevels.PHYSICAL_THREAT_LEVEL level :
        SecurityLevels.PHYSICAL_THREAT_LEVEL.values()) {
      HTMLNode input;
      input =
          div.addChild("p")
              .addChild(
                  TAG_INPUT,
                  new String[] {"type", "name", ATTR_VALUE, "id"},
                  new String[] {"radio", controlName, level.name(), controlName + level.name()});
      input
          .addChild(TAG_LABEL, new String[] {"for"}, new String[] {controlName + level.name()})
          .addChild("b", WizardL10n.l10nSec("physicalThreatLevel.name." + level));
      input.addChild("#", ": ");
      NodeL10n.getBase()
          .addL10nSubstitution(
              input,
              "SecurityLevels.physicalThreatLevel.choice." + level,
              new String[] {"bold"},
              new HTMLNode[] {HTMLNode.STRONG});
      if (level == SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH
          && core.getNode().getSecurityLevels().getPhysicalThreatLevel() != level) {
        // Add password form on high security if not already at high security.
        HTMLNode p = div.addChild("p");
        p.addChild(TAG_LABEL, "for", "passwordBox", WizardL10n.l10nSec("setPasswordLabel") + ":");
        p.addChild(
            TAG_INPUT,
            new String[] {"id", "type", "name"},
            new String[] {"passwordBox", "password", "masterPassword"});
        // Confirm password box
        p.addChild(
            TAG_LABEL,
            "for",
            "confirmPasswordBox",
            WizardL10n.l10nSec("confirmPasswordLabel") + ":");
        p.addChild(
            TAG_INPUT,
            new String[] {"id", "type", "name"},
            new String[] {"confirmPasswordBox", "password", "confirmMasterPassword"});
      }
    }
    div.addChild("#", WizardL10n.l10nSec("physicalThreatLevelEnd"));
    form.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "back", NodeL10n.getBase().getString("Toadlet.back")});
    form.addChild(
        TAG_INPUT,
        new String[] {"type", "name", ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "next", NodeL10n.getBase().getString("Toadlet.next")});
  }

  /**
   * Internal error handler wrapper with the hope of making the code more readable.
   *
   * @param request defines which error and information about it
   * @param helper creates page, infoboxes, forms.
   * @return whether an error page was successfully generated.
   */
  private boolean errorHandler(HTTPRequest request, PageHelper helper) {
    String physicalThreatLevel = request.getParam("newThreatLevel");
    SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel =
        SecurityLevels.parsePhysicalThreatLevel(physicalThreatLevel);
    String error = request.getParam("error");
    if (newThreatLevel == null && ("pass".equals(error) || "delete".equals(error))) {
      // Render the default page if the threat level is missing/invalid.
      return false;
    }

    switch (error) {
      case "pass" -> {
        // Password prompt requested
        PASSWORD_PROMPT type;
        try {
          type = PASSWORD_PROMPT.valueOf(request.getParam("type"));
        } catch (IllegalArgumentException e) {
          // Render the default page if unable to parse password prompt type.
          return false;
        }

        final String pageTitleKey;
        final String infoboxTitleKey;
        final boolean forDowngrade;
        final boolean forUpgrade;
        final boolean wasWrong = type == PASSWORD_PROMPT.DECRYPT_WRONG;

        switch (type) {
          case SET_BLANK, SET_NO_MATCH:
            pageTitleKey = "passwordPageTitle";
            infoboxTitleKey = "enterPasswordTitle";
            forDowngrade = false;
            forUpgrade = true;
            break;
          case DECRYPT_WRONG:
            pageTitleKey = PASSWORD_FOR_DECRYPT_TITLE_KEY;
            infoboxTitleKey = "passwordWrongTitle";
            forDowngrade = false;
            forUpgrade = false;
            break;
          case DECRYPT_BLANK:
            pageTitleKey = PASSWORD_FOR_DECRYPT_TITLE_KEY;
            infoboxTitleKey = PASSWORD_FOR_DECRYPT_TITLE_KEY;
            forDowngrade = true;
            forUpgrade = false;
            break;
          default:
            // Unanticipated value for type!
            return false;
        }

        HTMLNode contentNode = helper.getPageContent(WizardL10n.l10nSec(pageTitleKey));

        HTMLNode content =
            helper.getInfobox(
                "infobox-error", WizardL10n.l10nSec(infoboxTitleKey), contentNode, null, true);

        if (type == PASSWORD_PROMPT.SET_BLANK || type == PASSWORD_PROMPT.DECRYPT_BLANK) {
          content.addChild("p", WizardL10n.l10nSec("passwordNotZeroLength"));
        } else if (type == PASSWORD_PROMPT.SET_NO_MATCH) {
          content.addChild("p", WizardL10n.l10nSec("passwordsDoNotMatch"));
        }

        HTMLNode form = helper.addFormChild(content, ".", "masterPasswordForm");

        SecurityLevelsToadlet.generatePasswordFormPage(
            wasWrong, form, content, forDowngrade, forUpgrade, newThreatLevel.name(), null);

        addBackToPhysicalSeclevelsButton(form);
        return true;
      }
      case "corrupt" -> {
        // Password file corrupt
        SecurityLevelsToadlet.sendPasswordFileCorruptedPageInner(
            helper, core.getNode().getMasterPasswordFile().getPath());
        return true;
      }
      case "delete" -> {
        SecurityLevelsToadlet.sendCantDeleteMasterKeysFileInner(
            helper, core.getNode().getMasterPasswordFile().getPath(), newThreatLevel.name());
        return true;
      }
      default -> {
        // Error type was not recognized.
        return false;
      }
    }
  }

  /**
   * Returns the currently configured physical threat level for the node.
   *
   * <p>This is a convenience accessor used by wizard templates and other steps that need to reflect
   * the current state. The returned value is read from {@link SecurityLevels} at call time and
   * therefore reflects any changes applied earlier in the request.
   *
   * @return the node's current {@link SecurityLevels.PHYSICAL_THREAT_LEVEL}, never {@code null} in
   *     a correctly initialized node.
   */
  public SecurityLevels.PHYSICAL_THREAT_LEVEL getCurrentLevel() {
    return core.getNode().getSecurityLevels().getPhysicalThreatLevel();
  }

  /**
   * Handles a physical security wizard form submission (HTTP POST).
   *
   * <p>This method interprets the selected {@link SecurityLevels.PHYSICAL_THREAT_LEVEL} and, when
   * necessary, validates or prompts for the master password. Depending on the transition requested
   * by the user, it may:
   *
   * <ul>
   *   <li>prompt for a non-blank password or a matching confirmation when upgrading to high,
   *   <li>prompt for the existing password when downgrading from high (to decrypt master keys),
   *   <li>attempt to delete the master keys file when switching to maximum.
   * </ul>
   *
   * <p>On successful completion, the new threat level is persisted via {@link #setThreatLevel} and
   * the wizard advances to the next step.
   *
   * @param request HTTP request providing the submitted form fields, including the selected threat
   *     level and optional password entries.
   * @return the name of the next wizard step to render, or a redirect target used to show a
   *     password/error page for the current step.
   * @throws IOException if updating the master password fails in a way that should abort the
   *     submission and surface an error to the caller.
   */
  @Override
  public String postStep(HTTPRequest request) throws IOException {
    final String errorCorrupt =
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL + "&error=corrupt";
    String pass =
        request.getPartAsStringFailsafe(
            "masterPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH);
    String confirmPass =
        request.getPartAsStringFailsafe(
            "confirmMasterPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH);
    final boolean passwordIsBlank = pass.isEmpty() && confirmPass.isEmpty();
    final boolean passwordsDoNotMatch = !pass.equals(confirmPass);

    String physicalThreatLevel = request.getPartAsStringFailsafe(PARAM_PHYSICAL_THREAT_LEVEL, 128);
    SecurityLevels.PHYSICAL_THREAT_LEVEL oldThreatLevel =
        core.getNode().getSecurityLevels().getPhysicalThreatLevel();
    SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel =
        SecurityLevels.parsePhysicalThreatLevel(physicalThreatLevel);
    if (FirstTimeWizardToadlet.shouldLogMinor()) {
      LOG.debug("Old threat level: {} new threat level: {}", oldThreatLevel, newThreatLevel);
    }

    /* If the user did not select a physical security level before continuing, the selected level
     * cannot be determined. This also handles returning from a password prompt by redirecting back
     * to the main physical security selection page. */
    if (shouldReturnToPhysicalSecurity(request, newThreatLevel)) {
      return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name();
    }

    String redirect =
        handleUpgradeToHigh(
            oldThreatLevel,
            newThreatLevel,
            passwordIsBlank,
            passwordsDoNotMatch,
            pass,
            errorCorrupt);
    if (redirect != null) {
      return redirect;
    }

    redirect =
        handleDowngradeFromHigh(
            oldThreatLevel, newThreatLevel, passwordIsBlank, pass, errorCorrupt);
    if (redirect != null) {
      return redirect;
    }

    redirect = handleMaximumThreatLevel(newThreatLevel);
    if (redirect != null) {
      return redirect;
    }

    setThreatLevel(newThreatLevel);
    return FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name();
  }

  private static boolean shouldReturnToPhysicalSecurity(
      HTTPRequest request, SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel) {
    return newThreatLevel == null
        || !request.isPartSet(PARAM_PHYSICAL_THREAT_LEVEL)
        || request.isPartSet("backToMain");
  }

  private String handleUpgradeToHigh(
      SecurityLevels.PHYSICAL_THREAT_LEVEL oldThreatLevel,
      SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel,
      boolean passwordIsBlank,
      boolean passwordsDoNotMatch,
      String pass,
      String errorCorrupt)
      throws IOException {
    if (newThreatLevel != SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH
        || oldThreatLevel == newThreatLevel) {
      return null;
    }
    if (passwordIsBlank) {
      // Must set the password to something non-blank.
      return promptPassword(newThreatLevel, PASSWORD_PROMPT.SET_BLANK);
    }
    if (passwordsDoNotMatch) {
      // Must Confirm the password before setting it
      return promptPassword(newThreatLevel, PASSWORD_PROMPT.SET_NO_MATCH);
    }
    try {
      if (oldThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL
          || oldThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.LOW) {
        core.getNode().changeMasterPassword("", pass, true);
      } else {
        core.getNode().setMasterPassword(pass, true);
      }
    } catch (Node.AlreadySetPasswordException e) {
      // Do nothing, already set a password.
    } catch (MasterKeysWrongPasswordException e) {
      throw new IOException("Incorrect password when changing from another level to high", e);
    } catch (MasterKeysFileSizeException e) {
      return errorCorrupt;
    }
    return null;
  }

  private String handleDowngradeFromHigh(
      SecurityLevels.PHYSICAL_THREAT_LEVEL oldThreatLevel,
      SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel,
      boolean passwordIsBlank,
      String pass,
      String errorCorrupt)
      throws IOException {
    boolean isLowOrNormal =
        newThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.LOW
            || newThreatLevel == SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL;
    if (!isLowOrNormal || oldThreatLevel != SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH) {
      return null;
    }
    if (passwordIsBlank) {
      // Prompt for the old password, which is needed to decrypt
      return promptPassword(newThreatLevel, PASSWORD_PROMPT.DECRYPT_BLANK);
    }
    if (!core.getNode().getMasterPasswordFile().exists()) {
      return null;
    }
    try {
      core.getNode().changeMasterPassword(pass, "", true);
    } catch (IOException e) {
      if (!core.getNode().getMasterPasswordFile().exists()) {
        // Ok.
        LOG.info("Master password file no longer exists, assuming this is deliberate");
      } else {
        LOG.error("Cannot change password as cannot write new passwords file", e);
        throw new IOException("cantWriteNewMasterKeysFile", e);
      }
    } catch (MasterKeysWrongPasswordException e) {
      return promptPassword(newThreatLevel, PASSWORD_PROMPT.DECRYPT_WRONG);
    } catch (MasterKeysFileSizeException e) {
      return errorCorrupt;
    } catch (Node.AlreadySetPasswordException e) {
      LOG.warn(
          "Already set a password when changing it - maybe master.keys copied in at the wrong"
              + " moment???",
          e);
    }
    return null;
  }

  private String handleMaximumThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel) {
    if (newThreatLevel != SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM) {
      return null;
    }
    try {
      core.getNode().killMasterKeysFile();
    } catch (IOException e) {
      return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
          + "&error=delete&newThreatLevel="
          + newThreatLevel.name();
    }
    return null;
  }

  /**
   * Internal utility function for displaying a password prompt.
   *
   * @param newThreatLevel the user-selected threat level, to be used in creating the form.
   * @param type what type of prompt needed
   * @return URL to display the requested page
   */
  private String promptPassword(
      SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel, PASSWORD_PROMPT type) {
    if (type == PASSWORD_PROMPT.DECRYPT_WRONG) {
      LOG.warn("Master password verification failed; prompting for password again");
    }
    return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
        + "&error=pass&newThreatLevel="
        + newThreatLevel.name()
        + "&type="
        + type.name();
  }

  /**
   * Applies the selected physical threat level and persists the change.
   *
   * <p>This method updates {@link SecurityLevels} in-memory, stores the configuration to disk via
   * {@link NodeClientCore#storeConfig()}, and triggers late database setup on the node. Callers are
   * expected to have already validated that {@code newThreatLevel} is a supported choice and, when
   * moving to or from {@link SecurityLevels.PHYSICAL_THREAT_LEVEL#HIGH}, to have handled any master
   * password requirements.
   *
   * @param newThreatLevel the threat level to set on the node; must be non-null and represent a
   *     valid {@link SecurityLevels.PHYSICAL_THREAT_LEVEL} constant.
   */
  public void setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel) {
    core.getNode().getSecurityLevels().setThreatLevel(newThreatLevel);
    core.storeConfig();
    core.getNode().lateSetupDatabase(null);
  }

  private void addBackToPhysicalSeclevelsButton(HTMLNode form) {
    form.addChild("p")
        .addChild(
            TAG_INPUT,
            new String[] {"type", "name", ATTR_VALUE},
            new String[] {
              INPUT_TYPE_SUBMIT, "backToMain", WizardL10n.l10n("backToSecurityLevels")
            });
  }
}
