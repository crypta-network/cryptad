package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;

/**
 * This step allows the user to choose between darknet and opennet, explaining each briefly.
 */
public class OPENNET implements Step {

    @Override
    public void getStep(HTTPRequest request, PageHelper helper) {
        HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("opennetChoicePageTitle"));
        HTMLNode infoboxContent =
            helper.getInfobox("infobox-normal", WizardL10n.l10n("opennetChoiceTitle"), contentNode, null,
                              false);

        infoboxContent.addChild("p", WizardL10n.l10n("opennetChoiceIntroduction"));

        HTMLNode form = helper.addFormChild(infoboxContent, ".", "opennetForm", false);

        HTMLNode p = form.addChild("p");
        HTMLNode input = p.addChild("input", new String[]{"type", "name", "value", "id"},
                                    new String[]{"radio", "opennet", "false", "opennetFalse"});
        input.addChild("label", new String[]{"for"}, new String[]{"opennetFalse"})
             .addChild("b", WizardL10n.l10n("opennetChoiceConnectFriends") + ":");
        p.addChild("br");
        p.addChild("i", WizardL10n.l10n("opennetChoicePro"));
        p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectFriendsPRO") + "¹");
        p.addChild("br");
        p.addChild("i", WizardL10n.l10n("opennetChoiceCon"));
        p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectFriendsCON", "minfriends", "5"));

        p = form.addChild("p");
        input = p.addChild("input", new String[]{"type", "name", "value", "id"},
                           new String[]{"radio", "opennet", "true", "opennetTrue"});
        input.addChild("label", new String[]{"for"}, new String[]{"opennetTrue"})
             .addChild("b", WizardL10n.l10n("opennetChoiceConnectStrangers") + ":");
        p.addChild("br");
        p.addChild("i", WizardL10n.l10n("opennetChoicePro"));
        p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectStrangersPRO"));
        p.addChild("br");
        p.addChild("i", WizardL10n.l10n("opennetChoiceCon"));
        p.addChild("#", ": " + WizardL10n.l10n("opennetChoiceConnectStrangersCON"));

        form.addChild("input", new String[]{"type", "name", "value"},
                      new String[]{"submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
        form.addChild("input", new String[]{"type", "name", "value"},
                      new String[]{"submit", "next", NodeL10n.getBase().getString("Toadlet.next")});

        HTMLNode foot = infoboxContent.addChild("div", "class", "toggleable");
        foot.addChild("i", "¹: " + WizardL10n.l10n("opennetChoiceHowSafeIsCryptaToggle"));
        HTMLNode footHidden = foot.addChild("div", "class", "hidden");
        HTMLNode footList = footHidden.addChild("ol");
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaStupid"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaFriends") + "²");
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaTrustworthy"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaNoSuspect"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaChangeID"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaSSK"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaOS"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaBigPriv"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaDistant"));
        footList.addChild("li", WizardL10n.l10n("opennetChoiceHowSafeIsCryptaBugs"));
        HTMLNode foot2 = footHidden.addChild("p");
        foot2.addChild("#", "²: " + WizardL10n.l10n("opennetChoiceHowSafeIsCryptaFoot2"));
    }

    /**
     * Doesn't make any changes, just passes result on to SECURITY_NETWORK.
     *
     * @param request Checked for "opennet" value.
     */
    @Override
    public String postStep(HTTPRequest request) {
        if (request.isPartSet("opennet")) {
            return FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_NETWORK + "&opennet=" +
                   request.getPartAsStringFailsafe("opennet", 5);
        } else {
            //Nothing selected when "next" clicked. Display choice again.
            return FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name();
        }
    }
}
