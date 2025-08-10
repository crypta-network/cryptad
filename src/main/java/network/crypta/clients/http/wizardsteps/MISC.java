package network.crypta.clients.http.wizardsteps;

import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.config.Config;
import network.crypta.config.ConfigException;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.Logger;
import network.crypta.support.api.HTTPRequest;

/**
 * Allows the user to choose whether to enable auto-updating, and what official utility plugins to install.
 */
public class MISC implements Step {

	private final Config config;
	private final NodeClientCore core;

	public MISC(NodeClientCore core, Config config) {
		this.core = core;
		this.config = config;
	}

	@Override
	public void getStep(HTTPRequest request, PageHelper helper) {
		HTMLNode contentNode = helper.getPageContent(WizardL10n.l10n("stepMiscTitle"));
		HTMLNode form = helper.addFormChild(contentNode, ".", "miscForm");

		HTMLNode miscInfoboxContent = helper.getInfobox("infobox-normal", WizardL10n.l10n("autoUpdate"),
		        form, null, false);

		miscInfoboxContent.addChild("p", WizardL10n.l10n("autoUpdateLong"));
		miscInfoboxContent.addChild("p").addChild("input",
            new String[] { "type", "checked", "name", "value", "id" },
            new String[] { "radio", "on", "autodeploy", "true", "autodeployTrue" }
            ).addChild("label",
              new String[] { "for" },
              new String[] { "autodeployTrue" }, WizardL10n.l10n("autoUpdateAutodeploy"));
		miscInfoboxContent.addChild("p").addChild("input",
            new String[] { "type", "name", "value", "id" },
            new String[] { "radio", "autodeploy", "false", "autodeployFalse" }
            ).addChild("label",
              new String[] { "for" },
              new String[] { "autodeployFalse" }, WizardL10n.l10n("autoUpdateNoAutodeploy"));

		miscInfoboxContent = helper.getInfobox("infobox-normal", WizardL10n.l10n("plugins"),
		        form, null, false);

		miscInfoboxContent.addChild("p", WizardL10n.l10n("pluginsLong"));
		miscInfoboxContent.addChild("p").addChild("input",
            new String[] { "type", "checked", "name", "value", "id" },
            new String[] { "checkbox", "on", "upnp", "true", "upnpTrue" }
            ).addChild("label",
              new String[] { "for" },
              new String[] { "upnpTrue" }, WizardL10n.l10n("enableUPnP"));
		miscInfoboxContent.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "back", NodeL10n.getBase().getString("Toadlet.back")});
		miscInfoboxContent.addChild("input",
		        new String[] { "type", "name", "value" },
		        new String[] { "submit", "next", NodeL10n.getBase().getString("Toadlet.next")});
	}

	@Override
	public String postStep(HTTPRequest request) {
		setAutoUpdate(Boolean.parseBoolean(request.getPartAsStringFailsafe("autodeploy", 10)));
		setUPnP(request.isPartSet("upnp"));
		return FirstTimeWizardToadlet.WIZARD_STEP.OPENNET.name();
	}

	/**
	 * Sets whether auto-update should be enabled.
	 * @param enabled whether auto-update should be enabled.
	 */
	public void setAutoUpdate(boolean enabled) {
		try {
			config.get("node.updater").set("autoupdate", enabled);
		} catch (ConfigException e) {
			Logger.error(this, "Should not happen, please report!" + e, e);
		}
	}

	/**
	 * Enables or disables the UPnP plugin asynchronously. If the plugin's state would not change for the given
	 * argument, it does nothing.
	 * @param enableUPnP whether UPnP should be enabled.
	 */
	public void setUPnP(final boolean enableUPnP) {
		//If its state would not change, don't do anything.
		if(enableUPnP == core.getNode().getPluginManager().isPluginLoaded("plugins.UPnP.UPnP")) {
				return;
		}

		core.getNode().getExecutor().execute(new Runnable() {

			private final boolean enable = enableUPnP;

			@Override
			public void run() {
				if(enable) {
					core.getNode().getPluginManager().startPluginOfficial("UPnP", true);
				} else {
					core.getNode().getPluginManager().killPluginByClass("plugins.UPnP.UPnP", 5000);
				}
			}

		});
	}
}
