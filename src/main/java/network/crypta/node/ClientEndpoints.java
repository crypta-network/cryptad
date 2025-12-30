package network.crypta.node;

import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.io.TempBucketFactory;

/** Bundles client-facing endpoints (FCP, TMCI, and HTTP toadlet container) and their lifecycle. */
public final class ClientEndpoints {
  private final FCPServer fcpServer;
  private final TextModeClientInterfaceServer tmci;
  private final SimpleToadletServer toadletContainer;
  private volatile TextModeClientInterface directTMCI;
  private volatile FProxyToadlet fproxy;
  private UserAlert startingUpAlert;

  public ClientEndpoints(
      FCPServer fcpServer,
      TextModeClientInterfaceServer tmci,
      SimpleToadletServer toadletContainer) {
    this.fcpServer = fcpServer;
    this.tmci = tmci;
    this.toadletContainer = toadletContainer;
  }

  public FCPServer getFCPServer() {
    return fcpServer;
  }

  public FProxyToadlet getFProxy() {
    return fproxy;
  }

  public void setFProxy(FProxyToadlet fproxy) {
    this.fproxy = fproxy;
  }

  public SimpleToadletServer getToadletContainer() {
    return toadletContainer;
  }

  public TextModeClientInterfaceServer getTextModeClientInterface() {
    return tmci;
  }

  public TextModeClientInterface getDirectTMCI() {
    return directTMCI;
  }

  public void setDirectTMCI(TextModeClientInterface tmci) {
    this.directTMCI = tmci;
  }

  public void loadPersistentRequestsIfNeeded() {
    fcpServer.load();
  }

  public void maybeStart() {
    fcpServer.maybeStart();
    if (tmci != null) {
      tmci.start();
    }
  }

  public void configureBucketFactory(TempBucketFactory tempBucketFactory) {
    toadletContainer.setBucketFactory(tempBucketFactory);
  }

  public void registerStartupAlerts(
      UserAlertManager alerts,
      NodeClientCore core,
      String title,
      String longText,
      String shortText) {
    UserAlert alert = NodeClientCoreSupport.createStartingUpAlert(title, longText, shortText);
    NodeClientCoreSupport.registerFProxyAlerts(alerts, core, alert);
    startingUpAlert = alert;
  }

  public void unregisterStartupAlert(UserAlertManager alerts) {
    if (startingUpAlert != null) {
      alerts.unregister(startingUpAlert);
    }
  }

  public boolean isAdvancedModeEnabled() {
    return toadletContainer.isAdvancedModeEnabled();
  }

  public boolean isFProxyJavascriptEnabled() {
    return toadletContainer.isFProxyJavascriptEnabled();
  }

  public static ClientEndpoints create(
      Node node,
      NodeClientCore core,
      NodeClientCoreInit init,
      NodeClientPersistence persistence,
      ClientContext clientContext) {
    TextModeClientInterfaceServer tmci =
        TextModeClientInterfaceServer.maybeCreate(node, core, init.getConfig());
    FCPServer fcpServer = persistence.createFcpServer(node, core);
    clientContext.setDownloadCache(fcpServer);
    if (!core.killedDatabase()) {
      fcpServer.load();
    }
    return new ClientEndpoints(fcpServer, tmci, init.getToadlets());
  }
}
