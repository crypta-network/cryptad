package network.crypta.support.plugins.helpers1;

import java.io.IOException;
import java.net.URI;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.support.api.HTTPRequest;

public class InvisibleWebInterfaceToadlet extends WebInterfaceToadlet {

  private final Toadlet _showAsToadlet;

  protected InvisibleWebInterfaceToadlet(
      PluginContext pluginContext2, String pluginURL2, String pageName2, Toadlet showAsToadlet) {
    super(pluginContext2, pluginURL2, pageName2);
    _showAsToadlet = showAsToadlet;
  }

  @Override
  public Toadlet showAsToadlet() {
    return _showAsToadlet;
  }

  @Override
  /** Override this! */
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    this.sendErrorPage(ctx, 500, "Internal Server Error", "Not implemented");
  }
}
