package network.crypta.clients.http.ajaxpush;

import java.io.IOException;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.UpdaterConstants;
import network.crypta.support.Logger;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.api.HTTPRequest;

/** This toadlet is used to let the client write to the logs */
public class LogWritebackToadlet extends Toadlet {

  private static volatile boolean logMINOR;

  static {
    Logger.registerClass(LogWritebackToadlet.class);
  }

  public LogWritebackToadlet(HighLevelSimpleClient client) {
    super(client);
  }

  public void handleMethodGET(URI uri, HTTPRequest req, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    if (logMINOR) {
      try {
        Logger.minor(this, "GWT:" + URLDecoder.decode(req.getParam("msg"), false));
      } catch (URLEncodedFormatException e) {
        Logger.error(this, "Invalid GWT:" + req.getParam("msg"));
      }
    }
    writeHTMLReply(ctx, 200, "OK", UpdaterConstants.SUCCESS);
  }

  @Override
  public String path() {
    return UpdaterConstants.logWritebackPath;
  }
}
