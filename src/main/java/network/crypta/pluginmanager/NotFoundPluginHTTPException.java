package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * 404 error code.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class NotFoundPluginHTTPException extends PluginHTTPException {
  @Serial private static final long serialVersionUID = -1;

  public static final short code = 404; // Not Found

  public NotFoundPluginHTTPException(String errorMessage, String location) {
    super(errorMessage, location);
  }
}
