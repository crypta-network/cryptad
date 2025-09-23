package network.crypta.pluginmanager;

import java.io.Serial;

/**
 * 302 error code.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class RedirectPluginHTTPException extends PluginHTTPException {
  @Serial private static final long serialVersionUID = -1;

  public static final short code = 302; // Found
  public final String newLocation;

  /**
   * Creates a new redirect exception.
   *
   * @param message The message to put in the reply
   * @param newLocation The location to redirect to
   */
  public RedirectPluginHTTPException(String message, String newLocation) {
    super(message, null);
    this.newLocation = newLocation;
  }

  /**
   * Creates a new redirect exception.
   *
   * @param message The message to put in the reply
   * @param location unsued
   * @param newLocation The location to redirect to
   * @deprecated use {@link #RedirectPluginHTTPException(String, String)} instead
   */
  @Deprecated
  public RedirectPluginHTTPException(String message, String location, String newLocation) {
    super(message, location);
    this.newLocation = newLocation;
  }
}
