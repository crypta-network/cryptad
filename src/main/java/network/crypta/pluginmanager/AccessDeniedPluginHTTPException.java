package network.crypta.pluginmanager;

/**
 * 403 error code.
 * 
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 */
public class AccessDeniedPluginHTTPException extends PluginHTTPException {
	private static final long serialVersionUID = -1;
	
	public static final short code = 403; // Access Denied

	public AccessDeniedPluginHTTPException(String errorMessage, String location) {
		super(errorMessage, location);
	}
}
