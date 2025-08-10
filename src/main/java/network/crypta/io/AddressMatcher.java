package network.crypta.io;

import java.net.InetAddress;

/**
 * @author David Roden &lt;droden@gmail.com&gt;
 * @version $Id$
 */
public interface AddressMatcher {
	boolean matches(InetAddress address);

	/** Get the human-readable version of the Matcher */
    String getHumanRepresentation();

}
