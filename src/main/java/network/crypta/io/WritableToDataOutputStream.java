package network.crypta.io;

import java.io.DataOutputStream;
import java.io.IOException;

/**
 * @author ian
 *     <p>To change the template for this generated type comment go to Window - Preferences - Java -
 *     Code Generation - Code and Comments
 */
public interface WritableToDataOutputStream {

  String VERSION = "$Id: WritableToDataOutputStream.java,v 1.1 2005/01/29 19:12:10 amphibian Exp $";

  void writeToDataOutputStream(DataOutputStream stream) throws IOException;
}
