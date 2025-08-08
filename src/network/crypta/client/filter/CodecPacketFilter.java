package network.crypta.client.filter;

import java.io.IOException;

/**Base class for specific logical bitstream filters. Subclasses should create
 * a method overriding <code>parse</code> which includes a call to the original
 * method.
 * @author sajack
 */
public interface CodecPacketFilter {

	/**Does minimal validation of a codec packet.
	 * @param packet A packet from the coded stream
	 * @return Whether packet was properly validated
	 * @throws IOException
	 */
    CodecPacket parse(CodecPacket packet) throws IOException;

}
