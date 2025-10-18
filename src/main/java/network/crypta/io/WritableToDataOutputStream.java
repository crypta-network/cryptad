package network.crypta.io;

import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Contract for types that can write their serialized form to a {@link DataOutputStream}.
 *
 * <p>Implementations write their binary representation to the provided stream. This interface does
 * not prescribe a specific on-wire format; consult the implementing class for details about layout,
 * versioning, and compatibility. Unless otherwise documented by an implementation, instances are
 * not assumed to be thread-safe.
 */
public interface WritableToDataOutputStream {

  /**
   * Legacy source-control revision identifier retained for diagnostics and historical context. The
   * value is not normative and may not reflect the current project versioning scheme.
   */
  String VERSION = "$Id: WritableToDataOutputStream.java,v 1.1 2005/01/29 19:12:10 amphibian Exp $";

  /**
   * Writes this object's serialized representation to the given {@link DataOutputStream}.
   *
   * <p>Implementations write zero or more bytes to the stream. Unless explicitly documented
   * otherwise by the implementation, this method does not close the provided stream.
   *
   * @param stream destination that receives the binary representation; must be non-null and open
   * @throws IOException if an I/O error occurs while writing to the stream
   */
  void writeToDataOutputStream(DataOutputStream stream) throws IOException;
}
