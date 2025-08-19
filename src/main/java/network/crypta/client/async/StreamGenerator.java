package network.crypta.client.async;

import java.io.IOException;
import java.io.OutputStream;

/** Writes an underlying data structure to an output stream. */
public interface StreamGenerator {

  /**
   * Writes the data.
   *
   * @param os Stream to which the data will be written
   * @param context
   * @throws IOException
   */
  void writeTo(OutputStream os, ClientContext context) throws IOException;

  /**
   * @return The size of the underlying structure
   */
  long size();
}
