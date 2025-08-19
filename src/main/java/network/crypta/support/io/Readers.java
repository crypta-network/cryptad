package network.crypta.support.io;

import java.io.BufferedReader;
import java.io.IOException;

/** * Utility class for all sorts of Readers. */
public final class Readers {

  private Readers() {}

  /**
   * * A {@link LineReader} <a href="http://en.wikipedia.org/wiki/Adapter_pattern">Adapter</a> * for
   * {@link BufferedReader}.
   */
  public static LineReader fromBufferedReader(final BufferedReader br) {
    return new LineReader() {
      @Override
      public String readLine(int maxLength, int bufferSize, boolean utf) throws IOException {
        return br.readLine();
      }
    };
  }

  /**
   * A {@link LineReader} <a href="http://en.wikipedia.org/wiki/Adapter_pattern">Adapter</a> for
   * {@link String} array.
   */
  public static LineReader fromStringArray(final String[] lines) {
    return new LineReader() {
      private int currentLine = -1;

      @Override
      public String readLine(int maxLength, int bufferSize, boolean utf) throws IOException {
        if (++currentLine < lines.length) {
          return lines[currentLine];
        }
        return null;
      }
    };
  }
}
