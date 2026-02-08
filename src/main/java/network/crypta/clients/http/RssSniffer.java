package network.crypta.clients.http;

/**
 * Utility helpers for detecting RSS or Atom XML roots in incoming HTTP payload prefixes.
 *
 * <p>This class provides a lightweight, allocation-free scan that looks only at the initial bytes
 * of an entity body to decide whether a browser is likely to sniff the content as a feed. It is
 * intended for callers that already possess a small prefix (typically a few kilobytes read for MIME
 * sniffing) and need to force a download instead of inline rendering when a feed is detected. The
 * logic recognizes top-level {@code <rss}, {@code <feed}, and {@code <rdf:RDF} tags even when they
 * are preceded by XML declarations or comments. Callers should not pass unbounded streams; the
 * input is treated as immutable, and no additional I/O occurs during detection.
 *
 * <p>The class is stateless and thread-safe. All methods are static and throw no checked
 * exceptions, making it safe to invoke from network pipelines or pre-processing filters where
 * defensive checks are desired, but latency and memory overhead must remain minimal.
 *
 * <ul>
 *   <li>Responsibilities: detect browser feed sniffing cues in raw byte prefixes.
 *   <li>Notable behavior: ignores XML comments and processing instructions before root tags.
 *   <li>Thread safety: fully immutable utility with no shared state.
 * </ul>
 */
public class RssSniffer {

  private RssSniffer() {}

  /**
   * Look for any of the following strings as top-level XML tags: &lt;rss &lt;feed &lt;rdf:RDF
   *
   * <p>If they start at the beginning of the file or are preceded by one or more &lt;! or &lt;?
   * tags, then firefox will read it as RSS. In which case we must force it to be downloaded to
   * disk.
   *
   * <p>The scan is limited to the supplied prefix and does not read additional bytes. It tolerates
   * XML declarations and comments before the root element but otherwise requires the tag to be the
   * first top-level element. The method performs a simple byte comparison without charset decoding
   * and is therefore insensitive to XML prolog encoding hints.
   *
   * @param prefix initial bytes from the HTTP entity body; may be truncated
   * @return true when a recognized feed root tag appears as the first top-level tag
   */
  public static boolean isSniffedAsFeed(byte[] prefix) {
    int tlt = indexOfTopLevelTag(prefix);
    if (tlt == -1) {
      return false;
    }
    return startsWithString(prefix, "<rss", tlt)
        || startsWithString(prefix, "<feed", tlt)
        || startsWithString(prefix, "<rdf:RDF", tlt);
  }

  /**
   * Finds the smallest index of a top-level XML tag in the data. A tag is any sequence that starts
   * with '<'. A top-level tag is any subsequence that is not a comment, processing instruction or
   * doctype (e.g. "<?" or "<!") and is not embedded in such a tag. Returns -1 if no such tag exists
   * in the data.
   */
  private static int indexOfTopLevelTag(byte[] data) {
    int i = 0;
    // Scan over all tags in the data.
    while ((i = indexOf(data, (byte) '<', i)) != -1) {
      i++;
      if (i >= data.length) {
        return -1;
      }
      if (data[i] != (byte) '?' && data[i] != (byte) '!') {
        // Found a top-level tag.
        return i - 1;
      }
      // Found a comment, processing instruction or doctype; proceed to the end of the tag.
      i = indexOf(data, (byte) '>', i);
      if (i == -1) {
        // No end of tag in the buffer: we won't find a top-level tag.
        return -1;
      }
    }
    return -1;
  }

  /**
   * Checks whether the given data starts with the characters in the key value when starting at
   * fromIndex in the data array.
   */
  private static boolean startsWithString(byte[] data, String key, int fromIndex) {
    if (data.length - fromIndex < key.length()) {
      return false;
    }
    for (int i = 0; i < key.length(); i++) {
      if (data[i + fromIndex] != key.charAt(i)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Returns the smallest index of the key in the data array not smaller than fromIndex, or -1 if no
   * such index exists.
   */
  private static int indexOf(byte[] data, byte key, int fromIndex) {
    for (int i = fromIndex; i < data.length; i++) {
      if (data[i] == key) {
        return i;
      }
    }
    return -1;
  }
}
