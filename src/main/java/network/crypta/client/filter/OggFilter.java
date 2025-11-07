package network.crypta.client.filter;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.io.CountedOutputStream;

/**
 * Filters Ogg container files. These containers contain one or more logical bitstreams of data
 * encapsulated into a physical bitstream. The data is broken into variable length pages, consisting
 * of a header and 0-255 segments of 0-255 bytes. For more details refer to <a
 * href="http://www.xiph.org/ogg/doc/rfc3533.txt">http://www.xiph.org/ogg/doc/rfc3533.txt</a>
 *
 * @author sajack
 */
public class OggFilter implements ContentDataFilter {

  public void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException {
    HashMap<Integer, OggBitstreamFilter> streamFilters = new HashMap<>();
    LinkedList<OggPage> splitPages = new LinkedList<>();
    CountedOutputStream out = new CountedOutputStream(output);
    DataInputStream in = new DataInputStream(new BufferedInputStream(input, 255));

    OggPage nextPage = OggPage.readPage(in);
    boolean running = true;
    while (running) {
      OggPage page = nextPage;
      nextPage = readNextPageOrNull(in);
      if (nextPage == null) running = false;

      OggBitstreamFilter filter = getOrCreateFilter(streamFilters, page);
      if (filter == null) continue;

      page = filter.parse(page);
      handlePage(page, nextPage, splitPages, out);
    }
    out.flush();
    if (out.written() == 0) {
      throw new DataFilterException(
          l10n("EmptyOutputTitle"), l10n("EmptyOutputTitle"), l10n("EmptyOutputDescription"));
    }
  }

  private static OggPage readNextPageOrNull(DataInputStream in) throws IOException {
    try {
      return OggPage.readPage(in);
    } catch (EOFException e) {
      return null;
    }
  }

  private OggBitstreamFilter getOrCreateFilter(
      Map<Integer, OggBitstreamFilter> streamFilters, OggPage page) {
    Integer serial = page.getSerial();
    if (streamFilters.containsKey(serial)) {
      return streamFilters.get(serial);
    }
    OggBitstreamFilter filter = OggBitstreamFilter.getBitstreamFilter(page);
    // Preserve behavior: store even when null to avoid re-resolving later
    streamFilters.put(serial, filter);
    return filter;
  }

  private void handlePage(
      OggPage page, OggPage nextPage, LinkedList<OggPage> splitPages, CountedOutputStream out)
      throws IOException {
    if (isWritablePage(page, nextPage)) {
      splitPages.add(page);
      if (isEndOfPacket(nextPage)) {
        writeAllSplitPages(splitPages, out);
      }
    } else if (!splitPages.isEmpty()) {
      splitPages.clear();
    }
  }

  private static boolean isEndOfPacket(OggPage nextPage) {
    return nextPage == null || !nextPage.isPacketContinued();
  }

  private void writeAllSplitPages(LinkedList<OggPage> splitPages, CountedOutputStream out)
      throws IOException {
    while (!splitPages.isEmpty()) {
      OggPage part = splitPages.remove();
      out.write(part.toArray());
    }
  }

  private boolean isWritablePage(OggPage page, OggPage nextPage) throws IOException {
    return page != null && page.headerValid() && !hasValidSubpage(page, nextPage);
  }

  /**
   * Searches for valid pages hidden inside this page
   *
   * @return whether or not a hidden page exists
   * @throws IOException
   */
  private boolean hasValidSubpage(OggPage page, OggPage nextPage) throws IOException {
    OggPage subpage;
    int pageCount = 0;
    try (ByteArrayOutputStream data = new ByteArrayOutputStream()) {
      // Populate a byte array with all the data in which a subpage might hide
      data.write(page.toArray());
      if (nextPage != null) data.write(nextPage.toArray());
      try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(data.toByteArray()))) {
        while (in.available() > 0) {
          OggPage.seekToPage(in);
          in.mark(65307);
          subpage = new OggPage(in);
          if (subpage.headerValid()) {
            pageCount++;
          }
          in.reset();
          long skipped = in.skip(1L); // Break the lock on the current page
          if (skipped <= 0) break;
        }
      } catch (EOFException e) {
        // We've ran out of data to read. Break.
      }
    }
    return (pageCount > 2 || hasValidSubpage(page));
  }

  private boolean hasValidSubpage(OggPage page) throws IOException {
    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(page.toArray()))) {
      long skipped = in.skip(1L); // Break alignment with the first page
      if (skipped <= 0) return false;
      while (in.available() > 0) {
        OggPage subpage = OggPage.readPage(in);
        if (subpage.headerValid()) return true;
      }
    } catch (EOFException e) {
      // We've ran out of data to read. Break.
    }
    return false;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("OggFilter." + key);
  }
}
