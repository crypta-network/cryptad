package network.crypta.client.filter;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.io.CountedOutputStream;

/**
 * Filters Ogg container files by validating page structure and forwarding acceptable data.
 *
 * <p>The Ogg container multiplexes one or more logical bitstreams (such as Vorbis, Theora, or FLAC)
 * into a single physical bitstream composed of pages. Each page carries a small header and a
 * sequence of lacing values that split the payload into segments. This filter reads the stream
 * page-by-page, performs inexpensive structural checks to guard against malformed content, and
 * copies valid pages to the destination stream. Pages that contain embedded, valid “subpages”
 * (which typically indicate an attempt to smuggle a nested stream) are treated conservatively and
 * are not forwarded.
 *
 * <p>Use this filter when relaying user-supplied Ogg files or when a basic integrity pass is
 * desired before passing data to downstream decoders. The implementation is streaming (does not
 * buffer entire files), holds no shared mutable state, and is safe for reuse across independent
 * invocations as long as a fresh input/output stream pair is provided each time. It does not parse
 * or decode individual codec packets; instead, it focuses on container framing validity and on
 * avoiding mixed or nested page sequences that could confuse consumers.
 *
 * <ul>
 *   <li>Responsibilities: validate Ogg page framing; reject pages that hide nested pages; copy
 *       acceptable bytes verbatim.
 *   <li>Concurrency: instances are stateless and effectively thread-safe; no shared state.
 *   <li>Error handling: malformed input results in a {@link DataFilterException}; I/O failures are
 *       surfaced as {@link IOException}.
 * </ul>
 *
 * <p>Reference: <a href="https://www.xiph.org/ogg/doc/rfc3533.txt">RFC 3533 – The Ogg Encapsulation
 * Format</a>.
 *
 * @see ContentDataFilter
 * @see OggPage
 * @see OggBitstreamFilter
 * @author sajack
 */
public class OggFilter implements ContentDataFilter {

  /**
   * Creates a new Ogg filter instance.
   *
   * <p>Instances are stateless and can be reused across multiple calls as long as a new input and
   * output stream is provided per invocation of {@link #readFilter(InputStream, OutputStream,
   * String, Map, String, FilterCallback)}. No additional initialization is required.
   */
  public OggFilter() {
    // Intentionally empty: the filter is stateless and requires no initialization.
  }

  /**
   * Run the Ogg read filter, validating page structure and forwarding acceptable pages.
   *
   * <p>This is the integration point required by {@link ContentDataFilter}. The method reads the
   * input as an Ogg physical bitstream, aggregates packet splits across consecutive pages, and
   * writes pages that pass structural checks to {@code output}. If no output is produced, a
   * localized {@link DataFilterException} is raised to signal rejection. The character set and
   * auxiliary parameters are accepted for interface compatibility but are not used by this binary
   * container filter.
   *
   * <pre>{@code
   * // Example: stream an Ogg file through the filter
   * var filter = new OggFilter();
   * filter.readFilter(in, out, null, Map.of(), host, callback);
   * }</pre>
   *
   * @param input the source of Ogg bytes; must remain readable for the duration of filtering; not
   *     closed by this method.
   * @param output the destination receiving validated pages written verbatim; flushed on success;
   *     not closed by this method.
   * @param charset unused for Ogg content; callers may pass {@code null} or an empty string safely;
   *     retained for API compatibility.
   * @param otherParams additional parameters supplied by higher layers; ignored by this filter but
   *     accepted for interface compatibility; may be {@code null}.
   * @param schemeHostAndPort request authority ({@code scheme://host:port}) supplied by callers;
   *     not used by this filter and may be {@code null}.
   * @param cb callback for link discovery or tag replacement in text formats; not used here but
   *     carried for interface consistency; may be {@code null}.
   * @throws IOException if reading from {@code input} or writing to {@code output} fails; includes
   *     validation failures signaled via {@link DataFilterException}.
   */
  @Override
  public void readFilter(
      InputStream input,
      OutputStream output,
      String charset,
      Map<String, String> otherParams,
      String schemeHostAndPort,
      FilterCallback cb)
      throws IOException {
    HashMap<Integer, OggBitstreamFilter> streamFilters = new HashMap<>();
    Deque<OggPage> splitPages = new ArrayDeque<>();
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
    } catch (EOFException _) {
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
      OggPage page, OggPage nextPage, Deque<OggPage> splitPages, CountedOutputStream out)
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

  private void writeAllSplitPages(Deque<OggPage> splitPages, CountedOutputStream out)
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
   * Searches for valid pages hidden inside this page.
   *
   * @param page the current page whose payload will be scanned for embedded subpages
   * @param nextPage the following page, used to extend the scan window across a packet boundary;
   *     may be {@code null}
   * @return {@code true} if a valid hidden subpage is detected; {@code false} otherwise
   * @throws IOException if an I/O error occurs while reading or parsing candidate subpages
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
      } catch (EOFException _) {
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
    } catch (EOFException _) {
      // We've ran out of data to read. Break.
    }
    return false;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("OggFilter." + key);
  }
}
