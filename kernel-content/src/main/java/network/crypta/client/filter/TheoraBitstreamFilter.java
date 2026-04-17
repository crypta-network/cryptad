package network.crypta.client.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters and normalizes Theora packets carried inside Ogg pages.
 *
 * <p>This filter wraps an {@link OggBitstreamFilter} and uses a {@link TheoraPacketFilter} to
 * inspect each packet on an input {@link OggPage}. Packets that parse successfully are preserved,
 * while packets that cannot be parsed as Theora are skipped silently for the caller (a debug log is
 * emitted), and a new {@link OggPage} is produced that contains only the accepted packets. If the
 * superclass finds the underlying bitstream to be invalid, parsing is aborted and {@code null} is
 * returned from {@link #parse(OggPage)}.
 *
 * <p>Typical usage is to construct one instance per logical Ogg/Theora stream and invoke {@link
 * #parse(OggPage)} for each page in order. The class holds minimal per-stream state and is intended
 * to be used in a single-threaded decoding/ingestion pipeline; instances are not designed to be
 * shared across threads without external synchronization.
 *
 * <ul>
 *   <li>Responsibility: accept well-formed Theora packets and drop malformed ones.
 *   <li>Scope: operates at the packet level within an Ogg page; does not transcode.
 *   <li>Failure model: invalid packets are ignored; invalid streams stop further processing.
 * </ul>
 *
 * @see OggBitstreamFilter
 * @see TheoraPacketFilter
 * @see OggPage
 * @see CodecPacket
 */
public class TheoraBitstreamFilter extends OggBitstreamFilter {
  private static final Logger LOG = LoggerFactory.getLogger(TheoraBitstreamFilter.class);

  private final TheoraPacketFilter parser;

  /**
   * Creates a new Theora bitstream filter initialized from the supplied page.
   *
   * <p>The provided {@code page} is forwarded to the superclass to initialize common Ogg stream
   * validation and state. Callers typically construct the filter with the first page of a Theora
   * logical stream and then feed later pages via {@link #parse(OggPage)}.
   *
   * <pre>{@code
   * // Example: construct per-stream filter and feed pages
   * var filter = new TheoraBitstreamFilter(firstPage);
   * var processed = filter.parse(nextPage);
   * }</pre>
   *
   * @param page initial {@link OggPage} used to initialize superclass state; must represent the
   *     same logical stream as later pages; not {@code null}.
   */
  protected TheoraBitstreamFilter(OggPage page) {
    super(page);
    parser = new TheoraPacketFilter();
  }

  /**
   * Parses and filters a single Ogg page, returning a page that retains only packets accepted by
   * the Theora packet parser.
   *
   * <p>The method first delegates to the superclass for generic Ogg processing. If the stream has
   * been marked invalid, it returns {@code null}. Otherwise, each packet from the input page is
   * parsed; packets that raise a {@code DataFilterException} are skipped, and all other packets are
   * kept. A new {@link OggPage} instance is returned that references the filtered packet list.
   *
   * @param page input {@link OggPage} belonging to the same logical stream used at construction;
   *     must not be {@code null}.
   * @return a new {@link OggPage} containing only packets successfully parsed as Theora; returns
   *     {@code null} when the stream is not valid per superclass checks.
   * @throws IOException if an I/O error occurs during superclass parsing or page materialization.
   */
  @Override
  OggPage parse(OggPage page) throws IOException {
    page = super.parse(page);
    if (!isValidStream) {
      return null;
    }

    List<CodecPacket> parsedPackets = new ArrayList<>();
    for (CodecPacket packet : page.asPackets()) {
      try {
        parsedPackets.add(parser.parse(packet));
      } catch (DataFilterException e) { // skip packet
        LOG.debug(e.getLocalizedMessage());
      }
    }

    page = new OggPage(page, parsedPackets);
    return page;
  }
}
