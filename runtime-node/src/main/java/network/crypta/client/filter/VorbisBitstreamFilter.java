package network.crypta.client.filter;

import java.io.IOException;
import java.util.ArrayList;

/**
 * Parses and validates Ogg Vorbis logical bitstreams.
 *
 * <p>This filter specializes {@link OggBitstreamFilter} with Vorbis-specific packet processing
 * performed by a {@link VorbisPacketFilter}. An instance is bound to one Ogg logical stream (the
 * page serial number captured at construction) and expects pages from that stream in sequence.
 * Callers typically obtain an instance via {@link OggBitstreamFilter#getBitstreamFilter(OggPage)}
 * after inspecting an early header page, then feed subsequent pages to {@code parse}. The filter
 * delegates packet-level checks to the Vorbis packet filter and returns a new {@link OggPage}
 * composed of the packets that passed validation/transformation. Packets rejected by the packet
 * filter are omitted from the returned page.
 *
 * <p>Ordering and basic structural checks (e.g., page sequence progression within a logical stream)
 * are implemented by the base class and preserved by delegation. If a structural violation is
 * detected, the filter marks the stream invalid and throws a {@code DataFilterException}. Once
 * invalidated, further parsing attempts on the same instance yield no result. Instances are not
 * thread-safe and are intended for single-consumer use per logical bitstream.
 *
 * <ul>
 *   <li>Responsibilities: maintain per-stream ordering, apply Vorbis packet filtering, and emit a
 *       reconstructed page containing accepted packets.
 *   <li>Notable behavior: silently drops packets that fail Vorbis validation rather than halting
 *       the entire stream, unless a structural page error occurs.
 *   <li>State model: minimal state (validity flag and last page number) inherited from the base
 *       filter; no shared mutable state across streams.
 * </ul>
 *
 * @author sajack
 * @see OggBitstreamFilter
 * @see VorbisPacketFilter
 * @see OggPage
 * @see CodecPacket
 */
public class VorbisBitstreamFilter extends OggBitstreamFilter {
  private final VorbisPacketFilter parser;

  VorbisBitstreamFilter(OggPage page) {
    super(page);
    parser = new VorbisPacketFilter();
  }

  @Override
  OggPage parse(OggPage page) throws IOException {
    page = super.parse(page);
    if (!isValidStream) return null;
    ArrayList<CodecPacket> parsedPackets = new ArrayList<>();
    for (CodecPacket packet : page.asPackets()) {
      packet = parser.parse(packet);
      if (packet != null) parsedPackets.add(packet);
    }
    return new OggPage(page, parsedPackets);
  }
}
