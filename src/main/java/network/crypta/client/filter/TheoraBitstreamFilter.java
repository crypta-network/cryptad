package network.crypta.client.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TheoraBitstreamFilter extends OggBitstreamFilter {
  private static final Logger LOG = LoggerFactory.getLogger(TheoraBitstreamFilter.class);

  private final TheoraPacketFilter parser;

  protected TheoraBitstreamFilter(OggPage page) {
    super(page);
    parser = new TheoraPacketFilter();
  }

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
