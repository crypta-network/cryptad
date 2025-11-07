package network.crypta.client.filter;

import static network.crypta.client.filter.ResourceFileUtil.resourceToDataInputStream;
import static network.crypta.client.filter.ResourceFileUtil.resourceToOggPage;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TheoraBitstreamFilterTest {

  @Test
  void parse_whenIdentificationHeader_expectSamePackets() throws IOException {
    // Arrange
    OggPage page = resourceToOggPage("./ogg/theora_header.ogg");
    TheoraBitstreamFilter filter = new TheoraBitstreamFilter(page);

    // Act
    var resultPackets = filter.parse(page).asPackets();

    // Assert
    assertEquals(page.asPackets(), resultPackets);
  }

  @Test
  void parse_whenParsingRealTheoraStream_expectNoExceptions() throws IOException {
    // Arrange
    int processed = 0;

    try (DataInputStream input =
        resourceToDataInputStream("./ogg/Infinite_Hands-2008-Thusnelda-2009-09-18.ogv")) {
      OggPage page = OggPage.readPage(input);
      int pageSerial = page.getSerial();
      TheoraBitstreamFilter filter = new TheoraBitstreamFilter(page);

      // Act
      while (true) {
        try {
          if (page.getSerial() == pageSerial) {
            filter.parse(page);
            processed++;
          }

          page = OggPage.readPage(input);
        } catch (EOFException e) {
          break;
        }
      }
    }

    // Assert
    // At least one page of the target serial should be processed without exceptions.
    assertTrue(processed > 0);
  }

  @Test
  void parse_whenInvalidHeader_expectUnknownContentTypeException() throws IOException {
    // Arrange
    OggPage page = resourceToOggPage("./ogg/invalid_header.ogg");
    TheoraBitstreamFilter filter = new TheoraBitstreamFilter(page);

    // Act & Assert
    assertThrows(UnknownContentTypeException.class, () -> filter.parse(page));
  }

  @Test
  void parse_whenParserThrowsDataFilterException_skipsPacket() throws Exception {
    OggPage page = buildSyntheticPage(1234, 1, new byte[] {1, 2}, new byte[] {3, 4, 5});
    TheoraBitstreamFilter filter = new TheoraBitstreamFilter(page);

    // Replace internal parser with a stub that throws for the first packet and returns a custom
    // packet for the second.
    TheoraPacketFilter stub =
        new TheoraPacketFilter() {
          int idx = 0;

          @Override
          public CodecPacket parse(CodecPacket packet) throws IOException {
            if (idx++ == 0) {
              throw new DataFilterException("skip this packet");
            }
            return new CodecPacket(new byte[] {9, 9});
          }
        };
    setParserViaReflection(filter, stub);

    OggPage out = filter.parse(page);
    Collection<CodecPacket> packets = out.asPackets();
    assertEquals(1, packets.size());
    assertArrayEquals(new byte[] {9, 9}, packets.iterator().next().toArray());
  }

  @Test
  void parse_whenParserThrowsUnknownContentTypeException_propagates() throws Exception {
    OggPage page = buildSyntheticPage(2222, 1, new byte[] {10, 11, 12});
    TheoraBitstreamFilter filter = new TheoraBitstreamFilter(page);

    TheoraPacketFilter stub =
        new TheoraPacketFilter() {
          @Override
          public CodecPacket parse(CodecPacket packet) throws IOException {
            throw new UnknownContentTypeException("theora/test");
          }
        };
    setParserViaReflection(filter, stub);

    assertThrows(UnknownContentTypeException.class, () -> filter.parse(page));
  }

  @Test
  void parse_whenPageSequenceOutOfOrder_throwsDataFilterException() throws Exception {
    OggPage first = buildSyntheticPage(777, 1, new byte[] {1});
    TheoraBitstreamFilter filter = new TheoraBitstreamFilter(first);

    // Same serial number, but jump sequence number by +2 to violate ordering rules
    OggPage outOfOrder = buildSyntheticPage(777, 3, new byte[] {2});
    assertThrows(DataFilterException.class, () -> filter.parse(outOfOrder));
  }

  // Helpers
  private static OggPage buildSyntheticPage(int serial, int pageNumber, byte[]... packets)
      throws IOException {
    // Build a minimal Ogg page with provided packets (each fits in a single segment <255 bytes).
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(new byte[] {0x4f, 0x67, 0x67, 0x53}); // "OggS"
    out.write(0); // version
    out.write(0); // headerType
    out.write(new byte[8]); // granule position
    out.write(intToBytes(serial)); // bitstream serial
    out.write(intToBytes(pageNumber)); // page sequence number
    out.write(new byte[4]); // checksum (ignored by parser here)

    int segmentCount = packets.length;
    out.write((byte) segmentCount);
    for (byte[] p : packets) {
      if (p.length == 0 || p.length >= 255) {
        throw new IllegalArgumentException("packet must be 1..254 bytes for this helper");
      }
      out.write((byte) p.length);
    }
    for (byte[] p : packets) {
      out.write(p);
    }

    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(out.toByteArray()))) {
      return OggPage.readPage(in);
    }
  }

  private static byte[] intToBytes(int value) {
    return ByteBuffer.allocate(4).putInt(value).array();
  }

  private static void setParserViaReflection(TheoraBitstreamFilter filter, TheoraPacketFilter stub)
      throws Exception {
    var field = TheoraBitstreamFilter.class.getDeclaredField("parser");
    field.setAccessible(true);
    field.set(filter, stub);
  }
}
