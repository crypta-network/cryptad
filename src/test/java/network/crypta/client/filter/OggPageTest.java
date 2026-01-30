package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class OggPageTest {

  // Helper: Build a valid Ogg page byte[] starting from the magic ("OggS") with a correct CRC.
  private static byte[] buildValidPageBytes(
      int version,
      int headerType,
      byte[] granulePos,
      byte[] serialBytes,
      byte[] pageSeqBytes,
      byte[] segmentTable,
      byte[] payload)
      throws IOException {
    // Construct an "old" page by feeding the constructor a stream starting at the version byte
    // (no magic). Then reconstruct a new page from its packets to calculate a valid CRC.
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write((byte) version);
    bos.write((byte) headerType);
    bos.write(granulePos);
    bos.write(serialBytes);
    bos.write(pageSeqBytes);
    bos.write(new byte[] {0, 0, 0, 0}); // placeholder checksum in header for the read constructor
    bos.write((byte) (segmentTable.length & 0xFF));
    bos.write(segmentTable);
    bos.write(payload);

    OggPage oldPage = new OggPage(new DataInputStream(new ByteArrayInputStream(bos.toByteArray())));
    Collection<CodecPacket> packets = oldPage.asPackets();
    OggPage rebuilt = new OggPage(oldPage, packets); // recomputes checksum
    return rebuilt.toArray(); // includes magic + computed checksum
  }

  // Helper: Create a DataInputStream for readPage with optional noise before a valid page.
  private static DataInputStream disWithNoise(byte[] validPageBytes, byte[] leadingNoise) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try {
      if (leadingNoise != null) out.write(leadingNoise);
      out.write(validPageBytes);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return new DataInputStream(new ByteArrayInputStream(out.toByteArray()));
  }

  @Test
  void readPage_whenSinglePacket_expectHeaderAndPayloadParsed() throws IOException {
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0x01, 0x02, 0x03, 0x04};
    byte[] pageSeq = new byte[] {0x11, 0x22, 0x33, 0x44};
    byte[] payload = new byte[] {0x61, 0x62, 0x63}; // "abc"
    byte[] segTable = new byte[] {(byte) 3};

    byte[] pageBytes = buildValidPageBytes(0, 0, granule, serial, pageSeq, segTable, payload);

    try (DataInputStream in = disWithNoise(pageBytes, new byte[] {9, 9, 9, 9, 9})) {
      OggPage page = OggPage.readPage(in);

      assertAll(
          () -> assertTrue(page.headerValid(), "headerValid"),
          () -> assertFalse(page.isPacketContinued(), "isPacketContinued"),
          () -> assertFalse(page.isFinalPacket(), "isFinalPacket"),
          () -> assertEquals(ByteBuffer.wrap(serial).getInt(), page.getSerial(), "serial"),
          () ->
              assertEquals(
                  Integer.reverseBytes(ByteBuffer.wrap(pageSeq).getInt()),
                  page.getPageNumber(),
                  "pageNumber"));

      // Verify we can reconstruct the original codec packet from segment lacing
      ArrayList<CodecPacket> packets = new ArrayList<>(page.asPackets());
      assertEquals(1, packets.size(), "packet count");
      assertArrayEquals(payload, packets.getFirst().toArray(), "packet payload");
    }
  }

  @Test
  void headerValid_whenVersionIsNotZero_expectFalseEvenWithCorrectCRC() throws IOException {
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0x00, 0x00, 0x00, 0x10};
    byte[] pageSeq = new byte[] {0x01, 0x00, 0x00, 0x00};
    byte[] payload = new byte[] {1, 2, 3, 4};
    byte[] segTable = new byte[] {(byte) 4};

    byte[] pageBytes =
        buildValidPageBytes(1, 0, granule, serial, pageSeq, segTable, payload); // version=1

    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(pageBytes))) {
      OggPage page = OggPage.readPage(in);
      assertFalse(page.headerValid(), "Non-zero version must be invalid");
    }
  }

  @Test
  void isPacketContinued_whenBit0Set_expectTrue() throws IOException {
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0x00, 0x00, 0x00, 0x20};
    byte[] pageSeq = new byte[] {0x01, 0x02, 0x03, 0x04};
    byte[] payload = new byte[] {7, 8, 9};
    byte[] segTable = new byte[] {(byte) 3};

    byte[] pageBytes = buildValidPageBytes(0, 0x01, granule, serial, pageSeq, segTable, payload);
    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(pageBytes))) {
      OggPage page = OggPage.readPage(in);
      assertTrue(page.isPacketContinued());
    }
  }

  @Test
  void isFinalPacket_whenBit2Set_expectTrue() throws IOException {
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0, 0, 0, 0x30};
    byte[] pageSeq = new byte[] {0x55, 0x66, 0x77, 0x01};
    byte[] payload = new byte[] {42};
    byte[] segTable = new byte[] {(byte) 1};

    byte[] pageBytes = buildValidPageBytes(0, 0x04, granule, serial, pageSeq, segTable, payload);
    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(pageBytes))) {
      OggPage page = OggPage.readPage(in);
      assertTrue(page.isFinalPacket());
    }
  }

  @Test
  void recalculateSegmentLacing_whenNullSizes_expectSegmentsSpanEntirePayload() throws IOException {
    // Payload of 510 bytes => two full 255-sized segments
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0, 0, 0, 0x7F};
    byte[] pageSeq = new byte[] {1, 2, 3, 4};
    byte[] payload = new byte[510];
    byte[] segTable = new byte[] {(byte) 255, (byte) 255};

    byte[] pageBytes = buildValidPageBytes(0, 0, granule, serial, pageSeq, segTable, payload);
    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(pageBytes))) {
      OggPage page = OggPage.readPage(in);

      page.recalculateSegmentLacing(null);

      // Expect a single packet spanning all segments (510 bytes). A segment value of 255 does not
      // terminate a packet unless it is the last segment of the page.
      var packets = new ArrayList<>(page.asPackets());
      assertEquals(1, packets.size(), "packet count after recalc(null)");
      assertEquals(510, packets.getFirst().toArray().length, "single packet length");
    }
  }

  @Test
  void recalculateSegmentLacing_whenExplicitSizes_expectCorrectLacing() throws IOException {
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0, 0, 0, 0x55};
    byte[] pageSeq = new byte[] {9, 9, 9, 9};
    byte[] payload = new byte[256 + 1];
    byte[] segTable = new byte[] {(byte) 255, (byte) 1, (byte) 1}; // initial, arbitrary

    byte[] pageBytes = buildValidPageBytes(0, 0, granule, serial, pageSeq, segTable, payload);

    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(pageBytes))) {
      OggPage page = OggPage.readPage(in);

      List<Integer> sizes = new ArrayList<>();
      sizes.add(256); // -> lacing: 255, 1
      sizes.add(1); // -> lacing: 1

      page.recalculateSegmentLacing(sizes);
      var packets = new ArrayList<>(page.asPackets());
      assertEquals(2, packets.size());
      assertAll(
          () -> assertEquals(256, packets.getFirst().toArray().length, "first packet length"),
          () -> assertEquals(1, packets.get(1).toArray().length, "second packet length"));
    }
  }

  @Test
  void seekToPage_withOverlappingCandidate_doesNotSkipValidHeader() throws IOException {
    // Build a minimal valid page and prepend stray bytes: 0x4f ('O'), 0x00.
    // The valid page starts immediately after, causing the input prefix to be
    // ... 4f 00 4f 67 67 53 ...
    // The scanner must not skip the second 0x4f when the first partial match fails.
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0x00, 0x00, 0x00, 0x21};
    byte[] pageSeq = new byte[] {0x00, 0x00, 0x00, 0x02};
    byte[] payload = new byte[] {0x41, 0x42}; // "AB"
    byte[] segTable = new byte[] {(byte) 2};

    byte[] pageBytes = buildValidPageBytes(0, 0, granule, serial, pageSeq, segTable, payload);

    try (DataInputStream in = disWithNoise(pageBytes, new byte[] {(byte) 0x4f, 0x00})) {
      OggPage page = OggPage.readPage(in);
      assertTrue(page.headerValid(), "Scanner must find real page after stray 0x4f");
      // Basic sanity checks to ensure we parsed the intended page
      assertEquals(ByteBuffer.wrap(serial).getInt(), page.getSerial());
      assertEquals(Integer.reverseBytes(ByteBuffer.wrap(pageSeq).getInt()), page.getPageNumber());
    }
  }

  @Test
  void asPackets_whenLacingExceedsPayload_expectArrayIndexOutOfBounds() throws IOException {
    // Build a small valid page, then rewrite lacing to exceed payload length
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0, 0, 0, 0x42};
    byte[] pageSeq = new byte[] {1, 0, 0, 0};
    byte[] payload = new byte[10];
    byte[] segTable = new byte[] {(byte) 10};

    byte[] pageBytes = buildValidPageBytes(0, 0, granule, serial, pageSeq, segTable, payload);
    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(pageBytes))) {
      OggPage page = OggPage.readPage(in);

      List<Integer> badSizes = new ArrayList<>();
      badSizes.add(20); // larger than actual payload
      page.recalculateSegmentLacing(badSizes);

      assertThrows(ArrayIndexOutOfBoundsException.class, page::asPackets);
    }
  }

  @Test
  void asPackets_whenZeroLengthSegment_presentExpectEmptyPacket() throws IOException {
    // Craft a page with segment table [0, 3] and a 3-byte payload; asPackets should produce an
    // empty packet followed by a 3-byte packet.
    byte[] granule = new byte[8];
    byte[] serial = new byte[] {0, 0, 0, 0x24};
    byte[] pageSeq = new byte[] {0, 0, 0, 1};
    byte[] payload = new byte[] {1, 2, 3};
    byte[] segTable = new byte[] {0, 3};

    // For this test we can parse directly using the constructor that starts at version (no magic)
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write((byte) 0); // version
    bos.write((byte) 0); // headerType
    bos.write(granule);
    bos.write(serial);
    bos.write(pageSeq);
    bos.write(new byte[] {0, 0, 0, 0}); // checksum placeholder
    bos.write((byte) 2); // segments
    bos.write(segTable);
    bos.write(payload);

    OggPage page = new OggPage(new DataInputStream(new ByteArrayInputStream(bos.toByteArray())));

    ArrayList<CodecPacket> packets = new ArrayList<>(page.asPackets());
    assertEquals(2, packets.size(), "packet count");
    assertAll(
        () -> assertEquals(0, packets.getFirst().toArray().length, "first packet empty"),
        () -> assertArrayEquals(new byte[] {1, 2, 3}, packets.get(1).toArray(), "second packet"));
  }
}
