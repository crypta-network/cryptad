package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class OggBitstreamFilterTest {

  @Test
  void getBitstreamFilter_whenVorbisMagic_expectVorbisFilter() throws IOException {
    byte[] payload = concat(new byte[] {1}, VorbisPacketFilter.magicNumber, new byte[] {0});
    OggPage page = buildPage(1234, 1, payload);

    OggBitstreamFilter filter = OggBitstreamFilter.getBitstreamFilter(page);

    assertNotNull(filter);
    assertInstanceOf(VorbisBitstreamFilter.class, filter);
  }

  @Test
  void getBitstreamFilter_whenTheoraMagic_expectTheoraFilter() throws IOException {
    byte[] payload =
        concat(new byte[] {(byte) 0x80}, TheoraPacketFilter.magicNumber, new byte[] {0});
    OggPage page = buildPage(5678, 2, payload);

    OggBitstreamFilter filter = OggBitstreamFilter.getBitstreamFilter(page);

    assertNotNull(filter);
    assertInstanceOf(TheoraBitstreamFilter.class, filter);
  }

  @Test
  void getBitstreamFilter_whenUnknownMagic_expectNull() throws IOException {
    byte[] payload = new byte[] {0, 'x', 'y', 'z', 1, 2};
    OggPage page = buildPage(42, 3, payload);

    assertNull(OggBitstreamFilter.getBitstreamFilter(page));
  }

  @Test
  void parse_whenSequenceIncrements_expectUpdatesLastAndReturnsPage() throws IOException {
    OggPage first = buildPage(99, 10, new byte[] {0});
    TestFilter filter = new TestFilter(first);

    OggPage next = buildPage(99, 11, new byte[] {1, 2, 3});
    OggPage returned = assertDoesNotThrow(() -> filter.parse(next));

    assertSame(next, returned);
    assertEquals(11, filter.lastPageSequenceNumber);
  }

  @Test
  void parse_whenSameSequence_expectAllowed() throws IOException {
    OggPage first = buildPage(7, 5, new byte[] {0});
    TestFilter filter = new TestFilter(first);

    OggPage same = buildPage(7, 5, new byte[] {9});
    assertDoesNotThrow(() -> filter.parse(same));
    assertEquals(5, filter.lastPageSequenceNumber);
  }

  @Test
  void parse_whenOutOfOrder_expectDataFilterExceptionWithLocalizedTitles() throws IOException {
    OggPage initial = buildPage(1, 100, new byte[] {0});
    VorbisBitstreamFilter filter = new VorbisBitstreamFilter(initial);

    OggPage outOfOrder = buildPage(1, 102, new byte[] {1});

    DataFilterException ex =
        assertThrows(DataFilterException.class, () -> filter.parse(outOfOrder));

    // Titles/messages come from NodeL10n using the simple class name of the runtime type
    String expectedTitle =
        network.crypta.l10n.NodeL10n.getBase().getString("VorbisBitstreamFilter.MalformedTitle");
    String expectedMessage =
        network.crypta.l10n.NodeL10n.getBase().getString("VorbisBitstreamFilter.MalformedMessage");

    assertEquals(expectedTitle, ex.getRawTitle());
    assertEquals(expectedTitle, ex.getHTMLEncodedTitle());
    assertEquals(expectedMessage, ex.getMessage());
    // Filter invalidated
    assertFalse(filter.isValidStream);
  }

  // --- helpers ---

  private static OggPage buildPage(int serial, int pageNumber, byte[] payload) throws IOException {
    if (payload.length > 255)
      throw new IllegalArgumentException("payload too large for single segment");

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Version and headerType
    out.write(0); // version
    out.write(0); // headerType
    // granule position (8 bytes)
    out.write(new byte[8]);
    // bitstream serial (big-endian int)
    out.write(intToBytesBE(serial));
    // page sequence number: store reverseBytes so getter returns desired value
    out.write(intToBytesBE(Integer.reverseBytes(pageNumber)));
    // checksum (ignored for tests)
    out.write(new byte[4]);
    // segment count (1)
    out.write(1);
    // segment table (single segment with full payload size)
    out.write((byte) payload.length);
    // payload bytes
    out.write(payload);

    return new OggPage(new DataInputStream(new ByteArrayInputStream(out.toByteArray())));
  }

  private static byte[] intToBytesBE(int v) {
    return ByteBuffer.allocate(4).putInt(v).array();
  }

  private static byte[] concat(byte[] a, byte[] b, byte[] c) {
    byte[] r = new byte[a.length + b.length + c.length];
    System.arraycopy(a, 0, r, 0, a.length);
    System.arraycopy(b, 0, r, a.length, b.length);
    System.arraycopy(c, 0, r, a.length + b.length, c.length);
    return r;
  }

  /** Minimal concrete filter exposing super.parse for direct testing. */
  private static final class TestFilter extends OggBitstreamFilter {
    TestFilter(OggPage page) {
      super(page);
    }

    @Override
    public OggPage parse(OggPage page) throws IOException {
      return super.parse(page);
    }
  }
}
