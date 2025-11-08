package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
class VorbisBitstreamFilterTest {

  @Test
  void parse_whenVorbisHeaders_expectCommentSanitizedAndThreePackets() throws IOException {
    // Arrange: build a single Ogg page with Identification, Comment (with vendor+comments), Setup
    byte[] ident = buildVorbisIdentificationHeader(/* channels= */ 2);
    byte[] comment = buildVorbisCommentHeader(/* comments= */ new String[] {"k1=v1", "k2=v2"});
    byte[] setup = new byte[] {5, 'v', 'o', 'r', 'b', 'i', 's', 0x01}; // minimal, parser ignores

    OggPage input = buildPageFromPackets(111, 1, ident, comment, setup);
    VorbisBitstreamFilter filter = new VorbisBitstreamFilter(input);

    // Act
    OggPage output = filter.parse(input);

    // Assert: three packets, with the Comment header rewritten to empty vendor/comments
    Collection<CodecPacket> packets = output.asPackets();
    assertEquals(3, packets.size());
    List<CodecPacket> list = new ArrayList<>(packets);

    // Identification should be unchanged
    assertArrayEquals(ident, list.get(0).toArray());

    // Comment header is normalized to: [0x03]["vorbis"][vendor_len=0][user_comment_len=0][true]
    byte[] expectedSanitizedComment = sanitizeVorbisCommentHeader();
    assertArrayEquals(expectedSanitizedComment, list.get(1).toArray());

    // Setup should pass through unchanged
    assertArrayEquals(setup, list.get(2).toArray());
  }

  @Test
  void parse_whenPreviouslyInvalidated_expectNullOnSubsequentValidPage() throws IOException {
    // Arrange: create a filter and invalidate it by sending an out-of-order page first.
    OggPage first = buildPageFromPackets(222, 10, new byte[] {1});
    VorbisBitstreamFilter filter = new VorbisBitstreamFilter(first);

    OggPage outOfOrder = buildPageFromPackets(222, 15, new byte[] {2});
    assertThrows(DataFilterException.class, () -> filter.parse(outOfOrder));

    // Act: now send an in-order page (same sequence number is allowed by base class)
    OggPage validAgain = buildPageFromPackets(222, 10, new byte[] {3});
    OggPage result = filter.parse(validAgain);

    // Assert: once invalidated, filter returns null without further processing
    assertNull(result);
  }

  @Test
  void parse_whenIdentificationFramingFalse_expectEmptyPage() throws IOException {
    // Arrange: Identification with framing_flag=false should be rejected (no packets propagated).
    byte[] badIdent = buildVorbisIdentificationHeaderWithFramingFalse();
    OggPage input = buildPageFromPackets(335, 1, badIdent);
    VorbisBitstreamFilter filter = new VorbisBitstreamFilter(input);

    // Act
    List<CodecPacket> pre = new ArrayList<>(input.asPackets());
    assertEquals(1, pre.size());
    assertEquals(badIdent.length, pre.getFirst().toArray().length);

    OggPage out = filter.parse(input);

    // Assert: the page rebuilt by the filter has no packets
    assertNotNull(out);
    assertEquals(0, out.asPackets().size());
  }

  @Test
  void parse_whenInvalidIdentification_expectEmptyPage() throws IOException {
    // Arrange: Identification with audio_channels = 0 (invalid) only.
    byte[] badIdent = buildVorbisIdentificationHeader(/* channels= */ 0);
    OggPage input = buildPageFromPackets(444, 1, badIdent);
    VorbisBitstreamFilter filter = new VorbisBitstreamFilter(input);

    // Act
    // Sanity-check packets from the input page
    List<CodecPacket> pre = new ArrayList<>(input.asPackets());
    assertEquals(1, pre.size());
    assertEquals(badIdent.length, pre.getFirst().toArray().length);

    OggPage out = filter.parse(input);

    // Assert: no packets in the rebuilt page
    assertNotNull(out);
    assertEquals(0, out.asPackets().size());
  }

  // --- helpers ---

  /** Build a minimal Vorbis Identification header payload with non-zero sample rate. */
  private static byte[] buildVorbisIdentificationHeader(int channels) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(1); // header type: identification
    out.write(VorbisPacketFilter.magicNumber);
    out.write(intToBytesBE(0)); // vorbis_version (reversed bits => 0)
    out.write((byte) channels); // audio_channels (>0)
    out.write(intToBytesBE(1)); // audio_sample_rate (reverseBytes != 0)
    out.write(intToBytesBE(0)); // bitrate_maximum (ignored by filter)
    out.write(intToBytesBE(0)); // bitrate_nominal (ignored)
    out.write(intToBytesBE(0)); // bitrate_minimum (ignored)
    out.write(0x11); // blocksize; nibble-check bug won't reject
    out.write(1); // framing_flag = true
    return out.toByteArray();
  }

  /** Build a Vorbis Identification header with framing flag set to false. */
  private static byte[] buildVorbisIdentificationHeaderWithFramingFalse() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(1);
    out.write(VorbisPacketFilter.magicNumber);
    out.write(intToBytesBE(0)); // version
    out.write((byte) 1); // channels=1
    out.write(intToBytesBE(1)); // sample rate
    out.write(intToBytesBE(0)); // bitrate max
    out.write(intToBytesBE(0)); // bitrate nominal
    out.write(intToBytesBE(0)); // bitrate min
    out.write(0x11); // blocksize
    out.write(0); // framing=false
    return out.toByteArray();
  }

  /** Build a Vorbis Comment header payload with a fixed vendor and framing=true. */
  private static byte[] buildVorbisCommentHeader(String[] comments) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x03); // header type: comment
    out.write(VorbisPacketFilter.magicNumber);
    byte[] vendor = "Acme".getBytes();
    out.write(intToBytesBE(Integer.reverseBytes(vendor.length))); // vendor_length (LE on read)
    out.write(vendor);
    out.write(intToBytesBE(Integer.reverseBytes(comments.length))); // user_comment_list_length
    for (String c : comments) {
      out.write(intToBytesBE(Integer.reverseBytes(c.length())));
      out.write(c.getBytes());
    }
    out.write(1); // framing flag true
    return out.toByteArray();
  }

  /** Expected normalized Comment header returned by VorbisPacketFilter. */
  private static byte[] sanitizeVorbisCommentHeader() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x03);
    out.write(VorbisPacketFilter.magicNumber);
    out.write(intToBytesBE(0)); // vendor_length = 0
    out.write(intToBytesBE(0)); // user_comment_list_length = 0
    out.write(1); // framing_flag = true
    return out.toByteArray();
  }

  /** Build an Ogg page with the given serial, sequence, and packets using full header + magic. */
  private static OggPage buildPageFromPackets(int serial, int pageNumber, byte[]... packets)
      throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Magic
    out.write(new byte[] {0x4f, 0x67, 0x67, 0x53}); // "OggS"
    // Version and headerType
    out.write(0); // version
    out.write(0); // headerType
    // granule position (8 bytes)
    out.write(new byte[8]);
    // bitstream serial (big-endian int)
    out.write(intToBytesBE(serial));
    // page sequence number (big-endian as written on wire)
    out.write(intToBytesBE(pageNumber));
    // checksum (ignored for tests here)
    out.write(new byte[4]);

    // Segment table
    List<Byte> lacing = new ArrayList<>();
    for (byte[] p : packets) {
      if (p.length == 0 || p.length >= 255) {
        throw new IllegalArgumentException("packet must be 1..254 bytes for this helper");
      }
      lacing.add((byte) p.length);
    }
    out.write((byte) lacing.size());
    for (byte b : lacing) out.write(b);
    for (byte[] p : packets) out.write(p);

    try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(out.toByteArray()))) {
      return OggPage.readPage(in);
    }
  }

  private static byte[] intToBytesBE(int v) {
    return ByteBuffer.allocate(4).putInt(v).array();
  }
}
