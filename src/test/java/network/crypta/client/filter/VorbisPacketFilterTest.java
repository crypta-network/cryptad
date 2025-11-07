package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@SuppressWarnings("java:S100")
class VorbisPacketFilterTest {

  // --- identification header tests ---

  @Test
  void parse_whenFirstPacketNotIdentification_expectNull() throws IOException {
    VorbisPacketFilter filter = new VorbisPacketFilter();
    byte[] payload = buildHeader((byte) 0x02, VorbisPacketFilter.magicNumber); // not 1
    CodecPacket packet = new CodecPacket(payload);

    assertNull(filter.parse(packet));
    assertEquals(VorbisPacketFilter.State.UNINITIALIZED, filter.currentState);
  }

  @Test
  void parse_whenIdentificationHeaderWrongMagic_expectNull() throws IOException {
    VorbisPacketFilter filter = new VorbisPacketFilter();
    byte[] wrongMagic = new byte[] {'v', 'o', 'r', 'b', 'i', 'X'}; // last char mismatched
    byte[] payload = buildHeader((byte) 0x01, wrongMagic);
    CodecPacket packet = new CodecPacket(payload);

    assertNull(filter.parse(packet));
    assertEquals(VorbisPacketFilter.State.UNINITIALIZED, filter.currentState);
  }

  @ParameterizedTest(name = "channels={0}, sampleRate={1}, framing={2}")
  @CsvSource({
    // zero channels
    "0,44100,true",
    // zero sample rate
    "2,0,true",
    // framing flag false
    "2,44100,false"
  })
  void parse_identificationHeaderInvalid_expectNull(int channels, int sampleRate, boolean framing)
      throws IOException {
    VorbisPacketFilter filter = new VorbisPacketFilter();
    byte[] payload = buildIdentificationHeader(channels, sampleRate, framing);
    CodecPacket packet = new CodecPacket(payload);

    assertNull(filter.parse(packet));
    assertEquals(VorbisPacketFilter.State.UNINITIALIZED, filter.currentState);
  }

  @Test
  void parse_whenIdentificationHeaderValid_expectReturnsSamePacketAndAdvancesState()
      throws IOException {
    VorbisPacketFilter filter = new VorbisPacketFilter();
    CodecPacket packet = new CodecPacket(buildIdentificationHeader(2, 44100, true));

    CodecPacket returned = filter.parse(packet);

    assertNotNull(returned);
    assertSame(packet, returned);
    assertEquals(VorbisPacketFilter.State.IDENTIFICATION_FOUND, filter.currentState);
  }

  // --- comment header tests ---

  @Test
  void parse_whenCommentHeaderValid_expectRewrittenPacketAndAdvanceState() throws IOException {
    VorbisPacketFilter filter = new VorbisPacketFilter();
    // First: valid identification to move state forward
    assertNotNull(filter.parse(new CodecPacket(buildIdentificationHeader(2, 48000, true))));

    // Then: a minimal valid comment header
    CodecPacket comment =
        new CodecPacket(buildCommentHeader(/* vendorLen= */ 5, /* listLen= */ 2, true));
    CodecPacket rewritten = filter.parse(comment);

    // Expect a new instance with sanitized payload: magic + 0 + 0 + true
    assertNotNull(rewritten);
    assertNotSame(rewritten, comment, "should return a new CodecPacket instance");
    byte[] expected = buildSanitizedComment();
    assertArrayEquals(expected, rewritten.toArray());
    assertEquals(VorbisPacketFilter.State.COMMENT_FOUND, filter.currentState);
  }

  @Test
  void parse_whenCommentHeaderFramingFalse_expectNullAndStateUnchanged() throws IOException {
    VorbisPacketFilter filter = new VorbisPacketFilter();
    // Move to IDENTIFICATION_FOUND
    assertNotNull(filter.parse(new CodecPacket(buildIdentificationHeader(2, 44100, true))));

    // Invalid comment: framing flag false
    CodecPacket invalidComment =
        new CodecPacket(
            buildCommentHeader(/* vendorLen= */ 3, /* listLen= */ 1, /* framing= */ false));

    assertNull(filter.parse(invalidComment));
    // Still expecting a comment header next
    assertEquals(VorbisPacketFilter.State.IDENTIFICATION_FOUND, filter.currentState);
  }

  // --- setup header / subsequent packets ---

  @Test
  void parse_whenCommentThenSetup_expectStateSetupAndPacketUnchanged() throws IOException {
    VorbisPacketFilter filter = new VorbisPacketFilter();

    // identification
    assertNotNull(filter.parse(new CodecPacket(buildIdentificationHeader(2, 44100, true))));
    // comment (valid)
    CodecPacket comment = new CodecPacket(buildCommentHeader(1, 1, true));
    filter.parse(comment);
    assertEquals(VorbisPacketFilter.State.COMMENT_FOUND, filter.currentState);

    // setup: content is ignored by filter in this state; must return the same reference
    CodecPacket setup = new CodecPacket(new byte[] {0x55, 0x66});
    CodecPacket returned = filter.parse(setup);
    assertSame(setup, returned);
    assertEquals(VorbisPacketFilter.State.SETUP_FOUND, filter.currentState);
  }

  // --- error handling ---

  @Test
  void parse_whenNullPayload_throwsNullPointerException() {
    VorbisPacketFilter filter = new VorbisPacketFilter();
    CodecPacket packet = new CodecPacket(null);

    assertThrows(NullPointerException.class, () -> filter.parse(packet));
    // State remains unchanged on failure
    assertEquals(VorbisPacketFilter.State.UNINITIALIZED, filter.currentState);
  }

  // --- helpers ---

  private static byte[] buildHeader(byte type, byte[] magic) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(type);
    out.write(magic);
    return out.toByteArray();
  }

  private static byte[] buildIdentificationHeader(int channels, int sampleRate, boolean framing)
      throws IOException {
    ByteArrayOutputStream raw = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(raw);
    // header type + magic
    raw.write(0x01);
    raw.write(VorbisPacketFilter.magicNumber);

    // vorbis_version (read with Integer.reverse; zero stays zero)
    dos.writeInt(0);
    // audio_channels (1 byte)
    dos.writeByte(channels & 0xFF);
    // fields stored little-endian in stream; write reverseBytes to achieve that with writeInt
    dos.writeInt(Integer.reverseBytes(sampleRate));
    dos.writeInt(Integer.reverseBytes(0)); // bitrate_maximum
    dos.writeInt(Integer.reverseBytes(0)); // bitrate_nominal
    dos.writeInt(Integer.reverseBytes(0)); // bitrate_minimum
    dos.writeByte(0x00); // blocksize (any value passes given current expression)
    dos.writeBoolean(framing);

    dos.flush();
    return raw.toByteArray();
  }

  private static byte[] buildCommentHeader(int vendorLen, int listLen, boolean framing)
      throws IOException {
    if (vendorLen < 0 || listLen < 0) throw new IllegalArgumentException();

    ByteArrayOutputStream raw = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(raw);
    raw.write(0x03);
    raw.write(VorbisPacketFilter.magicNumber);

    // vendor string length + bytes (little-endian length)
    dos.writeInt(Integer.reverseBytes(vendorLen));
    for (int i = 0; i < vendorLen; i++) raw.write('A');

    // user comment list length (little-endian)
    dos.writeInt(Integer.reverseBytes(listLen));
    for (int i = 0; i < listLen; i++) {
      // each comment: length + bytes (use 1-byte comments for simplicity)
      dos.writeInt(Integer.reverseBytes(1));
      raw.write('x');
    }

    // framing flag
    dos.writeBoolean(framing);

    dos.flush();
    return raw.toByteArray();
  }

  private static byte[] buildSanitizedComment() throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(out);
    out.write(0x03);
    out.write(VorbisPacketFilter.magicNumber);
    dos.writeInt(0);
    dos.writeInt(0);
    dos.writeBoolean(true);
    dos.flush();
    return out.toByteArray();
  }
}
