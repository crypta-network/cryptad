package network.crypta.client.filter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TheoraPacketFilterTest {

  @Test
  void parse_whenValidHeadersAndFrame_expectNormalizationAndPassThrough() {
    // Arrange
    TheoraPacketFilter filter = new TheoraPacketFilter();

    CodecPacket id = new CodecPacket(buildValidIdentificationHeader());
    CodecPacket comment = new CodecPacket(buildCommentHeader());
    CodecPacket setup = new CodecPacket(buildSetupHeaderValid());
    byte[] framePayload = new byte[] {0x01, 0x02, 0x03};
    CodecPacket frame = new CodecPacket(framePayload);

    // Act & Assert (Identification: returned as-is)
    CodecPacket outId = assertDoesNotThrow(() -> filter.parse(id));
    assertNotNull(outId);
    assertArrayEquals(id.toArray(), outId.toArray());

    // Act & Assert (Comment: normalized to empty vendor + comments)
    CodecPacket outComment = assertDoesNotThrow(() -> filter.parse(comment));
    assertNotNull(outComment);
    byte[] expectedComment = buildNormalizedEmptyCommentHeader();
    assertArrayEquals(expectedComment, outComment.toArray());

    // Act & Assert (Setup: returned as-is)
    CodecPacket outSetup = assertDoesNotThrow(() -> filter.parse(setup));
    assertNotNull(outSetup);
    assertArrayEquals(setup.toArray(), outSetup.toArray());

    // Act & Assert (Frame: pass-through unchanged)
    CodecPacket outFrame = assertDoesNotThrow(() -> filter.parse(frame));
    assertNotNull(outFrame);
    assertArrayEquals(framePayload, outFrame.toArray());
  }

  @Test
  void parse_whenIdentificationHeaderTypeWrong_expectUnknownContentTypeException() {
    // Arrange: use 0x81 instead of 0x80 for the first header byte
    byte[] payload =
        concat(new byte[] {(byte) 0x81}, TheoraPacketFilter.magicNumber, new byte[] {0});
    TheoraPacketFilter filter = new TheoraPacketFilter();

    // Act & Assert
    assertThrows(UnknownContentTypeException.class, () -> filter.parse(new CodecPacket(payload)));
  }

  @Test
  void parse_whenIdentificationHeaderMagicWrong_expectUnknownContentTypeException() {
    // Arrange: correct type, wrong magic bytes
    byte[] wrongMagic = new byte[] {'n', 'o', 't', 'h', 'e', 'o'};
    byte[] payload = concat(new byte[] {(byte) 0x80}, wrongMagic, new byte[] {0});
    TheoraPacketFilter filter = new TheoraPacketFilter();

    // Act & Assert
    assertThrows(UnknownContentTypeException.class, () -> filter.parse(new CodecPacket(payload)));
  }

  @Test
  void parse_whenIdentificationHeaderPfEqualsOne_expectUnknownContentTypeException() {
    // Arrange: build an otherwise-valid identification header but set PF=1 (disallowed)
    TheoraPacketFilter filter = new TheoraPacketFilter();
    byte[] id = buildIdentificationHeader(/*pf*/ 1, /*res*/ 0);

    // Act & Assert
    assertThrows(UnknownContentTypeException.class, () -> filter.parse(new CodecPacket(id)));
  }

  @Test
  void parse_whenSetupHeaderQiExceeds63_expectUnknownContentTypeException() {
    // Arrange: Step through valid ID + Comment to transition parser state to SETUP
    TheoraPacketFilter filter = new TheoraPacketFilter();
    assertDoesNotThrow(() -> filter.parse(new CodecPacket(buildValidIdentificationHeader())));
    assertDoesNotThrow(() -> filter.parse(new CodecPacket(buildCommentHeader())));

    byte[] invalidSetup = buildSetupHeaderInvalidQiGt63();

    // Act & Assert
    assertThrows(
        UnknownContentTypeException.class, () -> filter.parse(new CodecPacket(invalidSetup)));
  }

  @Test
  void parse_whenSetupHeaderNbmsTooLarge_expectUnknownContentTypeException() {
    // Arrange: Step through valid ID + Comment to transition parser state to SETUP
    TheoraPacketFilter filter = new TheoraPacketFilter();
    assertDoesNotThrow(() -> filter.parse(new CodecPacket(buildValidIdentificationHeader())));
    assertDoesNotThrow(() -> filter.parse(new CodecPacket(buildCommentHeader())));

    byte[] invalidSetup = buildSetupHeaderInvalidNbms();

    // Act & Assert
    assertThrows(
        UnknownContentTypeException.class, () -> filter.parse(new CodecPacket(invalidSetup)));
  }

  // --- helpers ---

  private static byte[] buildIdentificationHeader(int pf, int res) {
    BitWriter w = new BitWriter();
    // Header type (0x80) and magic "theora"
    w.u8(0x80);
    w.magic();

    // VMAJ (3), VMIN (2), VREV (0)
    w.u8(3);
    w.u8(2);
    w.u8(0);

    // FMBW (>0) and FMBH (>0). Use different values to diversify parameters.
    w.u16(10);
    w.u16(11);

    // PICW, PICH (<= FMB*16)
    w.u24(160);
    w.u24(160);

    // PICX, PICY (0)
    w.u8(0);
    w.u8(0);

    // FRN (>0), FRD (>0)
    w.u32(30);
    w.u32(1);

    // PARN (24) + PARD (24) skipped by reader
    w.u24(0);
    w.u24(0);

    // Use CS value 1 within the allowed 0-2 range.
    w.u8(1);

    // NOMBR + QUAL + KFGSHIFT: 35 bits (zeros)
    w.bits(0, 35);

    // PF (2 bits) must not be 1
    if (pf < 0 || pf > 3) throw new IllegalArgumentException("pf must be 0..3");
    w.bits(pf, 2);

    // Res (3 bits) must be 0
    if (res < 0 || res > 7) throw new IllegalArgumentException("res must be 0..7");
    w.bits(res, 3);

    return w.toByteArray();
  }

  private static byte[] buildCommentHeader() {
    BitWriter w = new BitWriter();
    w.u8(0x81);
    w.magic();
    // The parser ignores remaining bytes (vendor and user comments); include a small filler.
    w.u32(1); // vendor length (dummy)
    w.u8('x');
    w.u32(0); // userCommentsNumber
    return w.toByteArray();
  }

  private static byte[] buildNormalizedEmptyCommentHeader() {
    byte[] out = new byte[TheoraPacketFilter.magicNumber.length + 9];
    out[0] = (byte) 0x81;
    System.arraycopy(
        TheoraPacketFilter.magicNumber, 0, out, 1, TheoraPacketFilter.magicNumber.length);
    // The trailing 8 bytes are already zero per array initialization.
    return out;
  }

  private static byte[] buildSetupHeaderValid() {
    BitWriter w = new BitWriter();
    // Type + magic
    w.u8(0x82);
    w.magic();

    // NBITS (LFLIMS): 3 bits -> 0, thus skip 0 per entry
    w.bits(0, 3);

    // NBITS (ACSCALE): 4 bits -> 0 (+1 => 1), then 64 entries with 1 bit each (all zeros)
    w.bits(0, 4);
    for (int i = 0; i < 64; i++) w.bits(0, 1);

    // NBITS (DCSCALE): 4 bits -> 0 (+1 => 1), then 64 entries with 1 bit each (all zeros)
    w.bits(0, 4);
    for (int i = 0; i < 64; i++) w.bits(0, 1);

    // NBMS: 9 bits -> 1 (so NBMS becomes 2)
    w.bits(1, 9);

    // BMS: NBMS * 64 entries of 8 bits each (all zeros). With NBMS=2 -> 128 bytes
    for (int n = 0; n < 2 * 64; n++) w.u8(0);

    // NEWQR/QR definition for 6 combos (qti 0..1, pli 0..2)
    for (int qti = 0; qti <= 1; qti++) {
      for (int pli = 0; pli <= 2; pli++) {
        if (qti > 0 || pli > 0) {
          w.bits(1, 1); // NEWQR = 1
        }
        // QRBMIS[qri=0] with ilog(NBMS-1) = 1 bit
        w.bits(0, 1);
        // QRSIZES[...] = (read 6 bits) + 1; choose 62 -> +1 == 63
        w.bits(62, 6);
        // QRBMIS for next qri (again 1 bit)
        w.bits(0, 1);
      }
    }

    // 80 Huffman tables: use single-leaf with TOKEN=0 (ISLEAF=1, then 5-bit token)
    for (int i = 0; i < 80; i++) {
      w.bits(1, 1);
      w.bits(0, 5);
    }

    return w.toByteArray();
  }

  private static byte[] buildSetupHeaderInvalidQiGt63() {
    BitWriter w = new BitWriter();
    // Type + magic
    w.u8(0x82);
    w.magic();

    // NBITS (LFLIMS)
    w.bits(0, 3);
    // NBITS (ACSCALE) + 64 entries
    w.bits(0, 4);
    for (int i = 0; i < 64; i++) w.bits(0, 1);
    // NBITS (DCSCALE) + 64 entries
    w.bits(0, 4);
    for (int i = 0; i < 64; i++) w.bits(0, 1);

    // NBMS: 9 bits -> 1 (so NBMS=2)
    w.bits(1, 9);
    // BMS arrays (NBMS*64 bytes)
    for (int n = 0; n < 2 * 64; n++) w.u8(0);

    // First combo only: craft qi > 63 by picking QRSIZES value 63 -> +1 => 64
    // (qti=0, pli=0): no NEWQR read here
    w.bits(0, 1); // QRBMIS with 1 bit (ilog(1) = 1)
    w.bits(63, 6); // QRSIZES -> 63 + 1 => 64 -> triggers exception
    w.bits(
        0, 1); // the second QRBMIS read (not reached logically, but consumed by the reader before
    // throw)

    // The rest of the stream is irrelevant; parser will throw when qi > 63
    return w.toByteArray();
  }

  private static byte[] buildSetupHeaderInvalidNbms() {
    BitWriter w = new BitWriter();
    // Type + magic
    w.u8(0x82);
    w.magic();

    // NBITS (LFLIMS)
    w.bits(0, 3);
    // NBITS (ACSCALE) + 64 entries
    w.bits(0, 4);
    for (int i = 0; i < 64; i++) w.bits(0, 1);
    // NBITS (DCSCALE) + 64 entries
    w.bits(0, 4);
    for (int i = 0; i < 64; i++) w.bits(0, 1);

    // NBMS value > 383 (invalid). Choose 384 which fits in 9 bits: 0b110000000
    w.bits(384, 9);

    // No further bytes required; exception is thrown during NBMS validation
    return w.toByteArray();
  }

  private static byte[] concat(byte[] a, byte[] b, byte[] c) {
    byte[] r = Arrays.copyOf(a, a.length + b.length + c.length);
    System.arraycopy(b, 0, r, a.length, b.length);
    System.arraycopy(c, 0, r, a.length + b.length, c.length);
    return r;
  }

  // Minimal big-endian bit writer for constructing headers with sub-byte fields.
  private static final class BitWriter {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();
    private int currentByte = 0;
    private int bitsUsed = 0; // 0..8

    byte[] toByteArray() {
      if (bitsUsed > 0) {
        out.write(currentByte);
        currentByte = 0;
        bitsUsed = 0;
      }
      return out.toByteArray();
    }

    void magic() {
      flushToByteBoundary();
      out.writeBytes(TheoraPacketFilter.magicNumber);
    }

    void u8(int v) {
      bits(v & 0xFF, 8);
    }

    void u16(int v) {
      bits((v >>> 8) & 0xFF, 8);
      bits(v & 0xFF, 8);
    }

    void u24(int v) {
      bits((v >>> 16) & 0xFF, 8);
      bits((v >>> 8) & 0xFF, 8);
      bits(v & 0xFF, 8);
    }

    void u32(int v) {
      bits((v >>> 24) & 0xFF, 8);
      bits((v >>> 16) & 0xFF, 8);
      bits((v >>> 8) & 0xFF, 8);
      bits(v & 0xFF, 8);
    }

    void bits(int value, int length) {
      if (length == 0) return;
      for (int i = length - 1; i >= 0; i--) {
        int bit = (value >>> i) & 1;
        writeBit(bit);
      }
    }

    private void writeBit(int bit) {
      currentByte |= (bit & 1) << (7 - bitsUsed);
      bitsUsed++;
      if (bitsUsed == 8) {
        out.write(currentByte);
        currentByte = 0;
        bitsUsed = 0;
      }
    }

    private void flushToByteBoundary() {
      if (bitsUsed > 0) {
        out.write(currentByte);
        currentByte = 0;
        bitsUsed = 0;
      }
    }
  }

  private static byte[] buildValidIdentificationHeader() {
    return buildIdentificationHeader(0, 0);
  }

  @Test
  void parse_whenIdentificationHeaderResNonZero_expectUnknownContentTypeException() {
    TheoraPacketFilter filter = new TheoraPacketFilter();
    byte[] id = buildIdentificationHeader(0, 2);
    assertThrows(UnknownContentTypeException.class, () -> filter.parse(new CodecPacket(id)));
  }
}
