package network.crypta.client.filter;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.function.IntPredicate;
import network.crypta.support.io.BitInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Filters and validates Ogg Theora codec packets and enforces the required header sequence
 * (Identification → Comment → Setup) before passing through subsequent frame packets unchanged.
 *
 * <p>This filter consumes the bit-level structure of the Theora stream headers using {@link
 * network.crypta.support.io.BitInputStream} and performs a series of specification-driven checks
 * (field ranges, magic prefix, header ordering). It is intended to be used in client-side pipelines
 * that need to quickly reject malformed or unsupported streams while leaving valid frame data
 * intact. Typical usage is to feed incoming packets in order; the filter maintains minimal internal
 * state to track which header is expected next, and after all three headers are accepted it treats
 * subsequent packets as video frames and returns them unchanged.
 *
 * <p>Thread-safety: instances are not designed for concurrent use. Callers should either confine an
 * instance to a single decoding flow or provide external synchronization. The class does not retain
 * references to packet payloads beyond the duration of the call and does not modify the provided
 * arrays. Failure conditions are surfaced as {@link IOException} or unchecked exceptions specific
 * to unknown or malformed content.
 *
 * <ul>
 *   <li>Validates header types and the {@code theora} magic number prefix.
 *   <li>Checks identification fields and setup tables for basic bounds.
 *   <li>Rewrites the comment header to an empty vendor/comments block when appropriate.
 *   <li>Passes through frame packets without modification after headers are verified.
 * </ul>
 *
 * @see CodecPacketFilter
 * @see network.crypta.client.filter.CodecPacket
 */
public class TheoraPacketFilter implements CodecPacketFilter {
  private static final Logger LOG = LoggerFactory.getLogger(TheoraPacketFilter.class);

  static final byte[] magicNumber = new byte[] {'t', 'h', 'e', 'o', 'r', 'a'};

  private static final String HEADER_IDENTIFICATION = "Identification";
  private static final String HEADER_SETUP = "Setup";

  enum Packet {
    IDENTIFICATION_HEADER,
    COMMENT_HEADER,
    SETUP_HEADER,
    FRAME
  }

  private Packet expectedPacket = Packet.IDENTIFICATION_HEADER;

  /**
   * Constructs a new filter with initial state expecting the Theora Identification header. The
   * instance maintains minimal state only to track which header should arrive next; it does not
   * allocate large buffers and performs validation directly over the provided packet payloads.
   *
   * <p>Use a fresh instance per decoding pipeline when processing multiple streams concurrently. A
   * single instance is intended to consume packets from one logical stream in order, starting at
   * the first header. No external resources are acquired during construction, and there are no side
   * effects.
   */
  public TheoraPacketFilter() {
    // Intentionally empty: the filter only tracks the expected header order and
    // performs validation on provided packet payloads; no initialization is required.
  }

  /**
   * Parses and validates a single codec packet in sequence, enforcing Theora header ordering and
   * bounds. This method is stateful across calls: it expects the Identification header first,
   * followed by the Comment and Setup headers, then treats subsequent packets as frames.
   *
   * <p>On the Comment header, the implementation may return a new packet instance containing an
   * empty vendor string and zero user comments, which is functionally equivalent and simplifies
   * downstream handling. For frame packets, the packet is returned unchanged. If the input violates
   * structural constraints (e.g., magic number mismatch or out-of-range field), an exception is
   * thrown. The method is idempotent only for frames; header parsing advances internal state.
   *
   * <pre>{@code
   * // Example: feed packets in decoding order
   * CodecPacketFilter f = new TheoraPacketFilter();
   * var out = f.parse(incomingPacket);
   * }</pre>
   *
   * @param packet the input {@link CodecPacket} to validate and possibly normalize; must contain a
   *     non-null payload byte array with the encoded Theora data for the current step.
   * @return the same {@link CodecPacket} instance for most inputs; on the Comment header a new
   *     packet carrying an empty vendor string and zero comments may be returned instead.
   * @throws IOException if reading the bitstream fails or the packet cannot be fully consumed due
   *     to I/O problems; malformed content may trigger unchecked exceptions as appropriate.
   */
  @Override
  @SuppressWarnings("StatementSwitchToExpressionSwitch")
  public CodecPacket parse(CodecPacket packet) throws IOException {
    // Assemble the Theora packets https://www.theora.org/doc/Theora.pdf
    // https://github.com/xiph/theora/blob/master/doc/spec/spec.tex
    BitInputStream input = new BitInputStream(new ByteArrayInputStream(packet.payload));
    switch (expectedPacket) {
      case IDENTIFICATION_HEADER: // must be first
        LOG.debug("IDENTIFICATION_HEADER");
        verifyIdentificationHeader(input);
        expectedPacket = Packet.COMMENT_HEADER;
        break;

      case COMMENT_HEADER: // must be second
        LOG.debug("COMMENT_HEADER");
        verifyTypeAndHeader("Comment", input, 0x81); // expected -127
        expectedPacket = Packet.SETUP_HEADER;
        return constructCommentHeaderWithEmptyVendorStringAndComments();

      case SETUP_HEADER: // must be third
        LOG.debug("SETUP_HEADER");
        verifySetupHeader(input);
        expectedPacket = Packet.FRAME;
        break;

      case FRAME:
        // fall-through: frames are passed through unchanged
        break;
    }

    return packet;
  }

  private void verifyIdentificationHeader(BitInputStream input) throws IOException {
    verifyTypeAndHeader(HEADER_IDENTIFICATION, input, 0x80); // expected -128

    checkHeaderField(HEADER_IDENTIFICATION, "VMAJ", input, 8, v -> v == 3);
    checkHeaderField(HEADER_IDENTIFICATION, "VMIN", input, 8, v -> v == 2);
    input.skip(8); // skip VREV
    int fmbw = checkHeaderField(HEADER_IDENTIFICATION, "FMBW", input, 16, v -> v > 0);
    int fmbh = checkHeaderField(HEADER_IDENTIFICATION, "FMBH", input, 16, v -> v > 0);
    checkHeaderField(HEADER_IDENTIFICATION, "PICW", input, 24, v -> v <= fmbw * 16);
    checkHeaderField(HEADER_IDENTIFICATION, "PICH", input, 24, v -> v <= fmbh * 16);
    checkHeaderField(HEADER_IDENTIFICATION, "PICX", input, 8, x -> x <= fmbw * 16 - x);
    checkHeaderField(HEADER_IDENTIFICATION, "PICY", input, 8, x -> x <= fmbh * 16 - x);
    checkHeaderField(HEADER_IDENTIFICATION, "FRN", input, 32, v -> v > 0);
    checkHeaderField(HEADER_IDENTIFICATION, "FRD", input, 32, v -> v > 0);
    input.skip(48); // skip PARN and PARD
    checkHeaderField(HEADER_IDENTIFICATION, "CS", input, 8, v -> v == 0 || v == 1 || v == 2);
    input.skip(35); // skip NOMBR, QUAL and KFGSHIFT
    checkHeaderField(HEADER_IDENTIFICATION, "PF", input, 2, v -> v != 1);
    checkHeaderField(HEADER_IDENTIFICATION, "Res", input, 3, v -> v == 0);
  }

  private void verifySetupHeader(BitInputStream input) throws IOException {
    verifyTypeAndHeader(HEADER_SETUP, input, 0x82); // expected -126

    readQuantizationTables(input);
    readBlockMappingAndQuantRanges(input);
    readHuffmanTables(input);
    checkRedundantBits(input);
  }

  private void readQuantizationTables(BitInputStream input) throws IOException {
    int nbBits = input.readInt(3);
    for (int i = 0; i < 64; i++) {
      input.skip(nbBits); // skip LFLIMS[i]
    }

    nbBits = input.readInt(4) + 1;
    for (int i = 0; i < 64; i++) {
      input.skip(nbBits); // skip ACSCALE[i]
    }

    nbBits = input.readInt(4) + 1;
    for (int i = 0; i < 64; i++) {
      input.skip(nbBits); // skip DCSCALE[i]
    }
  }

  private void readBlockMappingAndQuantRanges(BitInputStream input) throws IOException {
    int nbms = checkHeaderField(HEADER_SETUP, "NBMS", input, 9, v -> v <= 383) + 1;

    readBmsTables(input, nbms);
    readQuantizationRangesForAllCombos(input, nbms);
  }

  private void readBmsTables(BitInputStream input, int nbms) throws IOException {
    int[][] bms = new int[nbms][64];
    for (int i = 0; i < bms.length; i++) {
      for (int j = 0; j < bms[i].length; j++) {
        bms[i][j] = input.readInt(8);
      }
    }
  }

  private void readQuantizationRangesForAllCombos(BitInputStream input, int nbms)
      throws IOException {
    for (int qti = 0; qti <= 1; qti++) {
      for (int pli = 0; pli <= 2; pli++) {
        readQuantizationRangeForCombo(input, nbms, qti, pli);
      }
    }
  }

  private void readQuantizationRangeForCombo(BitInputStream input, int nbms, int qti, int pli)
      throws IOException {
    int newQr = 1;
    if (qti > 0 || pli > 0) {
      newQr = input.readBit();
    }

    int[][] nqrs = new int[2][3];
    int[][][] qrSizes = new int[2][3][63];
    int[][][] qrbmis = new int[2][3][64];
    if (newQr == 0) {
      handleReuseQuantRanges(input, qti, pli, nqrs, qrSizes, qrbmis);
    } else {
      if (newQr != 1) {
        throw new UnknownContentTypeException("SetupHeader NEWQR: " + newQr + "(MUST be 0|1)");
      }
      readNewQuantRanges(input, nbms, qti, pli, nqrs, qrSizes, qrbmis);
    }
  }

  private void handleReuseQuantRanges(
      BitInputStream input, int qti, int pli, int[][] nqrs, int[][][] qrSizes, int[][][] qrbmis)
      throws IOException {
    int qtj;
    int plj;
    int rpQr = 0;
    if (qti > 0) {
      rpQr = input.readBit();
    }

    if (rpQr == 1) {
      qtj = qti - 1;
      plj = pli;
    } else {
      qtj = (3 * qti + pli - 1) / 3;
      plj = (pli + 2) % 3;
    }

    nqrs[qti][pli] = nqrs[qtj][plj];
    qrSizes[qti][pli] = qrSizes[qtj][plj];
    qrbmis[qti][pli] = qrbmis[qtj][plj];
  }

  private void readNewQuantRanges(
      BitInputStream input,
      int nbms,
      int qti,
      int pli,
      int[][] nqrs,
      int[][][] qrSizes,
      int[][][] qrbmis)
      throws IOException {
    int qri = 0;
    int qi = 0;

    qrbmis[qti][pli][qri] = input.readInt(ilog(nbms - 1));

    if (qrbmis[qti][pli][qri] >= nbms) {
      throw new UnknownContentTypeException(
          "SetupHeader (QRBMIS[qti][pli][qri]: "
              + qrbmis[qti][pli][qri]
              + ") >= (NBMS: "
              + nbms
              + ") The stream is undecodable.");
    }

    do {
      qrSizes[qti][pli][qri] = input.readInt(ilog(62 - qi)) + 1;

      qi = qi + qrSizes[qti][pli][qri];
      qri++;

      qrbmis[qti][pli][qri] = input.readInt(ilog(nbms - 1));

      if (qi > 63) {
        throw new UnknownContentTypeException(
            "SetupHeader qi: " + qi + " > 63 The stream is undecodable.");
      }
    } while (qi < 63);

    nqrs[qti][pli] = qri;
  }

  private void readHuffmanTables(BitInputStream input) throws IOException {
    int[][] hts = new int[80][0];
    for (int hti = 0; hti < 80; hti++) {
      hts[hti] = readHuffmanTable(0, hts[hti], input);
    }
  }

  private void checkRedundantBits(BitInputStream input) throws IOException {
    try {
      input.readBit();
      LOG.debug("SETUP_HEADER contains redundant bits");
    } catch (EOFException _) { // should be eof
      // expected: no extra bits
    }
  }

  // The header packets begin with the header type and the magic number. Validate both.
  private void verifyTypeAndHeader(String headerName, BitInputStream input, int expectedHeaderType)
      throws IOException {
    try {
      checkHeaderField(headerName, "type", input, 8, v -> v == expectedHeaderType);
    } catch (UnknownContentTypeException e) {
      throw new UnknownContentTypeException(e.getType() + "; expected: " + expectedHeaderType);
    }

    byte[] magicHeader = new byte[magicNumber.length];
    input.readFully(magicHeader);
    if (!Arrays.equals(magicNumber, magicHeader)) {
      throw new UnknownContentTypeException(
          "Packet magicHeader: "
              + Arrays.toString(magicHeader)
              + "; expected: "
              + Arrays.toString(magicNumber));
    }
  }

  private int checkHeaderField(
      String headerName,
      String fieldName,
      BitInputStream input,
      int sizeInBits,
      IntPredicate validator)
      throws IOException {
    int value = input.readInt(sizeInBits);
    if (!validator.test(value)) {
      throw new UnknownContentTypeException(headerName + "Header " + fieldName + ": " + value);
    }
    return value;
  }

  private CodecPacket constructCommentHeaderWithEmptyVendorStringAndComments() {
    // headerType - magicNumber - vendorStringLength (4 bytes, value 0) - userCommentsNumber (4
    // bytes, value 0)
    byte[] emptyCommentHeader = new byte[magicNumber.length + 9];
    emptyCommentHeader[0] = (byte) 0x81;
    System.arraycopy(magicNumber, 0, emptyCommentHeader, 1, magicNumber.length);
    return new CodecPacket(emptyCommentHeader);
  }

  // The minimum number of bits required to store a positive integer `a` in
  // two’s complement notation, or 0 for a non-positive integer 'a'.
  private int ilog(int a) {
    if (a <= 0) {
      return 0;
    }

    return 32 - Integer.numberOfLeadingZeros(a);
  }

  private int[] readHuffmanTable(int hbitsLength, int[] hts, BitInputStream input)
      throws IOException {
    if (hbitsLength > 32) {
      throw new UnknownContentTypeException(
          "HBITS.length = "
              + hbitsLength
              + "; HBITS is longer than 32 bits in length - The stream is undecodable.");
    }

    int isLeaf = input.readBit();
    if (isLeaf == 1) {
      if (hts.length == 32) {
        throw new UnknownContentTypeException(
            "HTS[hti] = "
                + Arrays.toString(hts)
                + "; HTS[hti] is already 32 - The stream is undecodable.");
      }
      int token = input.readInt(5);

      hts = Arrays.copyOf(hts, hts.length + 1);
      hts[hts.length - 1] = token;
    } else {
      int subTreeHbitsLength = hbitsLength + 1;
      readHuffmanTable(subTreeHbitsLength, hts, input);
      readHuffmanTable(subTreeHbitsLength, hts, input);
    }

    return hts;
  }
}
