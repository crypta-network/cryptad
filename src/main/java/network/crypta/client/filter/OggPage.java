package network.crypta.client.filter;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a single page of an Ogg bitstream.
 *
 * <p>An Ogg page is a framing unit that encapsulates a sequence of packet data along with header
 * fields such as the stream serial number, page sequence number and a CRC checksum. This class can
 * parse pages from a raw byte stream, expose commonly used header fields, re-lace segment tables
 * from known packet sizes, and serialize the page back to a byte array. Typical usage involves
 * repeatedly calling {@link #readPage(DataInputStream)} on a demultiplexed input until EOF.
 *
 * <p>Instances produced by the parsing constructor are effectively immutable with respect to header
 * fields exposed via accessors. The contained payload array is created by this class and is not
 * shared with the input stream. Methods that compute derived values (e.g., CRC or packets) operate
 * on the in-memory representation and do not mutate observable state unless explicitly documented.
 * This class is not thread-safe; callers should synchronize externally if the same instance is
 * accessed from multiple threads.
 *
 * <ul>
 *   <li>Responsibilities: decode page structure, verify header fields, and emit codec packets.
 *   <li>Notable behavior: careful scanning of magic header {@code "OggS"} to locate page starts.
 *   <li>Trade-offs: minimizes copying while keeping parsing logic straightforward and predictable.
 * </ul>
 *
 * @author sajack
 * @see #readPage(DataInputStream)
 * @see #asPackets()
 */
public final class OggPage {
  private static final Logger LOG = LoggerFactory.getLogger(OggPage.class);
  static final byte[] magicNumber = new byte[] {0x4f, 0x67, 0x67, 0x53};
  /*This CRC lookup table was taken from libogg. These values
   * are XORed with
   * See: http://www.ross.net/crc/download/crc_v3.txt
   */
  private static final int[] crc_lookup =
      new int[] {
        0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
        0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
        0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
        0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
        0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
        0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
        0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
        0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
        0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
        0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
        0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
        0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
        0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
        0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
        0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
        0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
        0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
        0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
        0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
        0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
        0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
        0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
        0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
        0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
        0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
        0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
        0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
        0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
        0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
        0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
        0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
        0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
        0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
        0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
        0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
        0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
        0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
        0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
        0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
        0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
        0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
        0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
        0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
        0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
        0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
        0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
        0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
        0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
        0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
        0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
        0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
        0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4
      };

  // Page header contained here
  final byte version;
  final byte headerType;
  final byte[] granuelPosition;
  final byte[] bitStreamSerial;
  final byte[] pageSequenceNumber;
  byte[] checksum = new byte[4];
  byte segments;
  byte[] segmentTable;
  byte[] payload;

  /**
   * Construct an {@code OggPage} by reading fields that immediately follow the magic {@code "OggS"}
   * marker.
   *
   * <p>The given stream must be positioned at the first header byte after the four-byte magic. The
   * constructor consumes the entire page, including the segment table and payload, and stores an
   * internal copy of those bytes. The input stream is left positioned at the first byte following
   * this page, ready to read the next page or subsequent data.
   *
   * @param input data source positioned just after the {@code "OggS"} magic; never {@code null}.
   *     The implementation reads all required header fields, segment counts, and payload bytes.
   * @throws IOException if the underlying input cannot supply the full header, segment table, or
   *     payload, or if a read operation fails due to end-of-stream or an I/O error.
   */
  public OggPage(DataInputStream input) throws IOException {
    version = input.readByte();
    LOG.debug("Version: {}", version);
    headerType = input.readByte();
    LOG.debug("Headertype: {}", headerType);
    this.granuelPosition = new byte[8];
    this.bitStreamSerial = new byte[4];
    this.pageSequenceNumber = new byte[4];
    input.readFully(granuelPosition);
    input.readFully(bitStreamSerial);
    input.readFully(pageSequenceNumber);
    input.readFully(checksum);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Checksum: {}{}{}{}",
          Integer.toHexString(byteToUnsigned(checksum[0])),
          Integer.toHexString(byteToUnsigned(checksum[1])),
          Integer.toHexString(byteToUnsigned(checksum[2])),
          Integer.toHexString(byteToUnsigned(checksum[3])));
    }
    segments = intToUnsignedByte(input.readUnsignedByte());
    segmentTable = new byte[byteToUnsigned(segments)];
    input.readFully(segmentTable);
    int payloadSize = 0;
    for (int i = 0; i < byteToUnsigned(segments); i++) {
      payloadSize += byteToUnsigned(segmentTable[i]);
    }
    payload = new byte[payloadSize];
    input.readFully(payload);
    LOG.debug("Created page with {} segments", segments);
  }

  /**
   * Construct a new page by re-packing the payload of an existing page from codec packets.
   *
   * <p>The new page inherits header fields such as version, header type, stream serial, and page
   * sequence from {@code oldPage}. The provided {@link CodecPacket} collection is concatenated into
   * the payload, and the segment table is recalculated to reflect the packet boundaries using 255
   * byte lacing rules. A fresh CRC is computed over the resulting page.
   *
   * @param oldPage source page whose immutable header fields are copied into the new instance; must
   *     not be {@code null}.
   * @param packets ordered packets that form the new payload; each packet contributes one or more
   *     segments, and empty collections result in an empty payload and segment table.
   * @throws IOException if internal buffering or stream-like operations required during assembly
   *     fail. This constructor performs no external I/O beyond in-memory processing.
   */
  public OggPage(OggPage oldPage, Collection<CodecPacket> packets) throws IOException {
    this.version = oldPage.version;
    this.headerType = oldPage.headerType;
    if (LOG.isDebugEnabled()) {
      LOG.debug("Header type: {}", Integer.toBinaryString(this.headerType));
    }
    this.granuelPosition = oldPage.granuelPosition;
    this.bitStreamSerial = oldPage.bitStreamSerial;
    this.pageSequenceNumber = oldPage.pageSequenceNumber;
    this.segments = 0;
    ArrayList<Byte> segmentSizes = new ArrayList<>();
    ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
    for (CodecPacket packet : packets) {
      int wholeSegments = packet.payload.length / 255;
      int concludingPartialSegment = packet.payload.length % 255;
      LOG.debug("Whole segments: {} Partial: {}", wholeSegments, concludingPartialSegment);
      for (int i = 0; i < wholeSegments; i++) {
        segmentSizes.add(intToUnsignedByte(255));
      }
      if (concludingPartialSegment != 0) {
        segmentSizes.add(intToUnsignedByte(concludingPartialSegment));
      }
      LOG.debug("Writing packet sized: {}", packet.payload.length);
      payloadStream.write(packet.payload);
    }
    this.segments = intToUnsignedByte(segmentSizes.size());
    this.segmentTable = new byte[byteToUnsigned(segments)];
    LOG.debug(
        "SegmentSizes len: {} SegmentTable size: {} Segments: {}",
        segmentSizes.size(),
        segmentTable.length,
        segments);
    for (int i = 0; i < segmentSizes.size(); i++) {
      this.segmentTable[i] = segmentSizes.get(i);
    }

    payloadStream.close();
    this.payload = payloadStream.toByteArray();
    LOG.debug("Payload size: {}Made of {} packets", this.payload.length, packets.size());
    this.checksum = calculateCRC();
  }

  /**
   * Advance the input to the next Ogg page start by scanning for the {@code "OggS"} magic.
   *
   * <p>This method does not consume any header bytes beyond the magic. On return, the input stream
   * is positioned just after the four-byte marker and ready for an {@link OggPage} constructor
   * call. The implementation reads one byte at a time and permits overlapping matches, which is
   * robust in the presence of stray {@code 'O'} bytes before a legitimate header.
   *
   * @param input data source to scan; must not be {@code null}. The stream is advanced to the first
   *     occurrence of the {@code "OggS"} sequence or throws upon I/O failure.
   * @throws IOException if an I/O error occurs while reading from the stream or if the stream ends
   *     before a full {@code "OggS"} sequence can be read.
   */
  public static void seekToPage(DataInputStream input) throws IOException {
    // Scan byte-by-byte for the magic sequence, allowing overlapping candidates.
    int matched = 0;
    while (true) {
      byte b = input.readByte();
      if (b == magicNumber[matched]) {
        matched++;
        if (matched == magicNumber.length) {
          return; // positioned just after "OggS"
        }
      } else {
        // If this byte itself could start a new match, keep it; otherwise reset.
        matched = (b == magicNumber[0]) ? 1 : 0;
      }
    }
  }

  /**
   * Read and parse the next {@code OggPage} from the given input stream.
   *
   * <p>This convenience method first scans forward to the next {@code "OggS"} magic using {@link
   * #seekToPage(DataInputStream)} and then constructs an {@link OggPage} starting at the version
   * byte. The resulting instance represents the complete page, and the stream is positioned at the
   * first byte after the page payload when the method returns.
   *
   * @param input a stream containing a physical Ogg bitstream; must not be {@code null}. The method
   *     advances the stream to the next page and consumes exactly that page.
   * @return a parsed page object containing header fields, segment table, and payload data; callers
   *     own the returned instance and may retain it independently of the stream lifecycle.
   * @throws IOException if scanning for the magic or reading the page fails due to I/O errors or
   *     insufficient data to complete the parse.
   */
  public static OggPage readPage(DataInputStream input) throws IOException {
    seekToPage(input);
    return new OggPage(input);
  }

  /**
   * Check header sanity and verify this page's CRC checksum for integrity.
   *
   * <p>The method validates the version field (must be zero for current Ogg streams) and compares
   * the stored checksum with a computed CRC over the page with the checksum bytes cleared as per
   * Ogg format rules.
   *
   * @return {@code true} when the version is acceptable and the calculated CRC matches the stored
   *     value; {@code false} otherwise.
   */
  public boolean headerValid() {
    if (version != 0) return false;
    return Arrays.equals(checksum, calculateCRC());
  }

  /**
   * Determine whether the first packet in this page is a continuation from the previous page.
   *
   * <p>This inspects the least significant bit of the header type flag. When set, the first packet
   * of the payload begins in a prior page and continues here; otherwise, the first packet starts at
   * the first segment of this page.
   *
   * @return {@code true} when the continuation flag is set; {@code false} when the first packet
   *     starts within this page.
   */
  public boolean isPacketContinued() {
    if (LOG.isDebugEnabled()) LOG.debug("Packet continued: {}", headerType & 0x1);
    return (headerType & 0x01) == 1;
  }

  /**
   * Determine whether this page contains the final packet of the stream.
   *
   * <p>This inspects the end-of-stream bit in the header type field. It does not validate that the
   * page is actually the last in the physical bitstream; it only reports the header intent.
   *
   * @return {@code true} when the end-of-stream flag is set on this page; otherwise {@code false}.
   */
  public boolean isFinalPacket() {
    return (headerType & 0x04) == 4;
  }

  /**
   * Serialize this page to a newly allocated byte array including header and payload.
   *
   * <p>The resulting array begins with the magic {@code "OggS"}, followed by all header fields, the
   * segment table, and the entire payload. The returned array is independent of the internal state
   * and may be retained or modified by callers without affecting this instance.
   *
   * @return a new array containing a complete on-wire representation of this page, suitable for
   *     persistence or transmission.
   */
  public byte[] toArray() {
    ByteBuffer bb = ByteBuffer.allocate(27 + byteToUnsigned(segments) + payload.length);
    bb.put(magicNumber);
    bb.put(version);
    bb.put(headerType);
    bb.put(granuelPosition);
    bb.put(bitStreamSerial);
    bb.put(pageSequenceNumber);
    bb.put(checksum);
    bb.put(segments);
    bb.put(segmentTable);
    bb.put(payload);
    return bb.array();
  }

  /**
   * Get the stream serial number for this page.
   *
   * <p>The value identifies the logical Ogg bitstream to which this page belongs. It is extracted
   * directly from the page header and returned as a signed 32-bit integer using the native byte
   * order of {@link ByteBuffer#getInt()} for the stored four bytes.
   *
   * @return the stream serial number as a 32-bit signed integer, as stored in the header.
   */
  public int getSerial() {
    ByteBuffer bb = ByteBuffer.wrap(bitStreamSerial);
    return bb.getInt();
  }

  /**
   * Get this page's sequence number within its logical stream.
   *
   * <p>The page sequence is stored in little-endian order in the header. This method returns the
   * integer value with bytes reversed to match typical host-endian usage.
   *
   * @return the 32-bit page sequence number with byte order corrected for typical host usage.
   */
  public int getPageNumber() {
    ByteBuffer bb = ByteBuffer.wrap(pageSequenceNumber);
    return Integer.reverseBytes(bb.getInt());
  }

  /**
   * Calculate this page's 32-bit CRC checksum according to the Ogg specification.
   *
   * <p>The calculation serializes the page with its checksum field zeroed, then computes the CRC
   * using a standard lookup table compatible with libogg. The resulting bytes are ordered least
   * significant first, matching the on-wire representation.
   *
   * @return a four-byte array containing the CRC value in little-endian order; a new array is
   *     created for each call.
   */
  public byte[] calculateCRC() {
    byte[] array = toArray();
    // Strip out the checksum bytes
    array[22] = 0;
    array[23] = 0;
    array[24] = 0;
    array[25] = 0;
    int crcReg = 0;
    for (byte b : array) {
      /*Ugly, no? This line was taken from jorbis, which, I'd bet money, adapted it to java from libogg,
       * which in turn took it from http://www.ross.net/crc/download/crc_v3.txt */
      crcReg = (crcReg << 8) ^ crc_lookup[((crcReg >>> 24) & 0xff) ^ (b & 0xff)];
    }
    return new byte[] {
      (byte) crcReg, (byte) (crcReg >>> 8), (byte) (crcReg >>> 16), (byte) (crcReg >>> 24)
    };
  }

  /**
   * Rewrite the segment table (lacing) for this page using the provided packet sizes.
   *
   * <p>Each packet is expressed as one or more 255-byte segments, with a final partial segment when
   * the size is not an exact multiple of 255. When {@code packetSizes} is {@code null}, the method
   * assumes a single packet that spans the entire payload. This method updates only in-memory
   * structures for this page and does not alter payload bytes.
   *
   * @param packetSizes ordered list of packet lengths in bytes; may be {@code null} to indicate a
   *     single packet covering the full payload. Values must be non-negative and fit within the
   *     payload size.
   */
  public void recalculateSegmentLacing(List<Integer> packetSizes) {
    /*Will packets ever need to be expanded? Right now we're just cutting
     * stuff away, but if we need to write stuff, we run the risk of overflowing
     * past the hard limit of 255 packets, and will need to create a continuing page
     */
    List<Integer> sizes = ensurePacketSizes(packetSizes);
    segments = intToUnsignedByte(computeTotalSegments(sizes));
    if (LOG.isDebugEnabled()) LOG.debug("Segments {}", segments);
    segmentTable = buildSegmentTable(sizes, segments);
  }

  private List<Integer> ensurePacketSizes(List<Integer> packetSizes) {
    if (packetSizes != null) return new ArrayList<>(packetSizes);
    List<Integer> sizes = new ArrayList<>(1);
    sizes.add(payload.length);
    return sizes;
  }

  private int computeTotalSegments(Iterable<Integer> packetSizes) {
    int total = 0;
    for (int packet : packetSizes) {
      total += packet / 255 + (packet % 255 == 0 ? 0 : 1);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Size of current packet: {} Current number of segments: {} Number of whole segments"
                + " belonging to this packet: {} Remaining bytes {}",
            packet,
            total,
            packet / 255,
            packet % 255);
      }
    }
    return total;
  }

  private byte[] buildSegmentTable(Iterable<Integer> packetSizes, int segmentCount) {
    byte[] table = new byte[segmentCount];
    int segment = 0;
    for (int packet : packetSizes) {
      if (LOG.isDebugEnabled()) LOG.debug("Setting segments for packet sized {}", packet);
      for (int packetSegment = 0; packetSegment < packet / 255; packetSegment++) {
        if (LOG.isDebugEnabled()) LOG.debug("Setting segment {} to full.", segment);
        table[segment] = intToUnsignedByte(255);
        segment++;
      }
      int remainder = packet % 255;
      if (remainder != 0) {
        if (LOG.isDebugEnabled()) LOG.debug("Partially filling segment {}", segment);
        table[segment] = intToUnsignedByte(remainder);
        segment++;
      }
    }
    return table;
  }

  /**
   * Interpret the payload using the current segment table and return codec packets.
   *
   * <p>The method walks the lacing values, concatenating full 255-byte segments until a packet
   * boundary is encountered (a segment value other than 255 or the final segment of the page). The
   * returned collection preserves order and contains newly allocated packet payload arrays.
   *
   * @return a collection of {@link CodecPacket} instances representing packets contained in this
   *     page; the collection and its packet arrays are independent of the page.
   */
  public Collection<CodecPacket> asPackets() {
    LOG.debug("Creating packets for {} segments", byteToUnsigned(segments));
    ArrayList<CodecPacket> packets = new ArrayList<>();
    int bytesParsed = 0;
    int packetSize = 0;
    for (int i = 0; i < segmentTable.length; i++) {
      if ((byteToUnsigned(segmentTable[i]) % 255 != 0)
          || byteToUnsigned(segmentTable[i]) == 0
          || i == segmentTable.length - 1) {
        packetSize += byteToUnsigned(segmentTable[i]);
        byte[] packetPayload = new byte[packetSize];
        System.arraycopy(payload, bytesParsed, packetPayload, 0, packetSize);

        bytesParsed += packetSize;
        packets.add(new CodecPacket(packetPayload));
        packetSize = 0;
      } else {
        packetSize += 255;
      }
    }
    return packets;
  }

  private static int byteToUnsigned(byte input) {
    return (input & 0xff);
  }

  private static byte intToUnsignedByte(int input) {
    return (byte) (input & 0xff);
  }
}
