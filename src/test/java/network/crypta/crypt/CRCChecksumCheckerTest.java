package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.CRC32;
import network.crypta.support.Fields;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.PrependLengthOutputStream;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CRCChecksumCheckerTest {

  private final CRCChecksumChecker checker = new CRCChecksumChecker();

  @Test
  void checksumLength_whenCalled_returnsFour() {
    assertEquals(4, checker.checksumLength());
  }

  @Test
  void getChecksumTypeID_whenCalled_returnsCrcId() {
    assertEquals(ChecksumChecker.CHECKSUM_CRC, checker.getChecksumTypeID());
  }

  @Test
  void generateChecksum_whenKnownData_matchesCRC32LittleEndian() {
    byte[] data = new byte[] {1, 2, 3, 4, 5};
    CRC32 crc = new CRC32();
    crc.update(data, 0, data.length);
    byte[] expected = Fields.intToBytes((int) crc.getValue());

    byte[] actual = checker.generateChecksum(data, 0, data.length);
    assertArrayEquals(expected, actual);
  }

  @Test
  void appendChecksum_whenPayload_returnsPayloadThenChecksum() {
    byte[] payload = new byte[] {10, 11, 12};
    CRC32 crc = new CRC32();
    crc.update(payload, 0, payload.length);
    byte[] expectedCrc = Fields.intToBytes((int) crc.getValue());

    byte[] out = checker.appendChecksum(payload);
    byte[] outPayload = new byte[payload.length];
    System.arraycopy(out, 0, outPayload, 0, payload.length);
    byte[] outCrc = new byte[4];
    System.arraycopy(out, payload.length, outCrc, 0, 4);

    assertArrayEquals(payload, outPayload);
    assertArrayEquals(expectedCrc, outCrc);
  }

  @Test
  void checkChecksum_whenMatching_returnsTrue() {
    byte[] data = new byte[] {42, 43, 44, 45};
    byte[] checksum = checker.generateChecksum(data, 0, data.length);
    assertTrue(checker.checkChecksum(data, 0, data.length, checksum));
  }

  @Test
  void checkChecksum_whenMismatched_returnsFalse() {
    byte[] data = new byte[] {42, 43, 44, 45};
    byte[] checksum = new byte[] {0, 0, 0, 0};
    assertFalse(checker.checkChecksum(data, 0, data.length, checksum));
  }

  @Test
  void checkChecksum_whenWrongLength_throwsIllegalArgumentException() {
    byte[] data = new byte[] {1, 2, 3};
    byte[] bad = new byte[] {1, 2, 3}; // length 3 instead of 4
    assertThrows(
        IllegalArgumentException.class, () -> checker.checkChecksum(data, 0, data.length, bad));
  }

  @Test
  void checksumWriter_whenClosed_appendsChecksumAndSkipsPrefixBytes() throws IOException {
    byte[] payload = new byte[32];
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) (i * 7 + 3);
    }
    int prefix = 5; // should be excluded from checksum

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (OutputStream os = checker.checksumWriter(bos, prefix)) {
      os.write(payload);
    }

    byte[] written = bos.toByteArray();
    byte[] writtenPayload = new byte[payload.length];
    System.arraycopy(written, 0, writtenPayload, 0, payload.length);
    byte[] writtenCrc = new byte[4];
    System.arraycopy(written, payload.length, writtenCrc, 0, 4);

    // Payload is forwarded unmodified.
    assertArrayEquals(payload, writtenPayload);

    // Compute expected CRC over bytes after the skipped prefix.
    CRC32 crc = new CRC32();
    crc.update(payload, prefix, payload.length - prefix);
    byte[] expectedTrailer = Fields.intToBytes((int) crc.getValue());
    assertArrayEquals(expectedTrailer, writtenCrc);
  }

  @Test
  void copyAndStripChecksum_whenValidChecksum_writesOnlyPayload() throws Exception {
    byte[] payload = new byte[1000];
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) (i * 13 + 5);
    }
    CRC32 crc = new CRC32();
    crc.update(payload, 0, payload.length);
    byte[] trailer = Fields.intToBytes((int) crc.getValue());

    byte[] source = new byte[payload.length + trailer.length];
    System.arraycopy(payload, 0, source, 0, payload.length);
    System.arraycopy(trailer, 0, source, payload.length, trailer.length);

    ByteArrayOutputStream dest = new ByteArrayOutputStream();
    checker.copyAndStripChecksum(new ByteArrayInputStream(source), dest, payload.length);

    assertArrayEquals(payload, dest.toByteArray());
  }

  @Test
  void copyAndStripChecksum_whenChecksumMismatch_throwsAndDestinationHasPayload() {
    byte[] payload = new byte[257];
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) (i * 11 + 1);
    }
    byte[] badTrailer = new byte[] {0, 0, 0, 0};

    byte[] source = new byte[payload.length + badTrailer.length];
    System.arraycopy(payload, 0, source, 0, payload.length);
    System.arraycopy(badTrailer, 0, source, payload.length, badTrailer.length);

    ByteArrayOutputStream dest = new ByteArrayOutputStream();
    assertThrows(
        ChecksumFailedException.class,
        () -> checker.copyAndStripChecksum(new ByteArrayInputStream(source), dest, payload.length));
    // Payload bytes are already forwarded before verification.
    assertArrayEquals(payload, dest.toByteArray());
  }

  @Test
  void copyAndStripChecksum_whenLengthMinusOne_copiesAllBytesWithoutVerification()
      throws Exception {
    byte[] payloadOnly = new byte[128];
    for (int i = 0; i < payloadOnly.length; i++) {
      payloadOnly[i] = (byte) (i * 17 + 9);
    }

    ByteArrayOutputStream dest = new ByteArrayOutputStream();
    checker.copyAndStripChecksum(new ByteArrayInputStream(payloadOnly), dest, -1);
    assertArrayEquals(payloadOnly, dest.toByteArray());
  }

  @Test
  void copyAndStripChecksum_whenPrematureEof_throwsEOFException() {
    byte[] fewer = new byte[10];
    ByteArrayInputStream src = new ByteArrayInputStream(fewer);
    ByteArrayOutputStream dest = new ByteArrayOutputStream();
    assertThrows(EOFException.class, () -> checker.copyAndStripChecksum(src, dest, 20));
  }

  @Test
  void checksumWriterWithLengthNoClose_whenClosed_canWriteAndReadBackConsecutiveRecords()
      throws Exception {
    byte[] firstPayload = new byte[] {1, 2, 3};
    byte[] secondPayload = new byte[] {9, 8, 7, 6};
    ByteArrayOutputStream sink = new ByteArrayOutputStream();

    try (PrependLengthOutputStream os =
        checker.checksumWriterWithLengthNoClose(sink, new ArrayBucketFactory())) {
      os.write(firstPayload);
    }
    try (PrependLengthOutputStream os =
        checker.checksumWriterWithLengthNoClose(sink, new ArrayBucketFactory())) {
      os.write(secondPayload);
    }

    byte[] encoded = sink.toByteArray();
    DataInputStream source = new DataInputStream(new ByteArrayInputStream(encoded));
    try (InputStream first =
            checker.checksumReaderWithLength(source, new ArrayBucketFactory(), encoded.length);
        InputStream second =
            checker.checksumReaderWithLength(source, new ArrayBucketFactory(), encoded.length)) {
      assertArrayEquals(firstPayload, first.readAllBytes());
      assertArrayEquals(secondPayload, second.readAllBytes());
    }
    assertEquals(-1, source.read());
  }

  @Test
  void readAndChecksum_whenValid_fillsBuffer() throws Exception {
    byte[] payload = new byte[] {9, 8, 7, 6, 5};
    CRC32 crc = new CRC32();
    crc.update(payload, 0, payload.length);
    byte[] trailer = Fields.intToBytes((int) crc.getValue());

    byte[] source = new byte[payload.length + trailer.length];
    System.arraycopy(payload, 0, source, 0, payload.length);
    System.arraycopy(trailer, 0, source, payload.length, trailer.length);

    byte[] buf = new byte[payload.length];
    checker.readAndChecksum(
        new DataInputStream(new ByteArrayInputStream(source)), buf, 0, payload.length);
    assertArrayEquals(payload, buf);
  }

  @Test
  void readAndChecksum_whenChecksumMismatch_zerosBufferAndThrows() {
    byte[] payload = new byte[] {1, 2, 3, 4};
    byte[] badTrailer = new byte[] {0, 0, 0, 0};
    byte[] source = new byte[payload.length + badTrailer.length];
    System.arraycopy(payload, 0, source, 0, payload.length);
    System.arraycopy(badTrailer, 0, source, payload.length, badTrailer.length);

    byte[] buf = new byte[payload.length];
    assertThrows(
        ChecksumFailedException.class,
        () ->
            checker.readAndChecksum(
                new DataInputStream(new ByteArrayInputStream(source)), buf, 0, payload.length));
    // Buffer region must be zeroed on checksum failure.
    for (byte b : buf) {
      assertEquals(0, b);
    }
  }

  @Test
  void readAndChecksum_whenMissingChecksum_throwsEOFExceptionAndLeavesBuffer() {
    byte[] payload = new byte[] {100, 101, 102};
    // No checksum bytes provided
    byte[] source = payload.clone();

    byte[] buf = new byte[payload.length];
    // Expect EOFException from DataInput.readFully on checksum read.
    assertThrows(
        EOFException.class,
        () ->
            checker.readAndChecksum(
                new DataInputStream(new ByteArrayInputStream(source)), buf, 0, payload.length));
    // Buffer remains containing the payload read before failure (implementation detail, but stable
    // here).
    assertArrayEquals(payload, buf);
  }

  @Test
  void readAndChecksum_whenZeroLengthPayload_readsChecksumOnlyAndSucceeds() throws Exception {
    byte[] empty = new byte[0];
    CRC32 crc = new CRC32();
    crc.update(empty, 0, 0);

    byte[] source =
        Fields.intToBytes((int) crc.getValue()); // payload length 0 → only checksum presents
    byte[] buf = new byte[0];
    checker.readAndChecksum(new DataInputStream(new ByteArrayInputStream(source)), buf, 0, 0);
    assertEquals(0, buf.length);
  }
}
