package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.StorageFormatException;

/**
 * Parses and validates persisted splitfile storage headers for resume.
 *
 * <p>This reader verifies the footer magic, checksum type, flags, and version before parsing the
 * basic settings block via {@link SplitFileFetcherStorageSettingsCodec}. It isolates byte-level
 * parsing and checksum validation from the storage orchestrator so that callers can resume only
 * from storage that passes structural checks.
 *
 * <p>All methods are static and side-effect free aside from reading from the supplied buffer. The
 * reader assumes the caller has already opened the storage and provided the correct checksum
 * configuration. It does not synchronize on the buffer, so callers must ensure exclusive access if
 * they read concurrently.
 *
 * <ul>
 *   <li>Validates footer magic, version, and checksum type.
 *   <li>Computes the basic settings block location with checksum validation.
 *   <li>Decodes persisted settings used to rebuild the storage state.
 * </ul>
 */
final class SplitFileFetcherStorageResumeReader {
  /** Prevents instantiation; all operations are exposed as static helpers. */
  private SplitFileFetcherStorageResumeReader() {}

  /**
   * Reads persisted settings from the footer and validates versioning metadata.
   *
   * <p>The method performs a fixed sequence of checks: minimum length, footer magic, version,
   * checksum type, flags, and the check-summed basic settings length. It then reads the settings
   * payload and parses it into a {@link ParsedBasicSettings} instance. The method is deterministic
   * and does not alter the buffer contents.
   *
   * <pre>{@code
   * ParsedBasicSettings settings =
   *     SplitFileFetcherStorageResumeReader.readParsedSettings(
   *         raf, checker, checksumLength, raf.size(), completeViaTruncation);
   * }</pre>
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param checksumChecker checker used to validate the footer checksums and lengths
   * @param checksumLength checksum length in bytes used by the storage format
   * @param rafLength total length of the backing buffer in bytes
   * @param completeViaTruncation true when truncation represents completion
   * @return parsed settings derived from the persisted footer and basic settings
   * @throws IOException when the underlying buffer cannot be read
   * @throws StorageFormatException when the footer metadata or checksums are invalid
   */
  static ParsedBasicSettings readParsedSettings(
      LockableRandomAccessBuffer raf,
      ChecksumChecker checksumChecker,
      int checksumLength,
      long rafLength,
      boolean completeViaTruncation)
      throws IOException, StorageFormatException {

    ensureMinLength(rafLength);
    validateMagic(raf, rafLength);
    byte[] versionBuf = readVersionBytes(raf, rafLength);
    int parsedVersion = parseInt(versionBuf);
    if (parsedVersion != SplitFileFetcherStorage.VERSION)
      throw new StorageFormatException("Wrong version " + parsedVersion);
    byte[] checksumTypeBuf = readChecksumTypeBytes(raf, rafLength);
    validateChecksumType(checksumTypeBuf);
    byte[] flagsBuf = readFlagsBytes(raf, rafLength);
    validateFlags(flagsBuf);

    BasicSettingsInfo basicInfo =
        readBasicSettingsLocation(
            raf, rafLength, checksumChecker, checksumLength, flagsBuf, checksumTypeBuf, versionBuf);
    byte[] basicSettingsBuffer =
        readChecksummed(raf, checksumChecker, checksumLength, basicInfo.offset, basicInfo.length);
    return SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
        basicSettingsBuffer, basicInfo.offset, completeViaTruncation, rafLength);
  }

  /**
   * Verifies the backing buffer is long enough to contain a footer magic value.
   *
   * <p>The minimum length is eight bytes because the footer magic is a {@code long} stored at the
   * end of the file. Shorter buffers cannot contain a valid footer and are rejected early.
   *
   * @param length total buffer length in bytes
   * @throws StorageFormatException when the buffer is shorter than the footer magic size
   */
  private static void ensureMinLength(long length) throws StorageFormatException {
    if (length < 8) throw new StorageFormatException("Too short");
  }

  /**
   * Reads and validates the footer magic from the end of the buffer.
   *
   * <p>The method reads eight bytes from the end of the file and compares them to the expected
   * magic constant. A mismatch indicates the storage is not a splitfile resume buffer.
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param length total length of the backing buffer in bytes
   * @throws IOException when the buffer cannot be read
   * @throws StorageFormatException when the footer magic does not match
   */
  private static void validateMagic(LockableRandomAccessBuffer raf, long length)
      throws IOException, StorageFormatException {
    byte[] buf = new byte[8];
    raf.pread(length - 8, buf, 0, 8);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
    if (dis.readLong() != SplitFileFetcherStorage.END_MAGIC)
      throw new StorageFormatException("Wrong magic bytes");
  }

  /**
   * Parses a four-byte big-endian integer from the provided buffer.
   *
   * @param buf four-byte array containing the serialized integer value
   * @return parsed integer value from the buffer
   * @throws IOException when the buffer cannot be read as an integer
   */
  private static int parseInt(byte[] buf) throws IOException {
    return new DataInputStream(new ByteArrayInputStream(buf)).readInt();
  }

  /**
   * Reads the serialized version value located just before the footer magic.
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param length total length of the backing buffer in bytes
   * @return four-byte buffer containing the serialized version
   * @throws IOException when the version bytes cannot be read
   */
  private static byte[] readVersionBytes(LockableRandomAccessBuffer raf, long length)
      throws IOException {
    byte[] versionBuf = new byte[4];
    raf.pread(length - 12, versionBuf, 0, 4);
    return versionBuf;
  }

  /**
   * Reads the checksum type bytes stored immediately before the version bytes.
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param length total length of the backing buffer in bytes
   * @return two-byte buffer containing the serialized checksum type
   * @throws IOException when the checksum type bytes cannot be read
   */
  private static byte[] readChecksumTypeBytes(LockableRandomAccessBuffer raf, long length)
      throws IOException {
    byte[] checksumTypeBuf = new byte[2];
    raf.pread(length - 14, checksumTypeBuf, 0, 2);
    return checksumTypeBuf;
  }

  /**
   * Validates that the checksum type matches the supported checksum implementation.
   *
   * @param checksumTypeBuf two-byte buffer containing the serialized checksum type
   * @throws IOException when the checksum type bytes cannot be read
   * @throws StorageFormatException when the checksum type is not recognized
   */
  private static void validateChecksumType(byte[] checksumTypeBuf)
      throws IOException, StorageFormatException {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(checksumTypeBuf));
    int checksumType = dis.readShort();
    if (checksumType != ChecksumChecker.CHECKSUM_CRC)
      throw new StorageFormatException("Unknown checksum type " + checksumType);
  }

  /**
   * Reads the flags field stored before the checksum type and version information.
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param length total length of the backing buffer in bytes
   * @return four-byte buffer containing the serialized flags value
   * @throws IOException when the flags bytes cannot be read
   */
  private static byte[] readFlagsBytes(LockableRandomAccessBuffer raf, long length)
      throws IOException {
    byte[] flagsBuf = new byte[4];
    raf.pread(length - 18, flagsBuf, 0, 4);
    return flagsBuf;
  }

  /**
   * Validates the flags field for unknown bits or unsupported settings.
   *
   * @param flagsBuf four-byte buffer containing the serialized flags value
   * @throws IOException when the flags buffer cannot be read
   * @throws StorageFormatException when the flags contain unsupported values
   */
  private static void validateFlags(byte[] flagsBuf) throws IOException, StorageFormatException {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(flagsBuf));
    int flags = dis.readInt();
    if (flags != 0) throw new StorageFormatException("Unknown flags: " + flags);
  }

  /**
   * Locates and validates the basic settings block near the end of the buffer.
   *
   * <p>The method reads the check-summed length header, verifies its checksum, and enforces bounds
   * to prevent unreasonable settings lengths. It then computes the offset where the settings block
   * begins, returning both the offset and the length for later reads.
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param length total length of the backing buffer in bytes
   * @param checksumChecker checker used to validate the basic settings length checksum
   * @param checksumLength checksum length in bytes used by the storage format
   * @param flagsBuf buffer containing the serialized flags value
   * @param checksumTypeBuf buffer containing the serialized checksum type
   * @param versionBuf buffer containing the serialized storage version
   * @return offset and length describing the basic settings payload
   * @throws IOException when buffer reads fail
   * @throws StorageFormatException when the settings length header is invalid
   */
  private static BasicSettingsInfo readBasicSettingsLocation(
      LockableRandomAccessBuffer raf,
      long length,
      ChecksumChecker checksumChecker,
      int checksumLength,
      byte[] flagsBuf,
      byte[] checksumTypeBuf,
      byte[] versionBuf)
      throws IOException, StorageFormatException {
    byte[] buf = new byte[14];
    raf.pread(length - (22 + checksumLength), buf, 0, 4);
    byte[] checksum = new byte[checksumLength];
    raf.pread(length - (18 + checksumLength), checksum, 0, checksumLength);
    System.arraycopy(flagsBuf, 0, buf, 4, 4);
    System.arraycopy(checksumTypeBuf, 0, buf, 8, 2);
    System.arraycopy(versionBuf, 0, buf, 10, 4);
    if (!checksumChecker.checkChecksum(buf, 0, 14, checksum))
      throw new StorageFormatException("Checksum failed on basic settings length and version");
    int basicSettingsLength = parseInt(buf);
    if (basicSettingsLength < 0
        || basicSettingsLength + 12 + 4 + checksumLength > raf.size()
        || basicSettingsLength > 1024 * 1024)
      throw new StorageFormatException("Bad basic settings length");
    long basicSettingsOffset = length - (18 + 4 + checksumLength * 2L + basicSettingsLength);
    return new BasicSettingsInfo(basicSettingsOffset, basicSettingsLength);
  }

  /**
   * Reads a check-summed byte range and converts checksum failures to storage format errors.
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param checksumChecker checker used to validate the checksum for the range
   * @param checksumLength checksum length in bytes used by the storage format
   * @param offset absolute offset where the data payload begins
   * @param length number of bytes to read into the buffer
   * @return byte array containing the validated payload
   * @throws StorageFormatException when checksum validation fails
   * @throws IOException when the buffer cannot be read
   */
  private static byte[] readChecksummed(
      LockableRandomAccessBuffer raf,
      ChecksumChecker checksumChecker,
      int checksumLength,
      long offset,
      int length)
      throws StorageFormatException, IOException {
    byte[] basicSettingsBuffer = new byte[length];
    try {
      preadChecksummed(raf, checksumChecker, checksumLength, offset, basicSettingsBuffer, length);
    } catch (ChecksumFailedException _) {
      throw new StorageFormatException("Basic settings checksum invalid");
    }
    return basicSettingsBuffer;
  }

  /**
   * Reads a range and validates the trailing checksum, zeroing the buffer on failure.
   *
   * <p>The method reads {@code length} bytes at {@code fileOffset} followed by the checksum
   * trailer. When the checksum does not match, the buffer is zeroed to prevent reuse of invalid
   * data and a {@link ChecksumFailedException} is thrown.
   *
   * @param raf backing buffer containing the persisted splitfile storage
   * @param checksumChecker checker used to validate the checksum for the range
   * @param checksumLength checksum length in bytes used by the storage format
   * @param fileOffset absolute offset where the data payload begins
   * @param buf destination buffer to fill with the payload contents
   * @param length number of bytes to read into the buffer
   * @throws IOException when the buffer cannot be read
   * @throws ChecksumFailedException when the checksum validation fails
   */
  private static void preadChecksummed(
      LockableRandomAccessBuffer raf,
      ChecksumChecker checksumChecker,
      int checksumLength,
      long fileOffset,
      byte[] buf,
      int length)
      throws IOException, ChecksumFailedException {
    byte[] checksumBuf = new byte[checksumLength];
    raf.pread(fileOffset, buf, 0, length);
    raf.pread(fileOffset + length, checksumBuf, 0, checksumLength);
    if (!checksumChecker.checkChecksum(buf, 0, length, checksumBuf)) {
      for (int i = 0; i < length; i++) {
        buf[i] = 0;
      }
      throw new ChecksumFailedException();
    }
  }

  /**
   * Holds the offset and length for the basic settings payload near the file footer.
   *
   * @param offset absolute offset where the basic settings block begins
   * @param length length in bytes of the basic settings payload
   */
  private record BasicSettingsInfo(long offset, int length) {}
}
