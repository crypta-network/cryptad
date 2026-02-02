package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.client.MetadataParseException;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.StorageFormatException;
import org.jetbrains.annotations.NotNull;

/**
 * Encodes and decodes the basic settings section of splitfile fetcher persistence.
 *
 * <p>This utility reads and writes the fixed header portion that precedes per-segment metadata in
 * the splitfile fetcher storage footer. Encoding gathers immutable settings and offsets from a
 * fully initialized {@link SplitFileFetcherStorage} and produces a single byte array, including the
 * checksum, that can be written to the storage file. Decoding consumes the corresponding byte
 * block, validates structural invariants such as lengths, offsets, and compatibility modes, and
 * exposes the parsed values for follow-on parsing.
 *
 * <p>The class is stateless and does not cache or retain input buffers; callers are responsible for
 * synchronization around shared {@link SplitFileFetcherStorage} instances and for ensuring that the
 * buffer represents the on-disk basic settings block they intend to parse. Parsing returns a {@link
 * ParsedBasicSettings} that keeps the {@link DataInputStream} open and positioned after the fixed
 * fields so callers can read segment metadata sequentially.
 *
 * <ul>
 *   <li>Serializes splitfile algorithm, crypto parameters, lengths, and client metadata.
 *   <li>Writes and validates offsets for subsequent storage sections.
 *   <li>Records compatibility mode and block counts used for segment construction.
 * </ul>
 *
 * @see SplitFileFetcherStorage
 * @see ParsedBasicSettings
 */
public final class SplitFileFetcherStorageSettingsCodec {
  private SplitFileFetcherStorageSettingsCodec() {}

  /** Parse the basic settings block from the persisted splitfile storage format. */
  static ParsedBasicSettings parseBasicSettings(
      byte[] basicSettingsBuffer,
      long basicSettingsOffset,
      boolean completeViaTruncation,
      long rafLength)
      throws StorageFormatException {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(basicSettingsBuffer));
    try {
      SplitfileAlgorithm splitfileAlgorithm = readSplitfileAlgorithm(dis);
      CryptoInfo crypto = readCryptoInfo(dis, splitfileAlgorithm);
      LengthsInfo lengths = readLengths(dis);
      HeaderInfo header = new HeaderInfo(splitfileAlgorithm, crypto, lengths);
      ClientMetadata cm = readClientMetadataSafe(dis);
      List<COMPRESSOR_TYPE> decomps = readDecompressors(dis);
      OffsetsInfo offsets = readOffsets(dis, basicSettingsOffset, completeViaTruncation, rafLength);
      CompatAndCounts compat = readCompatAndCounts(dis);
      return new ParsedBasicSettings(
          header.splitfileType,
          header.crypto.algorithm,
          header.crypto.key,
          header.lengths.finalLength,
          header.lengths.decompressedLength,
          cm,
          decomps,
          offsets.offsetKeyList,
          offsets.offsetSegmentStatus,
          offsets.offsetGeneralProgress,
          offsets.offsetMainBloomFilter,
          offsets.offsetSegmentBloomFilters,
          offsets.offsetOriginalMetadata,
          offsets.offsetOriginalDetails,
          offsets.offsetBasicSettings,
          compat.mode,
          compat.segmentCount,
          compat.totalDataBlocks,
          compat.totalCheckBlocks,
          compat.totalCrossCheckBlocks,
          dis);
    } catch (IOException e) {
      throw new StorageFormatException(
          "Cannot read basic settings even though passed checksum: " + e, e);
    }
  }

  /**
   * Encodes the basic settings block, including the checksum, for splitfile fetcher persistence.
   *
   * <p>The method serializes the fixed header fields from {@code storage}, including crypto
   * parameters, lengths, client metadata, offsets, compatibility mode, and the supplied block
   * totals. It then writes fixed metadata for each segment, any cross-segment metadata, and the key
   * listener's static settings before appending the checksum with the storage checker. The method
   * does not perform additional validation of the block totals and assumes the offsets and lengths
   * in {@code storage} are already computed.
   *
   * <pre>{@code
   * byte[] settings =
   *     SplitFileFetcherStorageSettingsCodec.encodeBasicSettings(
   *         storage, dataBlocks, checkBlocks, crossBlocks);
   * }</pre>
   *
   * @param storage storage instance providing offsets, metadata, and checksum checker; initialized
   *     for serialization
   * @param totalDataBlocks total count of data blocks across all segments; non-negative
   * @param totalCheckBlocks total count of check blocks across all segments; non-negative
   * @param totalCrossCheckBlocks total count of cross-check blocks across all segments;
   *     non-negative
   * @return byte array containing the encoded settings block with appended checksum
   * @throws IllegalStateException if an unexpected I/O error occurs while encoding
   */
  public static byte[] encodeBasicSettings(
      SplitFileFetcherStorage storage,
      int totalDataBlocks,
      int totalCheckBlocks,
      int totalCrossCheckBlocks) {
    byte[] raw =
        innerEncodeBasicSettings(storage, totalDataBlocks, totalCheckBlocks, totalCrossCheckBlocks);
    return storage.checksumChecker.appendChecksum(raw);
  }

  private static SplitfileAlgorithm readSplitfileAlgorithm(DataInputStream dis)
      throws IOException, StorageFormatException {
    short code = dis.readShort();
    try {
      return SplitfileAlgorithm.getByCode(code);
    } catch (IllegalArgumentException _) {
      throw new StorageFormatException("Invalid splitfile type " + code);
    }
  }

  private static CryptoInfo readCryptoInfo(
      DataInputStream dis, SplitfileAlgorithm splitfileAlgorithm)
      throws IOException, StorageFormatException {
    byte alg = dis.readByte();
    if (!Metadata.isValidSplitfileCryptoAlgorithm(alg)) {
      throw new StorageFormatException("Invalid splitfile crypto algorithm " + splitfileAlgorithm);
    }
    byte[] key = null;
    if (dis.readBoolean()) {
      key = new byte[32];
      dis.readFully(key);
    }
    return new CryptoInfo(alg, key);
  }

  private static LengthsInfo readLengths(DataInputStream dis)
      throws IOException, StorageFormatException {
    long finalLen = dis.readLong();
    if (finalLen < 0) throw new StorageFormatException("Invalid final length " + finalLen);
    long decompLen = dis.readLong();
    if (decompLen < 0) throw new StorageFormatException("Invalid decompressed length " + decompLen);
    return new LengthsInfo(finalLen, decompLen);
  }

  private static ClientMetadata readClientMetadataSafe(DataInputStream dis)
      throws IOException, StorageFormatException {
    try {
      return ClientMetadata.construct(dis);
    } catch (MetadataParseException _) {
      throw new StorageFormatException("Invalid MIME type");
    }
  }

  private static List<COMPRESSOR_TYPE> readDecompressors(DataInputStream dis)
      throws IOException, StorageFormatException {
    int decompressorCount = dis.readInt();
    if (decompressorCount < 0) {
      throw new StorageFormatException("Invalid decompressor count " + decompressorCount);
    }
    List<COMPRESSOR_TYPE> decomps = new ArrayList<>(decompressorCount);
    for (int i = 0; i < decompressorCount; i++) {
      short type = dis.readShort();
      COMPRESSOR_TYPE decompressor = COMPRESSOR_TYPE.getCompressorByMetadataID(type);
      if (decompressor == null) {
        throw new StorageFormatException("Invalid decompressor ID " + type);
      }
      decomps.add(decompressor);
    }
    return decomps;
  }

  private static OffsetsInfo readOffsets(
      DataInputStream dis, long basicSettingsOffset, boolean completeViaTruncation, long rafLength)
      throws IOException, StorageFormatException {
    long keyListOffset = readValidatedOffset(dis, "key list", rafLength);
    long segmentStatusOffset = readValidatedOffset(dis, "segment status", rafLength);
    long generalProgressOffset = readValidatedOffset(dis, "general progress", rafLength);
    long mainBloomOffset = readValidatedOffset(dis, "main bloom filter", rafLength);
    long segmentBloomOffset = readValidatedOffset(dis, "segment bloom filters", rafLength);
    long origMetaOffset = readValidatedOffset(dis, "original metadata", rafLength);
    long origDetailsOffset = readValidatedOffset(dis, "original metadata", rafLength);
    long basicSettingsOff = dis.readLong();
    if (basicSettingsOff != basicSettingsOffset)
      throw new StorageFormatException("Invalid basic settings offset (not the same as computed)");
    if (completeViaTruncation != dis.readBoolean())
      throw new StorageFormatException("Complete via truncation flag is wrong");
    return new OffsetsInfo(
        keyListOffset,
        segmentStatusOffset,
        generalProgressOffset,
        mainBloomOffset,
        segmentBloomOffset,
        origMetaOffset,
        origDetailsOffset,
        basicSettingsOff);
  }

  private static long readValidatedOffset(DataInputStream dis, String what, long rafLength)
      throws IOException, StorageFormatException {
    long value = dis.readLong();
    if (value < 0 || value > rafLength)
      throw new StorageFormatException("Invalid offset (" + what + ")");
    return value;
  }

  private static CompatAndCounts readCompatAndCounts(DataInputStream dis)
      throws IOException, StorageFormatException {
    int compatMode = dis.readInt();
    if (compatMode < 0 || compatMode > Short.MAX_VALUE)
      throw new StorageFormatException("Invalid compatibility mode " + compatMode);
    short compatCode = (short) compatMode;
    if (!CompatibilityMode.hasCode(compatCode))
      throw new StorageFormatException("Invalid compatibility mode " + compatMode);
    CompatibilityMode finalMode = CompatibilityMode.byCode(compatCode);
    int segmentCount = dis.readInt();
    if (segmentCount <= 0)
      throw new StorageFormatException("Invalid segment count " + segmentCount);
    int totalDataBlocks = dis.readInt();
    if (totalDataBlocks < 0)
      throw new StorageFormatException("Invalid total data blocks " + totalDataBlocks);
    int totalCheckBlocks = dis.readInt();
    if (totalCheckBlocks < 0)
      throw new StorageFormatException("Invalid total check blocks " + totalDataBlocks);
    int totalCrossCheckBlocks = dis.readInt();
    if (totalCrossCheckBlocks < 0)
      throw new StorageFormatException("Invalid total cross-check blocks " + totalDataBlocks);
    if (totalDataBlocks + totalCheckBlocks + totalCrossCheckBlocks <= 0) {
      throw new StorageFormatException("Total number of blocks in splitfile is non-positive");
    }
    return new CompatAndCounts(
        finalMode, segmentCount, totalDataBlocks, totalCheckBlocks, totalCrossCheckBlocks);
  }

  private static byte[] innerEncodeBasicSettings(
      SplitFileFetcherStorage storage,
      int totalDataBlocks,
      int totalCheckBlocks,
      int totalCrossCheckBlocks) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    try {
      dos.writeShort(storage.splitfileType.code);
      dos.writeByte(storage.splitfileSingleCryptoAlgorithm);
      dos.writeBoolean(storage.splitfileSingleCryptoKey != null);
      if (storage.splitfileSingleCryptoKey != null) {
        assert (storage.splitfileSingleCryptoKey.length == 32);
        dos.write(storage.splitfileSingleCryptoKey);
      }
      dos.writeLong(storage.finalLength);
      dos.writeLong(storage.decompressedLength);
      storage.clientMetadata.writeTo(dos);
      dos.writeInt(storage.decompressors.size());
      for (COMPRESSOR_TYPE compressor : storage.decompressors) {
        dos.writeShort(compressor.metadataID);
      }
      dos.writeLong(storage.offsetKeyList);
      dos.writeLong(storage.offsetSegmentStatus);
      dos.writeLong(storage.offsetGeneralProgress);
      dos.writeLong(storage.offsetMainBloomFilter);
      dos.writeLong(storage.offsetSegmentBloomFilters);
      dos.writeLong(storage.offsetOriginalMetadata);
      dos.writeLong(storage.offsetOriginalDetails);
      dos.writeLong(storage.offsetBasicSettings);
      dos.writeBoolean(storage.completeViaTruncation);
      dos.writeInt(storage.finalMinCompatMode.code);
      dos.writeInt(storage.segments.length);
      dos.writeInt(totalDataBlocks);
      dos.writeInt(totalCheckBlocks);
      dos.writeInt(totalCrossCheckBlocks);
      for (SplitFileFetcherSegmentStorage segment : storage.segments) {
        segment.writeFixedMetadata(dos);
      }
      if (storage.crossSegments == null) {
        dos.writeInt(0);
      } else {
        dos.writeInt(storage.crossSegments.length);
        for (SplitFileFetcherCrossSegmentStorage segment : storage.crossSegments) {
          segment.writeFixedMetadata(dos);
        }
      }
      storage.keyListener.writeStaticSettings(dos);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  private static final class CryptoInfo {
    private final byte algorithm;
    private final byte[] key;

    private CryptoInfo(byte algorithm, byte[] key) {
      this.algorithm = algorithm;
      this.key = key;
    }
  }

  private static final class LengthsInfo {
    private final long finalLength;
    private final long decompressedLength;

    private LengthsInfo(long finalLength, long decompressedLength) {
      this.finalLength = finalLength;
      this.decompressedLength = decompressedLength;
    }
  }

  private static final class HeaderInfo {
    private final SplitfileAlgorithm splitfileType;
    private final CryptoInfo crypto;
    private final LengthsInfo lengths;

    private HeaderInfo(SplitfileAlgorithm splitfileType, CryptoInfo crypto, LengthsInfo lengths) {
      this.splitfileType = splitfileType;
      this.crypto = crypto;
      this.lengths = lengths;
    }
  }

  private static final class OffsetsInfo {
    private final long offsetKeyList;
    private final long offsetSegmentStatus;
    private final long offsetGeneralProgress;
    private final long offsetMainBloomFilter;
    private final long offsetSegmentBloomFilters;
    private final long offsetOriginalMetadata;
    private final long offsetOriginalDetails;
    private final long offsetBasicSettings;

    private OffsetsInfo(long... offsets) {
      this.offsetKeyList = offsets[0];
      this.offsetSegmentStatus = offsets[1];
      this.offsetGeneralProgress = offsets[2];
      this.offsetMainBloomFilter = offsets[3];
      this.offsetSegmentBloomFilters = offsets[4];
      this.offsetOriginalMetadata = offsets[5];
      this.offsetOriginalDetails = offsets[6];
      this.offsetBasicSettings = offsets[7];
    }
  }

  private static final class CompatAndCounts {
    private final CompatibilityMode mode;
    private final int segmentCount;
    private final int totalDataBlocks;
    private final int totalCheckBlocks;
    private final int totalCrossCheckBlocks;

    private CompatAndCounts(
        CompatibilityMode mode,
        int segmentCount,
        int totalDataBlocks,
        int totalCheckBlocks,
        int totalCrossCheckBlocks) {
      this.mode = mode;
      this.segmentCount = segmentCount;
      this.totalDataBlocks = totalDataBlocks;
      this.totalCheckBlocks = totalCheckBlocks;
      this.totalCrossCheckBlocks = totalCrossCheckBlocks;
    }
  }
}

/**
 * Parsed basic settings extracted from the persisted splitfile storage footer.
 *
 * <p>The {@code settingsStream} remains open and positioned at the first byte after the parsed
 * fields so callers can continue reading segment metadata without reparsing the buffer.
 */
@SuppressWarnings("java:S6206")
final class ParsedBasicSettings {
  private final SplitfileAlgorithm splitfileType;
  private final byte splitfileSingleCryptoAlgorithm;
  private final byte[] splitfileSingleCryptoKey;
  private final long finalLength;
  private final long decompressedLength;
  private final ClientMetadata clientMetadata;
  private final List<COMPRESSOR_TYPE> decompressors;
  private final long offsetKeyList;
  private final long offsetSegmentStatus;
  private final long offsetGeneralProgress;
  private final long offsetMainBloomFilter;
  private final long offsetSegmentBloomFilters;
  private final long offsetOriginalMetadata;
  private final long offsetOriginalDetails;
  private final long offsetBasicSettings;
  private final CompatibilityMode finalMinCompatMode;
  private final int segmentCount;
  private final int totalDataBlocks;
  private final int totalCheckBlocks;
  private final int totalCrossCheckBlocks;
  private final DataInputStream settingsStream;

  ParsedBasicSettings(
      SplitfileAlgorithm splitfileType,
      byte splitfileSingleCryptoAlgorithm,
      byte[] splitfileSingleCryptoKey,
      long finalLength,
      long decompressedLength,
      ClientMetadata clientMetadata,
      List<COMPRESSOR_TYPE> decompressors,
      long offsetKeyList,
      long offsetSegmentStatus,
      long offsetGeneralProgress,
      long offsetMainBloomFilter,
      long offsetSegmentBloomFilters,
      long offsetOriginalMetadata,
      long offsetOriginalDetails,
      long offsetBasicSettings,
      CompatibilityMode finalMinCompatMode,
      int segmentCount,
      int totalDataBlocks,
      int totalCheckBlocks,
      int totalCrossCheckBlocks,
      DataInputStream settingsStream) {
    this.splitfileType = splitfileType;
    this.splitfileSingleCryptoAlgorithm = splitfileSingleCryptoAlgorithm;
    this.splitfileSingleCryptoKey = splitfileSingleCryptoKey;
    this.finalLength = finalLength;
    this.decompressedLength = decompressedLength;
    this.clientMetadata = clientMetadata;
    this.decompressors = decompressors;
    this.offsetKeyList = offsetKeyList;
    this.offsetSegmentStatus = offsetSegmentStatus;
    this.offsetGeneralProgress = offsetGeneralProgress;
    this.offsetMainBloomFilter = offsetMainBloomFilter;
    this.offsetSegmentBloomFilters = offsetSegmentBloomFilters;
    this.offsetOriginalMetadata = offsetOriginalMetadata;
    this.offsetOriginalDetails = offsetOriginalDetails;
    this.offsetBasicSettings = offsetBasicSettings;
    this.finalMinCompatMode = finalMinCompatMode;
    this.segmentCount = segmentCount;
    this.totalDataBlocks = totalDataBlocks;
    this.totalCheckBlocks = totalCheckBlocks;
    this.totalCrossCheckBlocks = totalCrossCheckBlocks;
    this.settingsStream = settingsStream;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ParsedBasicSettings otherSettings)) {
      return false;
    }
    return splitfileSingleCryptoAlgorithm == otherSettings.splitfileSingleCryptoAlgorithm
        && finalLength == otherSettings.finalLength
        && decompressedLength == otherSettings.decompressedLength
        && offsetKeyList == otherSettings.offsetKeyList
        && offsetSegmentStatus == otherSettings.offsetSegmentStatus
        && offsetGeneralProgress == otherSettings.offsetGeneralProgress
        && offsetMainBloomFilter == otherSettings.offsetMainBloomFilter
        && offsetSegmentBloomFilters == otherSettings.offsetSegmentBloomFilters
        && offsetOriginalMetadata == otherSettings.offsetOriginalMetadata
        && offsetOriginalDetails == otherSettings.offsetOriginalDetails
        && offsetBasicSettings == otherSettings.offsetBasicSettings
        && segmentCount == otherSettings.segmentCount
        && totalDataBlocks == otherSettings.totalDataBlocks
        && totalCheckBlocks == otherSettings.totalCheckBlocks
        && totalCrossCheckBlocks == otherSettings.totalCrossCheckBlocks
        && Objects.equals(splitfileType, otherSettings.splitfileType)
        && Arrays.equals(splitfileSingleCryptoKey, otherSettings.splitfileSingleCryptoKey)
        && Objects.equals(clientMetadata, otherSettings.clientMetadata)
        && Objects.equals(decompressors, otherSettings.decompressors)
        && Objects.equals(finalMinCompatMode, otherSettings.finalMinCompatMode)
        && Objects.equals(settingsStream, otherSettings.settingsStream);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(
            splitfileType,
            splitfileSingleCryptoAlgorithm,
            finalLength,
            decompressedLength,
            clientMetadata,
            decompressors,
            offsetKeyList,
            offsetSegmentStatus,
            offsetGeneralProgress,
            offsetMainBloomFilter,
            offsetSegmentBloomFilters,
            offsetOriginalMetadata,
            offsetOriginalDetails,
            offsetBasicSettings,
            finalMinCompatMode,
            segmentCount,
            totalDataBlocks,
            totalCheckBlocks,
            totalCrossCheckBlocks,
            settingsStream);
    return 31 * result + Arrays.hashCode(splitfileSingleCryptoKey);
  }

  @Override
  public @NotNull String toString() {
    return "ParsedBasicSettings["
        + "splitfileType="
        + splitfileType
        + ", splitfileSingleCryptoAlgorithm="
        + splitfileSingleCryptoAlgorithm
        + ", splitfileSingleCryptoKey="
        + Arrays.toString(splitfileSingleCryptoKey)
        + ", finalLength="
        + finalLength
        + ", decompressedLength="
        + decompressedLength
        + ", clientMetadata="
        + clientMetadata
        + ", decompressors="
        + decompressors
        + ", offsetKeyList="
        + offsetKeyList
        + ", offsetSegmentStatus="
        + offsetSegmentStatus
        + ", offsetGeneralProgress="
        + offsetGeneralProgress
        + ", offsetMainBloomFilter="
        + offsetMainBloomFilter
        + ", offsetSegmentBloomFilters="
        + offsetSegmentBloomFilters
        + ", offsetOriginalMetadata="
        + offsetOriginalMetadata
        + ", offsetOriginalDetails="
        + offsetOriginalDetails
        + ", offsetBasicSettings="
        + offsetBasicSettings
        + ", finalMinCompatMode="
        + finalMinCompatMode
        + ", segmentCount="
        + segmentCount
        + ", totalDataBlocks="
        + totalDataBlocks
        + ", totalCheckBlocks="
        + totalCheckBlocks
        + ", totalCrossCheckBlocks="
        + totalCrossCheckBlocks
        + ", settingsStream="
        + settingsStream
        + "]";
  }

  SplitfileAlgorithm getSplitfileType() {
    return splitfileType;
  }

  byte getSplitfileSingleCryptoAlgorithm() {
    return splitfileSingleCryptoAlgorithm;
  }

  byte[] getSplitfileSingleCryptoKey() {
    return splitfileSingleCryptoKey;
  }

  long getFinalLength() {
    return finalLength;
  }

  long getDecompressedLength() {
    return decompressedLength;
  }

  ClientMetadata getClientMetadata() {
    return clientMetadata;
  }

  List<COMPRESSOR_TYPE> getDecompressors() {
    return decompressors;
  }

  long getOffsetKeyList() {
    return offsetKeyList;
  }

  long getOffsetSegmentStatus() {
    return offsetSegmentStatus;
  }

  long getOffsetGeneralProgress() {
    return offsetGeneralProgress;
  }

  long getOffsetMainBloomFilter() {
    return offsetMainBloomFilter;
  }

  long getOffsetSegmentBloomFilters() {
    return offsetSegmentBloomFilters;
  }

  long getOffsetOriginalMetadata() {
    return offsetOriginalMetadata;
  }

  long getOffsetOriginalDetails() {
    return offsetOriginalDetails;
  }

  long getOffsetBasicSettings() {
    return offsetBasicSettings;
  }

  CompatibilityMode getFinalMinCompatMode() {
    return finalMinCompatMode;
  }

  int getSegmentCount() {
    return segmentCount;
  }

  int getTotalDataBlocks() {
    return totalDataBlocks;
  }

  int getTotalCheckBlocks() {
    return totalCheckBlocks;
  }

  int getTotalCrossCheckBlocks() {
    return totalCrossCheckBlocks;
  }

  DataInputStream getSettingsStream() {
    return settingsStream;
  }
}
