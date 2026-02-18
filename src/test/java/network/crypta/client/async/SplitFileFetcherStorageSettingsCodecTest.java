package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import network.crypta.client.ClientMetadata;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherStorageSettingsCodecTest {
  private static final long RAF_LENGTH = 1_000L;
  private static final int SENTINEL = 0xCAFEBABE;

  @Test
  void parseBasicSettings_whenValidBuffer_expectParsedValuesAndStreamPosition()
      throws StorageFormatException, IOException {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.cryptoKey = fixedKey();
    byte[] buffer = values.toBytes(trailingSentinelBytes());

    ParsedBasicSettings parsed =
        SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
            buffer,
            BasicSettingsValues.OFFSET_BASIC_SETTINGS,
            values.completeViaTruncation,
            RAF_LENGTH);

    assertParsedValues(values, parsed);

    DataInputStream remainder = parsed.getSettingsStream();
    assertNotNull(remainder);
    assertEquals(SENTINEL, remainder.readInt());
  }

  @Test
  void encodeBasicSettings_whenStorageProvided_expectSerializedValuesAndChecksummed()
      throws StorageFormatException, IOException {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.cryptoKey = fixedKey();
    values.decompressors = List.of(COMPRESSOR_TYPE.LZMA_NEW);
    values.completeViaTruncation = true;
    values.compatMode = CompatibilityMode.COMPAT_1251;
    values.segmentCount = 2;
    values.totalDataBlocks = 7;
    values.totalCheckBlocks = 3;
    values.totalCrossCheckBlocks = 1;

    SplitFileFetcherSegmentStorage segment0 = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage segment1 = mock(SplitFileFetcherSegmentStorage.class);
    doAnswer(
            invocation -> {
              DataOutputStream dos = invocation.getArgument(0);
              dos.writeInt(1);
              dos.writeInt(2);
              dos.writeInt(3);
              return null;
            })
        .when(segment0)
        .writeFixedMetadata(any(DataOutputStream.class));
    doAnswer(
            invocation -> {
              DataOutputStream dos = invocation.getArgument(0);
              dos.writeInt(4);
              dos.writeInt(5);
              dos.writeInt(6);
              return null;
            })
        .when(segment1)
        .writeFixedMetadata(any(DataOutputStream.class));
    SplitFileFetcherSegmentStorage[] segments =
        new SplitFileFetcherSegmentStorage[] {segment0, segment1};

    SplitFileFetcherCrossSegmentStorage crossSegment =
        mock(SplitFileFetcherCrossSegmentStorage.class);
    doAnswer(
            invocation -> {
              DataOutputStream dos = invocation.getArgument(0);
              dos.writeInt(7);
              dos.writeInt(8);
              dos.writeInt(9);
              dos.writeInt(10);
              return null;
            })
        .when(crossSegment)
        .writeFixedMetadata(any(DataOutputStream.class));
    SplitFileFetcherCrossSegmentStorage[] crossSegments =
        new SplitFileFetcherCrossSegmentStorage[] {crossSegment};

    SplitFileFetcherKeyListener keyListener = mock(SplitFileFetcherKeyListener.class);
    byte[] salt = new byte[32];
    Arrays.fill(salt, (byte) 0x5A);
    doAnswer(
            invocation -> {
              DataOutputStream dos = invocation.getArgument(0);
              dos.write(salt);
              dos.writeInt(111);
              dos.writeInt(222);
              dos.writeInt(333);
              dos.writeInt(444);
              return null;
            })
        .when(keyListener)
        .writeStaticSettings(any(DataOutputStream.class));

    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);
    when(checksumChecker.appendChecksum(any(byte[].class)))
        .thenAnswer(invocation -> invocation.getArgument(0));

    SplitFileFetcherStorage storage =
        newStorageForEncoding(values, segments, crossSegments, keyListener, checksumChecker);

    byte[] encoded =
        SplitFileFetcherStorageSettingsCodec.encodeBasicSettings(
            storage, values.totalDataBlocks, values.totalCheckBlocks, values.totalCrossCheckBlocks);

    verify(checksumChecker).appendChecksum(any(byte[].class));

    ParsedBasicSettings parsed =
        SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
            encoded,
            BasicSettingsValues.OFFSET_BASIC_SETTINGS,
            values.completeViaTruncation,
            RAF_LENGTH);

    assertParsedValues(values, parsed);

    DataInputStream remainder = parsed.getSettingsStream();
    assertEncodedRemainder(remainder, salt);
  }

  @Test
  void parseBasicSettings_whenInvalidSplitfileType_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.splitfileAlgorithmCodeOverride = (short) 99;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenInvalidCryptoAlgorithm_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.cryptoAlgorithm = (byte) 99;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenNegativeFinalLength_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.finalLength = -1L;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenInvalidClientMetadata_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.writeValidClientMetadata = false;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenNegativeDecompressorCount_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.decompressorCountOverride = -1;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenInvalidDecompressorId_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.decompressorIdsOverride = List.of((short) 999);
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenOffsetOutsideRafLength_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.offsetKeyList = RAF_LENGTH + 1;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenBasicSettingsOffsetMismatch_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS + 1,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenCompleteViaTruncationMismatch_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.completeViaTruncation = true;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer, BasicSettingsValues.OFFSET_BASIC_SETTINGS, false, RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenInvalidCompatMode_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.compatModeOrdinalOverride = CompatibilityMode.values().length + 1;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenSegmentCountNonPositive_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.segmentCount = 0;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  @Test
  void parseBasicSettings_whenTotalBlocksNonPositive_expectStorageFormatException() {
    BasicSettingsValues values = BasicSettingsValues.defaults();
    values.totalDataBlocks = 0;
    values.totalCheckBlocks = 0;
    values.totalCrossCheckBlocks = 0;
    byte[] buffer = values.toBytes(null);

    assertThrows(
        StorageFormatException.class,
        () ->
            SplitFileFetcherStorageSettingsCodec.parseBasicSettings(
                buffer,
                BasicSettingsValues.OFFSET_BASIC_SETTINGS,
                values.completeViaTruncation,
                RAF_LENGTH));
  }

  private static byte[] fixedKey() {
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) {
      key[i] = (byte) (i + 1);
    }
    return key;
  }

  private static byte[] trailingSentinelBytes() {
    try {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      try (DataOutputStream dos = new DataOutputStream(baos)) {
        dos.writeInt(SENTINEL);
      }
      return baos.toByteArray();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static void assertParsedValues(BasicSettingsValues values, ParsedBasicSettings parsed) {
    assertEquals(values.splitfileAlgorithm, parsed.getSplitfileType());
    assertEquals(values.cryptoAlgorithm, parsed.getSplitfileSingleCryptoAlgorithm());
    assertArrayEquals(values.cryptoKey, parsed.getSplitfileSingleCryptoKey());
    assertEquals(values.finalLength, parsed.getFinalLength());
    assertEquals(BasicSettingsValues.DECOMPRESSED_LENGTH, parsed.getDecompressedLength());
    assertEquals(values.clientMetadata.getMIMEType(), parsed.getClientMetadata().getMIMEType());
    assertEquals(values.decompressors, parsed.getDecompressors());
    assertEquals(values.offsetKeyList, parsed.getOffsetKeyList());
    assertEquals(BasicSettingsValues.OFFSET_SEGMENT_STATUS, parsed.getOffsetSegmentStatus());
    assertEquals(BasicSettingsValues.OFFSET_GENERAL_PROGRESS, parsed.getOffsetGeneralProgress());
    assertEquals(BasicSettingsValues.OFFSET_MAIN_BLOOM_FILTER, parsed.getOffsetMainBloomFilter());
    assertEquals(
        BasicSettingsValues.OFFSET_SEGMENT_BLOOM_FILTERS, parsed.getOffsetSegmentBloomFilters());
    assertEquals(BasicSettingsValues.OFFSET_ORIGINAL_METADATA, parsed.getOffsetOriginalMetadata());
    assertEquals(BasicSettingsValues.OFFSET_ORIGINAL_DETAILS, parsed.getOffsetOriginalDetails());
    assertEquals(BasicSettingsValues.OFFSET_BASIC_SETTINGS, parsed.getOffsetBasicSettings());
    assertEquals(values.compatMode, parsed.getFinalMinCompatMode());
    assertEquals(values.segmentCount, parsed.getSegmentCount());
    assertEquals(values.totalDataBlocks, parsed.getTotalDataBlocks());
    assertEquals(values.totalCheckBlocks, parsed.getTotalCheckBlocks());
    assertEquals(values.totalCrossCheckBlocks, parsed.getTotalCrossCheckBlocks());
  }

  private static void assertEncodedRemainder(DataInputStream remainder, byte[] expectedSalt)
      throws IOException {
    assertNotNull(remainder);
    assertArrayEquals(new int[] {1, 2, 3, 4, 5, 6, 1, 7, 8, 9, 10}, readInts(remainder, 11));
    assertArrayEquals(expectedSalt, remainder.readNBytes(expectedSalt.length));
    assertArrayEquals(new int[] {111, 222, 333, 444}, readInts(remainder, 4));
  }

  private static int[] readInts(DataInputStream remainder, int count) throws IOException {
    int[] values = new int[count];
    for (int i = 0; i < count; i++) {
      values[i] = remainder.readInt();
    }
    return values;
  }

  private static SplitFileFetcherStorage newStorageForEncoding(
      BasicSettingsValues values,
      SplitFileFetcherSegmentStorage[] segments,
      SplitFileFetcherCrossSegmentStorage[] crossSegments,
      SplitFileFetcherKeyListener keyListener,
      ChecksumChecker checksumChecker) {
    try {
      SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
      setField(storage, "splitfileType", values.splitfileAlgorithm);
      setField(storage, "splitfileSingleCryptoAlgorithm", values.cryptoAlgorithm);
      setField(storage, "splitfileSingleCryptoKey", values.cryptoKey);
      setField(storage, "finalLength", values.finalLength);
      setField(storage, "decompressedLength", BasicSettingsValues.DECOMPRESSED_LENGTH);
      setField(storage, "clientMetadata", values.clientMetadata);
      setField(storage, "decompressors", values.decompressors);
      setField(storage, "offsetKeyList", values.offsetKeyList);
      setField(storage, "offsetSegmentStatus", BasicSettingsValues.OFFSET_SEGMENT_STATUS);
      setField(storage, "offsetGeneralProgress", BasicSettingsValues.OFFSET_GENERAL_PROGRESS);
      setField(storage, "offsetMainBloomFilter", BasicSettingsValues.OFFSET_MAIN_BLOOM_FILTER);
      setField(
          storage, "offsetSegmentBloomFilters", BasicSettingsValues.OFFSET_SEGMENT_BLOOM_FILTERS);
      setField(storage, "offsetOriginalMetadata", BasicSettingsValues.OFFSET_ORIGINAL_METADATA);
      setField(storage, "offsetOriginalDetails", BasicSettingsValues.OFFSET_ORIGINAL_DETAILS);
      setField(storage, "offsetBasicSettings", BasicSettingsValues.OFFSET_BASIC_SETTINGS);
      setField(storage, "completeViaTruncation", values.completeViaTruncation);
      setField(storage, "finalMinCompatMode", values.compatMode);
      setField(storage, "segments", segments);
      setField(storage, "crossSegments", crossSegments);
      setField(storage, "keyListener", keyListener);
      setField(storage, "checksumChecker", checksumChecker);
      return storage;
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Unable to build storage instance", e);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void setField(Object target, String name, Object value)
      throws ReflectiveOperationException {
    Field field = SplitFileFetcherStorage.class.getDeclaredField(name);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static final class BasicSettingsValues {
    private final SplitfileAlgorithm splitfileAlgorithm = SplitfileAlgorithm.ONION_STANDARD;
    private Short splitfileAlgorithmCodeOverride;
    private byte cryptoAlgorithm = 0;
    private byte[] cryptoKey;
    private long finalLength = 123L;
    private static final long DECOMPRESSED_LENGTH = 456L;
    private final ClientMetadata clientMetadata = new ClientMetadata("text/plain");
    private boolean writeValidClientMetadata = true;
    private List<COMPRESSOR_TYPE> decompressors =
        List.of(COMPRESSOR_TYPE.GZIP, COMPRESSOR_TYPE.BZIP2);
    private Integer decompressorCountOverride;
    private List<Short> decompressorIdsOverride;
    private long offsetKeyList = 10L;
    private static final long OFFSET_SEGMENT_STATUS = 20L;
    private static final long OFFSET_GENERAL_PROGRESS = 30L;
    private static final long OFFSET_MAIN_BLOOM_FILTER = 40L;
    private static final long OFFSET_SEGMENT_BLOOM_FILTERS = 50L;
    private static final long OFFSET_ORIGINAL_METADATA = 60L;
    private static final long OFFSET_ORIGINAL_DETAILS = 70L;
    private static final long OFFSET_BASIC_SETTINGS = 80L;
    private boolean completeViaTruncation = false;
    private CompatibilityMode compatMode = CompatibilityMode.COMPAT_1250;
    private Integer compatModeOrdinalOverride;
    private int segmentCount = 2;
    private int totalDataBlocks = 10;
    private int totalCheckBlocks = 5;
    private int totalCrossCheckBlocks = 0;

    private static BasicSettingsValues defaults() {
      return new BasicSettingsValues();
    }

    private byte[] toBytes(byte[] trailing) {
      try {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeShort(resolveSplitfileAlgorithmCode());
        writeCryptoInfo(dos);
        dos.writeLong(finalLength);
        dos.writeLong(DECOMPRESSED_LENGTH);
        writeClientMetadata(dos);
        writeDecompressors(dos);
        writeOffsets(dos);
        dos.writeBoolean(completeViaTruncation);
        dos.writeInt(resolveCompatModeOrdinal());
        dos.writeInt(segmentCount);
        dos.writeInt(totalDataBlocks);
        dos.writeInt(totalCheckBlocks);
        dos.writeInt(totalCrossCheckBlocks);
        if (trailing != null) {
          dos.write(trailing);
        }
        dos.flush();
        return baos.toByteArray();
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
    }

    private short resolveSplitfileAlgorithmCode() {
      return splitfileAlgorithmCodeOverride != null
          ? splitfileAlgorithmCodeOverride
          : splitfileAlgorithm.code;
    }

    private void writeCryptoInfo(DataOutputStream dos) throws IOException {
      dos.writeByte(cryptoAlgorithm);
      if (cryptoKey == null) {
        dos.writeBoolean(false);
        return;
      }
      if (cryptoKey.length != 32) {
        throw new IllegalArgumentException("cryptoKey must be 32 bytes");
      }
      dos.writeBoolean(true);
      dos.write(cryptoKey);
    }

    private void writeClientMetadata(DataOutputStream dos) throws IOException {
      if (writeValidClientMetadata) {
        clientMetadata.writeTo(dos);
        return;
      }
      dos.writeInt(0x0BADBEEF);
      dos.writeShort(1);
      dos.writeBoolean(false);
    }

    private void writeDecompressors(DataOutputStream dos) throws IOException {
      int count = resolveDecompressorCount();
      dos.writeInt(count);
      if (count <= 0) {
        return;
      }
      for (short id : resolveDecompressorIds()) {
        dos.writeShort(id);
      }
    }

    private int resolveDecompressorCount() {
      if (decompressorCountOverride != null) {
        return decompressorCountOverride;
      }
      if (decompressorIdsOverride != null) {
        return decompressorIdsOverride.size();
      }
      return decompressors.size();
    }

    private List<Short> resolveDecompressorIds() {
      if (decompressorIdsOverride != null) {
        return decompressorIdsOverride;
      }
      return decompressors.stream().map(compressor -> compressor.metadataID).toList();
    }

    private void writeOffsets(DataOutputStream dos) throws IOException {
      dos.writeLong(offsetKeyList);
      dos.writeLong(OFFSET_SEGMENT_STATUS);
      dos.writeLong(OFFSET_GENERAL_PROGRESS);
      dos.writeLong(OFFSET_MAIN_BLOOM_FILTER);
      dos.writeLong(OFFSET_SEGMENT_BLOOM_FILTERS);
      dos.writeLong(OFFSET_ORIGINAL_METADATA);
      dos.writeLong(OFFSET_ORIGINAL_DETAILS);
      dos.writeLong(OFFSET_BASIC_SETTINGS);
    }

    @SuppressWarnings("EnumOrdinal")
    private int resolveCompatModeOrdinal() {
      return compatModeOrdinalOverride != null ? compatModeOrdinalOverride : compatMode.ordinal();
    }
  }
}
