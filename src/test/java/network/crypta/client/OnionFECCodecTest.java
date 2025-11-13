package network.crypta.client;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.onionnetworks.fec.PureCode;
import com.onionnetworks.util.Buffer;
import java.lang.ref.SoftReference;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Random;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.support.LRUMap;
import network.crypta.support.TestProperty;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

/** Test the new (post db4o) high level FEC API */
@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OnionFECCodecTest {

  @BeforeEach
  void setUp() {
    random = new Random(21482106);
  }

  @Test
  void decode_whenRandomSubsets_expectSuccessfulRecovery() {
    // Arrange
    int iterations = TestProperty.EXTENSIVE ? 100 : 10;
    // Act + Assert (in inner(): performs decode + roundtrip assertions)
    for (int i = 0; i < iterations; i++) inner(128, 128, random);
    for (int i = 0; i < iterations; i++) inner(127, 129, random);
    for (int i = 0; i < iterations; i++) inner(129, 127, random);
  }

  @Test
  void encode_whenLastDataBlockNotPadded_expectIllegalArgument() {
    // Arrange
    int data = 128;
    int check = 128;
    originalDataBlocks = createOriginalDataBlocks(random, data);
    originalDataBlocks[data - 1] = new byte[BLOCK_SIZE / 2];
    checkBlocks = setupCheckBlocks(check);
    dataBlocks = copy(originalDataBlocks);

    // Encode the check blocks.
    checkBlocksPresent = new boolean[checkBlocks.length];
    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> codec.encode(dataBlocks, checkBlocks, checkBlocksPresent, BLOCK_SIZE));
  }

  @Test
  void encode_whenPresentDataBlockWrongSize_expectIllegalArgument() {
    // Arrange
    setup(128, 128, random);
    deleteRandomBlocks(random);
    dataBlocks[127] = new byte[BLOCK_SIZE / 2];
    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> codec.encode(dataBlocks, checkBlocks, checkBlocksPresent, BLOCK_SIZE));
  }

  @Test
  void decode_whenAllDataBlocksPresent_expectNoOp() {
    // Arrange
    setup(128, 128, random);
    deleteAllCheckBlocks();
    // Act + Assert (decode() asserts data unchanged and re-encode roundtrip)
    decode();
  }

  @Test
  void decode_whenNoDataBlocksPresent_expectRecoveryFromChecks() {
    // Arrange
    setup(128, 128, random);
    deleteAllDataBlocks();
    // Act + Assert
    decode();
  }

  @Test
  void decode_whenManyChecksFewData_expectRecovery() {
    // Arrange + Act + Assert
    inner(2, 253, random);
    inner(5, 250, random);
    inner(50, 200, random);
    inner(2, 3, random); // common case
  }

  @Test
  void decode_whenManyDataFewChecks_expectRecovery() {
    // Arrange + Act + Assert
    inner(200, 55, random);
    inner(253, 2, random);
  }

  @Test
  void decode_whenRandomDataAndCheckCounts_expectRecovery() {
    // Arrange
    int iterations = TestProperty.EXTENSIVE ? 100 : 10;
    // Act + Assert
    for (int i = 0; i < iterations; i++) {
      int data = random.nextInt(252) + 2;
      int maxCheck = 255 - data;
      int check = random.nextInt(maxCheck) + 1;
      inner(data, check, random);
    }
  }

  protected void inner(int data, int check, Random r) {
    setup(data, check, r);
    // Now delete a random selection of blocks
    deleteRandomBlocks(r);
    decode();
  }

  protected void setup(int data, int check, Random r) {
    originalDataBlocks = createOriginalDataBlocks(r, data);
    checkBlocks = setupCheckBlocks(check);
    dataBlocks = copy(originalDataBlocks);

    // Encode the check blocks.
    checkBlocksPresent = new boolean[checkBlocks.length];
    codec.encode(dataBlocks, checkBlocks, checkBlocksPresent, BLOCK_SIZE);
    assertBlockArrayEquals(originalDataBlocks, dataBlocks);
    originalCheckBlocks = copy(checkBlocks);

    // Initially everything is present...
    dataBlocksPresent = new boolean[dataBlocks.length];
    Arrays.fill(dataBlocksPresent, true);
    Arrays.fill(checkBlocksPresent, true);
  }

  protected void decode() {
    boolean[] oldDataBlocksPresent = dataBlocksPresent.clone();
    boolean[] oldCheckBlocksPresent = checkBlocksPresent.clone();
    codec.decode(dataBlocks, checkBlocks, dataBlocksPresent, checkBlocksPresent, BLOCK_SIZE);
    assertBlockArrayEquals(originalDataBlocks, dataBlocks);
    assertArrayEquals(oldDataBlocksPresent, dataBlocksPresent);
    assertArrayEquals(oldCheckBlocksPresent, checkBlocksPresent);
    Arrays.fill(dataBlocksPresent, true);
    codec.encode(dataBlocks, checkBlocks, checkBlocksPresent, BLOCK_SIZE);
    assertBlockArrayEquals(originalCheckBlocks, checkBlocks);
    assertArrayEquals(oldCheckBlocksPresent, checkBlocksPresent);
  }

  protected byte[][] createOriginalDataBlocks(Random r, int count) {
    byte[][] blocks = new byte[count][];
    for (int i = 0; i < count; i++) {
      blocks[i] = new byte[BLOCK_SIZE];
      r.nextBytes(blocks[i]);
    }
    return blocks;
  }

  protected byte[][] setupCheckBlocks(int count) {
    byte[][] blocks = new byte[count][];
    for (int i = 0; i < count; i++) {
      blocks[i] = new byte[BLOCK_SIZE];
    }
    return blocks;
  }

  protected byte[][] copy(byte[][] blocks) {
    byte[][] ret = new byte[blocks.length][];
    for (int i = 0; i < ret.length; i++) {
      ret[i] = Arrays.copyOf(blocks[i], blocks[i].length);
    }
    return ret;
  }

  private void deleteRandomBlocks(Random r) {
    int dropped = 0;
    int data = dataBlocks.length;
    int check = checkBlocks.length;
    while (dropped < check) {
      int blockNo = r.nextInt(data + check);
      if (blockNo < data) {
        if (!dataBlocksPresent[blockNo]) {
          continue;
        }
        clear(dataBlocks, blockNo);
        dataBlocksPresent[blockNo] = false;
      } else {
        blockNo -= data;
        if (!checkBlocksPresent[blockNo]) {
          continue;
        }
        clear(checkBlocks, blockNo);
        checkBlocksPresent[blockNo] = false;
      }
      dropped++;
    }
  }

  private void clear(byte[][] dataBlocks, int blockNo) {
    Arrays.fill(dataBlocks[blockNo], (byte) 0);
  }

  private void assertBlockArrayEquals(byte[][] blocks1, byte[][] blocks2) {
    assertEquals(blocks1.length, blocks2.length);
    for (int i = 0; i < blocks1.length; i++) {
      assertArrayEquals(blocks1[i], blocks2[i]);
    }
  }

  private void deleteAllDataBlocks() {
    for (int i = 0; i < dataBlocks.length; i++) {
      clear(dataBlocks, i);
      dataBlocksPresent[i] = false;
    }
  }

  private void deleteAllCheckBlocks() {
    for (int i = 0; i < checkBlocks.length; i++) {
      clear(checkBlocks, i);
      checkBlocksPresent[i] = false;
    }
  }

  private static final int BLOCK_SIZE = 4096;
  private final OnionFECCodec codec = new OnionFECCodec();
  private byte[][] originalDataBlocks;
  private byte[][] dataBlocks;
  private byte[][] originalCheckBlocks;
  private byte[][] checkBlocks;
  private boolean[] checkBlocksPresent;
  private boolean[] dataBlocksPresent;
  private Random random;

  // ---------------------------- Additional focused unit tests ----------------------------

  @Test
  @DisplayName("encode() when all check blocks are present does not invoke codec.encode()")
  void encode_whenAllChecksPresent_expectNoEncodeInvocation() throws Exception {
    clearCodecCache();
    int k = 3;
    int r = 2;
    byte[][] d = new byte[k][BLOCK_SIZE];
    for (int i = 0; i < k; i++) Arrays.fill(d[i], (byte) i);
    byte[][] c = new byte[r][BLOCK_SIZE];
    boolean[] present = new boolean[r];
    Arrays.fill(present, true); // nothing to encode

    try (MockedConstruction<PureCode> cons = mockConstruction(PureCode.class)) {
      codec.encode(d, c, present, BLOCK_SIZE);

      // One PureCode constructed via getCodec(k,n), but encode() must not be called.
      assertEquals(1, cons.constructed().size(), "codec should be constructed once");
      PureCode mock = cons.constructed().getFirst();
      verify(mock, never()).encode(any(Buffer[].class), any(Buffer[].class), any(int[].class));
      verifyNoMoreInteractions(mock);
    }
  }

  @Test
  @DisplayName("encode() missing check blocks encodes correct parity indices")
  void encode_whenSomeChecksMissing_expectEncodeWithExpectedIndices() throws Exception {
    clearCodecCache();
    int k = 4;
    int r = 3;
    byte[][] d = new byte[k][BLOCK_SIZE];
    byte[][] c = new byte[r][BLOCK_SIZE];
    // Mark only 1st and last as missing → encode indices {k+0, k+2}
    boolean[] present = new boolean[] {false, true, false};

    try (MockedConstruction<PureCode> cons = mockConstruction(PureCode.class, (mock, ctx) -> {})) {
      codec.encode(d, c, present, BLOCK_SIZE);
      PureCode mock = cons.constructed().getFirst();

      ArgumentCaptor<Buffer[]> dataCap = ArgumentCaptor.forClass(Buffer[].class);
      ArgumentCaptor<Buffer[]> checkCap = ArgumentCaptor.forClass(Buffer[].class);
      ArgumentCaptor<int[]> idxCap = ArgumentCaptor.forClass(int[].class);
      verify(mock).encode(dataCap.capture(), checkCap.capture(), idxCap.capture());

      assertEquals(k, dataCap.getValue().length, "data buffers length");
      assertEquals(2, checkCap.getValue().length, "check buffers to encode (missing only)");
      //noinspection PointlessArithmeticExpression
      assertArrayEquals(new int[] {k + 0, k + 2}, idxCap.getValue(), "indices to encode");
    }
  }

  @Test
  @DisplayName("encode() throws on wrong-sized data block")
  void encode_whenDataBlockWrongSize_expectIllegalArgument() {
    byte[][] d = new byte[][] {new byte[BLOCK_SIZE], new byte[BLOCK_SIZE / 2]};
    byte[][] c = new byte[][] {new byte[BLOCK_SIZE]};
    boolean[] present = new boolean[] {false};
    assertThrows(IllegalArgumentException.class, () -> codec.encode(d, c, present, BLOCK_SIZE));
  }

  @Test
  @DisplayName("encode() throws on wrong-sized check block")
  void encode_whenCheckBlockWrongSize_expectIllegalArgument() {
    byte[][] d = new byte[][] {new byte[BLOCK_SIZE]};
    byte[][] c = new byte[][] {new byte[BLOCK_SIZE / 2]};
    boolean[] present = new boolean[] {false};
    assertThrows(IllegalArgumentException.class, () -> codec.encode(d, c, present, BLOCK_SIZE));
  }

  @Test
  @DisplayName("decode() wires buffers and block numbers correctly")
  void decode_whenGapFilledByCheck_expectCorrectBlockNumbersAndCopy() throws Exception {
    clearCodecCache();
    int k = 3;
    int r = 2;
    byte[][] d = new byte[k][BLOCK_SIZE];
    // Data present at 0 and 2; missing 1
    boolean[] dataPresent = new boolean[] {true, false, true};
    byte[][] c = new byte[r][BLOCK_SIZE];
    // Only first check available; content should be copied into d[1] before decode
    Arrays.fill(c[0], (byte) 0x7B);
    boolean[] checksPresent = new boolean[] {true, false};

    try (MockedConstruction<PureCode> cons = mockConstruction(PureCode.class)) {
      codec.decode(d, c, dataPresent, checksPresent, BLOCK_SIZE);

      PureCode mock = cons.constructed().getFirst();
      ArgumentCaptor<Buffer[]> bufsCap = ArgumentCaptor.forClass(Buffer[].class);
      ArgumentCaptor<int[]> numsCap = ArgumentCaptor.forClass(int[].class);
      verify(mock).decode(bufsCap.capture(), numsCap.capture());

      // Expect exactly k buffers and block numbers
      assertEquals(k, bufsCap.getValue().length);
      //noinspection PointlessArithmeticExpression
      assertArrayEquals(new int[] {0, k + 0, 2}, numsCap.getValue(), "block numbers");
      // The missing slot at index 1 must now contain the check block bytes
      for (int i = 0; i < BLOCK_SIZE; i++) {
        assertEquals((byte) 0x7B, d[1][i], "copied check content into missing data slot");
      }
    }
  }

  @Test
  @DisplayName("decode() throws on wrong-sized present data block")
  void decode_whenDataBlockWrongSize_expectIllegalArgument() {
    byte[][] d = new byte[][] {new byte[BLOCK_SIZE], new byte[BLOCK_SIZE / 2]};
    boolean[] dataPresent = new boolean[] {true, true};
    byte[][] c = new byte[][] {new byte[BLOCK_SIZE]};
    boolean[] checksPresent = new boolean[] {true};
    assertThrows(
        IllegalArgumentException.class,
        () -> codec.decode(d, c, dataPresent, checksPresent, BLOCK_SIZE));
  }

  @Test
  @DisplayName("decode() throws on wrong-sized present check block")
  void decode_whenCheckBlockWrongSize_expectIllegalArgument() {
    byte[][] d = new byte[][] {new byte[BLOCK_SIZE], new byte[BLOCK_SIZE]};
    boolean[] dataPresent = new boolean[] {true, false};
    byte[][] c = new byte[][] {new byte[BLOCK_SIZE / 2]};
    boolean[] checksPresent = new boolean[] {true};
    assertThrows(
        IllegalArgumentException.class,
        () -> codec.decode(d, c, dataPresent, checksPresent, BLOCK_SIZE));
  }

  @Test
  @DisplayName("getCheckBlocks() small data CURRENT → data+1 (capped later if needed)")
  void getCheckBlocks_whenSmallDataCurrent_expectDataPlusOne() {
    int data = 5;
    int result = codec.getCheckBlocks(data, CompatibilityMode.COMPAT_CURRENT);
    assertEquals(6, result);
  }

  @Test
  @DisplayName("getCheckBlocks() data=128 CURRENT → clamped to 128 (total ≤256)")
  void getCheckBlocks_whenAt128Current_expectClamped128() {
    int result =
        codec.getCheckBlocks(
            HighLevelSimpleClientImpl.SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
            CompatibilityMode.COMPAT_CURRENT);
    // Raw calculation would be 129; clamped to keep data+check ≤ 256
    assertEquals(128, result);
  }

  @Test
  @DisplayName("getCheckBlocks() large data CURRENT is capped to keep sum ≤ 256 (when data<256)")
  void getCheckBlocks_whenLargeDataCurrent_expectCappedTo256Total() {
    int data = 200;
    int checks = codec.getCheckBlocks(data, CompatibilityMode.COMPAT_CURRENT);
    assertEquals(56, checks); // 200 + 56 = 256
  }

  @Test
  @DisplayName("getCheckBlocks() small data COMPAT_1250 → at most data")
  void getCheckBlocks_whenCompat1250Small_expectAtMostData() {
    int data = 5;
    int checks = codec.getCheckBlocks(data, CompatibilityMode.COMPAT_1250);
    assertEquals(5, checks); // data+1 would be 6, but capped to data for 1250
  }

  @Test
  @DisplayName("getCheckBlocks() data=128 COMPAT_1250 → 128")
  void getCheckBlocks_whenCompat1250At128_expect128() {
    int checks =
        codec.getCheckBlocks(
            HighLevelSimpleClientImpl.SPLITFILE_CHECK_BLOCKS_PER_SEGMENT,
            CompatibilityMode.COMPAT_1250);
    assertEquals(128, checks);
  }

  @Test
  @DisplayName("getCheckBlocks() data=256 CURRENT → 129 (no 256 cap branch for data>=256)")
  void getCheckBlocks_whenData256Current_expect129() {
    int checks = codec.getCheckBlocks(256, CompatibilityMode.COMPAT_CURRENT);
    assertEquals(129, checks);
  }

  @Test
  @DisplayName("maxMemoryOverheadEncode/Decode() follow n*k*2*3 formula")
  void memoryOverhead_whenTypical_expectExpectedValues() {
    int data = 10;
    int check = 2;
    long expected = (long) (data + check) * data * 2L * 3L;
    assertEquals(expected, codec.maxMemoryOverheadEncode(data, check));
    assertEquals(expected, codec.maxMemoryOverheadDecode(data, check));
  }

  // Clear the private static codec cache to keep tests isolated
  private static void clearCodecCache() throws Exception {
    Field f = OnionFECCodec.class.getDeclaredField("recentlyUsedCodecs");
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    LRUMap<Object, SoftReference<PureCode>> cache =
        (LRUMap<Object, SoftReference<PureCode>>) f.get(null);
    cache.clear();
  }
}
