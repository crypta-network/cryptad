package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Random;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.async.SplitFileFetcherSegmentsBuilder.SegmentsBuildContext;
import network.crypta.client.async.SplitFileFetcherStorageLayout.AccumulatedSizes;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.NodeCHK;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherSegmentsBuilderTest {

  @Mock private SplitFileFetcherStorageCallback fetcherCallback;

  @Mock private PersistentJobRunner jobRunner;

  @Mock private MemoryLimitedJobRunner memoryLimitedJobRunner;

  @Mock private SplitFileFetcherKeyListener keyListener;

  @Test
  void initSegmentsAndKeys_whenValidContext_registersKeysAndOffsets() throws Exception {
    SplitFileSegmentKeys keysA = newSegmentKeys(2, 1);
    SplitFileSegmentKeys keysB = newSegmentKeys(3, 0);
    SplitFileSegmentKeys[] segmentKeys = new SplitFileSegmentKeys[] {keysA, keysB};

    int crossCheckBlocks = 0;
    int checksumLength = 4;
    boolean persistent = true;
    int maxRetries = 2;
    boolean hasSplitfileSingleCryptoKey = false;
    AccumulatedSizes acc =
        SplitFileFetcherStorageLayout.accumulateSizes(
            segmentKeys,
            crossCheckBlocks,
            hasSplitfileSingleCryptoKey,
            checksumLength,
            maxRetries,
            persistent);
    long storedBlocksLength = (long) acc.splitfileDataBlocks() * CHKBlock.DATA_LENGTH;

    SplitFileFetcherSegmentStorage[] segments = new SplitFileFetcherSegmentStorage[2];
    SplitFileFetcherStorage parent =
        newMinimalParent(segments, storedBlocksLength, storedBlocksLength + acc.storedKeysLength());
    setFinalOnParent(parent, "keyListener", keyListener);
    setFinalOnParent(parent, "fetcher", fetcherCallback);

    FetchContext fetchContext = Mockito.mock(FetchContext.class);
    Mockito.when(fetchContext.getMaxDataBlocksPerSegment()).thenReturn(10);
    Mockito.when(fetchContext.getMaxCheckBlocksPerSegment()).thenReturn(10);

    KeySalter salter = _ -> new byte[] {1, 2, 3, 4};

    SegmentsBuildContext ctx = new SegmentsBuildContext();
    ctx.parent = parent;
    ctx.segments = segments;
    ctx.segmentKeys = segmentKeys;
    ctx.metadata = Mockito.mock(Metadata.class);
    ctx.crossCheckBlocks = crossCheckBlocks;
    ctx.blocksPerSegment = 3;
    ctx.checkBlocksPerSegment = 1;
    ctx.origFetchContext = fetchContext;
    ctx.salt = salter;
    ctx.keysFetching = Mockito.mock(KeysFetchingLocally.class);
    ctx.acc = acc;
    ctx.storedBlocksLength = storedBlocksLength;
    ctx.storedCrossCheckBlocksLength = 0;
    ctx.completeViaTruncation = false;
    ctx.persistent = persistent;
    ctx.hasSplitfileSingleCryptoKey = hasSplitfileSingleCryptoKey;
    ctx.checksumLength = checksumLength;

    SplitFileFetcherSegmentsInit init = SplitFileFetcherSegmentsBuilder.initSegmentsAndKeys(ctx);

    assertNotNull(init);
    assertEquals(2, init.segments.length);
    assertNotNull(init.crossSegments);
    assertEquals(0, init.crossSegments.length);

    SplitFileFetcherSegmentStorage seg0 = init.segments[0];
    SplitFileFetcherSegmentStorage seg1 = init.segments[1];
    assertEquals(0L, seg0.segmentBlockDataOffset);
    assertEquals(2L * CHKBlock.DATA_LENGTH, seg0.segmentCrossCheckBlockDataOffset);
    assertEquals(2L * CHKBlock.DATA_LENGTH, seg1.segmentBlockDataOffset);
    assertEquals(5L * CHKBlock.DATA_LENGTH, seg1.segmentCrossCheckBlockDataOffset);

    //noinspection PointlessArithmeticExpression
    int totalKeys = (2 + 1) + (3 + 0);
    verify(keyListener, times(totalKeys)).addKey(any(), anyInt(), eq(salter));
    verify(keyListener, times(1)).finishedSetup();
    verify(fetcherCallback, times(1))
        .setSplitfileBlocks(acc.splitfileDataBlocks(), acc.splitfileCheckBlocks());
  }

  @Test
  void initSegmentsAndKeys_whenBlockLimitExceeded_throwsFetchException() throws Exception {
    SplitFileSegmentKeys keys = newSegmentKeys(4, 1);
    SplitFileSegmentKeys[] segmentKeys = new SplitFileSegmentKeys[] {keys};

    AccumulatedSizes acc =
        SplitFileFetcherStorageLayout.accumulateSizes(segmentKeys, 0, false, 4, 1, true);
    long storedBlocksLength = (long) acc.splitfileDataBlocks() * CHKBlock.DATA_LENGTH;

    SplitFileFetcherSegmentStorage[] segments = new SplitFileFetcherSegmentStorage[1];
    SplitFileFetcherStorage parent =
        newMinimalParent(segments, storedBlocksLength, storedBlocksLength + acc.storedKeysLength());
    setFinalOnParent(parent, "keyListener", keyListener);

    FetchContext fetchContext = Mockito.mock(FetchContext.class);
    Mockito.when(fetchContext.getMaxDataBlocksPerSegment()).thenReturn(2);

    SegmentsBuildContext ctx = new SegmentsBuildContext();
    ctx.parent = parent;
    ctx.segments = segments;
    ctx.segmentKeys = segmentKeys;
    ctx.metadata = Mockito.mock(Metadata.class);
    ctx.crossCheckBlocks = 0;
    ctx.blocksPerSegment = 4;
    ctx.checkBlocksPerSegment = 1;
    ctx.origFetchContext = fetchContext;
    ctx.salt = _ -> new byte[] {7, 8};
    ctx.keysFetching = null;
    ctx.acc = acc;
    ctx.storedBlocksLength = storedBlocksLength;
    ctx.storedCrossCheckBlocksLength = 0;
    ctx.completeViaTruncation = false;
    ctx.persistent = true;
    ctx.hasSplitfileSingleCryptoKey = false;
    ctx.checksumLength = 4;

    FetchException ex =
        assertThrows(
            FetchException.class, () -> SplitFileFetcherSegmentsBuilder.initSegmentsAndKeys(ctx));
    assertEquals(FetchExceptionMode.TOO_MANY_BLOCKS_PER_SEGMENT, ex.mode);
  }

  @Test
  void initSegmentsFromStream_whenTotalsMatch_returnsSegmentsAndStream() throws Exception {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    dos.writeInt(2);
    dos.writeInt(1);
    dos.writeInt(1);
    dos.writeInt(0);
    dos.close();

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    SplitFileFetcherSegmentStorage[] segments = new SplitFileFetcherSegmentStorage[1];
    SplitFileFetcherStorage parent = newMinimalParent(segments, 0L, 0L);

    SplitFileFetcherSegmentsLoadParams params =
        new SplitFileFetcherSegmentsLoadParams(
            parent,
            2,
            1,
            1,
            dis,
            false,
            Mockito.mock(KeysFetchingLocally.class),
            segments,
            4,
            false,
            0L,
            0L,
            3L * CHKBlock.DATA_LENGTH + 1);

    SplitFileFetcherSegmentsInit init =
        SplitFileFetcherSegmentsBuilder.initSegmentsFromStream(params);

    assertNotNull(init.segments[0]);
    assertSame(dis, init.remainingStream);
    assertEquals(2, init.segments[0].dataBlocks);
    assertEquals(1, init.segments[0].checkBlocks);
    assertEquals(1, init.segments[0].crossSegmentCheckBlocks);
    assertEquals(0L, init.segments[0].segmentBlockDataOffset);
    assertEquals(2L * CHKBlock.DATA_LENGTH, init.segments[0].segmentCrossCheckBlockDataOffset);
  }

  @Test
  void initSegmentsFromStream_whenTotalsMismatch_throwsStorageFormatException() throws Exception {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buildSegmentStream(1, 0)));

    SplitFileFetcherSegmentStorage[] segments = new SplitFileFetcherSegmentStorage[1];
    SplitFileFetcherStorage parent = newMinimalParent(segments, 0L, 0L);

    SplitFileFetcherSegmentsLoadParams params =
        new SplitFileFetcherSegmentsLoadParams(
            parent,
            2,
            0,
            0,
            dis,
            false,
            null,
            segments,
            4,
            false,
            0L,
            0L,
            CHKBlock.DATA_LENGTH * 2L);

    StorageFormatException ex =
        assertThrows(
            StorageFormatException.class,
            () -> SplitFileFetcherSegmentsBuilder.initSegmentsFromStream(params));
    assertEquals("Total data blocks 1 but expected 2", ex.getMessage());
  }

  @Test
  void initSegmentsFromStream_whenOffsetsPastRaf_throwsStorageFormatException() throws Exception {
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buildSegmentStream(2, 1)));

    SplitFileFetcherSegmentStorage[] segments = new SplitFileFetcherSegmentStorage[1];
    SplitFileFetcherStorage parent = newMinimalParent(segments, 0L, 0L);

    SplitFileFetcherSegmentsLoadParams params =
        new SplitFileFetcherSegmentsLoadParams(
            parent, 2, 0, 1, dis, false, null, segments, 4, false, 0L, 0L, CHKBlock.DATA_LENGTH);

    StorageFormatException ex =
        assertThrows(
            StorageFormatException.class,
            () -> SplitFileFetcherSegmentsBuilder.initSegmentsFromStream(params));
    long expectedOffset = 3L * CHKBlock.DATA_LENGTH;
    assertEquals(
        "Data offset past end of file " + expectedOffset + " of " + CHKBlock.DATA_LENGTH,
        ex.getMessage());
  }

  private SplitFileFetcherStorage newMinimalParent(
      SplitFileFetcherSegmentStorage[] segments, long offsetKeyList, long offsetSegmentStatus) {
    SplitFileFetcherStorage parent = Mockito.mock(SplitFileFetcherStorage.class);
    setFinalOnParent(parent, "segments", segments);
    setFinalOnParent(parent, "random", new DeterministicRandomSource(42L));
    setFinalOnParent(parent, "maxRetries", 1);
    setFinalOnParent(parent, "cooldownTries", 2);
    setFinalOnParent(parent, "cooldownLength", 1000L);
    setFinalOnParent(parent, "checksumLength", 4);
    setFinalOnParent(parent, "persistent", true);
    setFinalOnParent(parent, "splitfileSingleCryptoAlgorithm", (byte) 2);
    setFinalOnParent(parent, "splitfileSingleCryptoKey", null);
    setFinalOnParent(parent, "jobRunner", jobRunner);
    setFinalOnParent(parent, "memoryLimitedJobRunner", memoryLimitedJobRunner);
    setFinalOnParent(parent, "offsetKeyList", offsetKeyList);
    setFinalOnParent(parent, "offsetSegmentStatus", offsetSegmentStatus);
    setFinalOnParent(parent, "fecCodec", Mockito.mock(network.crypta.client.FECCodec.class));
    Mockito.lenient().when(parent.lastBlockMightNotBePadded()).thenReturn(false);
    return parent;
  }

  private static void setFinalOnParent(Object parent, String fieldName, Object value) {
    try {
      Field f = SplitFileFetcherStorage.class.getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(parent, value);
    } catch (Exception e) {
      throw new AssertionError("Failed to set final field '" + fieldName + "'", e);
    }
  }

  private static SplitFileSegmentKeys newSegmentKeys(int dataBlocks, int checkBlocks)
      throws Exception {
    byte algo = (byte) 2;
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(dataBlocks, checkBlocks, null, algo);
    for (int i = 0; i < dataBlocks + checkBlocks; i++) {
      byte[] rk = new byte[NodeCHK.KEY_LENGTH];
      rk[0] = (byte) (11 + i);
      byte[] ck = new byte[ClientCHK.CRYPTO_KEY_LENGTH];
      ck[0] = (byte) (77 + i);
      ClientCHK key = new ClientCHK(rk, ck, ClientCHK.getExtra(algo, (short) -1, false));
      keys.setKey(i, key);
    }
    return keys;
  }

  private static byte[] buildSegmentStream(int dataBlocks, int crossCheckBlocks)
      throws IOException {
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    dos.writeInt(dataBlocks);
    dos.writeInt(crossCheckBlocks);
    dos.writeInt(0);
    dos.writeInt(0);
    dos.close();
    return bos.toByteArray();
  }

  private static final class DeterministicRandomSource extends RandomSource {
    private final Random rnd;

    private DeterministicRandomSource(long seed) {
      this.rnd = new Random(seed);
    }

    @Override
    protected synchronized int next(int bits) {
      return rnd.nextInt(1 << bits);
    }

    @Override
    public int acceptEntropy(EntropySource source, long data, int entropyGuess) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource timer) {
      return 0;
    }

    @Override
    public int acceptTimerEntropy(EntropySource fnpTimingSource, double bias) {
      return 0;
    }

    @Override
    public int acceptEntropyBytes(
        EntropySource myPacketDataSource, byte[] buf, int offset, int length, double bias) {
      return 0;
    }

    @Override
    public void close() {
      // No-op test stub.
    }
  }
}
