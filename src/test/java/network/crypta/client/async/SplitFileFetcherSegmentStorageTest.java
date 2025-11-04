package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import network.crypta.crypt.EntropySource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherSegmentStorageTest {

  // No field-level KeysFetchingLocally mock required in this class.

  @Mock private SplitFileFetcherStorageCallback fetcherCallback;

  @Mock private PersistentJobRunner jobRunner;

  @Mock private network.crypta.support.MemoryLimitedJobRunner memoryLimitedJobRunner;

  private static void setBlockChooser(
      SplitFileFetcherSegmentStorage segment, SplitFileFetcherSegmentBlockChooser chooser) {
    try {
      Field f = SplitFileFetcherSegmentStorage.class.getDeclaredField("blockChooser");
      f.setAccessible(true);
      f.set(segment, chooser);
    } catch (Exception e) {
      throw new AssertionError("Failed to set blockChooser via reflection", e);
    }
  }

  private static void setFinalOnParent(
      SplitFileFetcherStorage parent, String fieldName, Object value) {
    try {
      Field f = SplitFileFetcherStorage.class.getDeclaredField(fieldName);
      f.setAccessible(true);
      f.set(parent, value);
    } catch (Exception e) {
      throw new AssertionError(
          "Failed to set final field '" + fieldName + "' on SplitFileFetcherStorage", e);
    }
  }

  private static class DeterministicRandomSource extends RandomSource {
    private final Random rnd;

    DeterministicRandomSource(long seed) {
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
      // No-op: deterministic test stub does not allocate external resources.
    }
  }

  private SplitFileFetcherStorage newMinimalParent() {
    SplitFileFetcherStorage parent = Mockito.mock(SplitFileFetcherStorage.class);
    // Set minimal required state used by the segment constructor and by code paths in tests.
    setFinalOnParent(parent, "segments", new SplitFileFetcherSegmentStorage[1]);
    setFinalOnParent(parent, "random", new DeterministicRandomSource(42L));
    setFinalOnParent(parent, "maxRetries", 3);
    setFinalOnParent(parent, "cooldownTries", 2);
    setFinalOnParent(parent, "cooldownLength", 1000L);
    setFinalOnParent(parent, "checksumLength", 4);
    setFinalOnParent(parent, "persistent", true);
    setFinalOnParent(parent, "splitfileSingleCryptoAlgorithm", (byte) 2);
    setFinalOnParent(parent, "splitfileSingleCryptoKey", null);
    setFinalOnParent(parent, "jobRunner", jobRunner);
    setFinalOnParent(parent, "memoryLimitedJobRunner", memoryLimitedJobRunner);
    setFinalOnParent(parent, "fetcher", fetcherCallback);
    Mockito.lenient().when(fetcherCallback.getSendableGet()).thenReturn(null);
    Mockito.lenient().when(parent.getPriorityClass()).thenReturn((short) 0);
    Mockito.lenient().when(parent.lastBlockMightNotBePadded()).thenReturn(false);
    return parent;
  }

  private static SplitFileSegmentKeys newKeys2Data(int checkBlocks) throws Exception {
    byte algo = (byte) 2;
    int dataBlocks = 2;
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(dataBlocks, checkBlocks, null, algo);
    for (int i = 0; i < dataBlocks + checkBlocks; i++) {
      byte[] rk = new byte[NodeCHK.KEY_LENGTH];
      rk[0] = (byte) (11 + i); // deterministic but unique per index
      byte[] ck = new byte[ClientCHK.CRYPTO_KEY_LENGTH];
      ck[0] = (byte) (77 + i);
      ClientCHK k = new ClientCHK(rk, ck, ClientCHK.getExtra(algo, (short) -1, false));
      keys.setKey(i, k);
    }
    return keys;
  }

  @Test
  void storedSegmentStatusLength_variousInputs_expectedLengths() {
    int len1 =
        SplitFileFetcherSegmentStorage.storedSegmentStatusLength(/*data*/ 3, /*check*/ 2, 0, true);
    // fetchedBlocks=3, totalBlocks=5 => 3*4 + 5*4
    assertEquals(32, len1);

    int len2 =
        SplitFileFetcherSegmentStorage.storedSegmentStatusLength(/*data*/ 4, /*check*/ 0, 2, false);
    // fetchedBlocks=6, totalBlocks=6 => 6*4 + 0
    assertEquals(24, len2);
  }

  @Test
  void paddedStoredSegmentStatusLength_persistentFlag_controlsChecksumPadding() {
    int base = SplitFileFetcherSegmentStorage.storedSegmentStatusLength(2, 1, 0, true);
    int padded =
        SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
            2, 1, 0, true, /*checksum*/ 4, true);
    assertEquals(base + 4, padded);

    int nonPersistent =
        SplitFileFetcherSegmentStorage.paddedStoredSegmentStatusLength(
            2, 1, 0, true, /*checksum*/ 4, false);
    assertEquals(0, nonPersistent);
  }

  @Test
  void storedKeysLength_commonKeyInfluencesLength() {
    int withCommon = SplitFileFetcherSegmentStorage.storedKeysLength(3, 2, true, 4);
    int withoutCommon = SplitFileFetcherSegmentStorage.storedKeysLength(3, 2, false, 4);
    // Expect different sizes when common decrypt key is present vs per-block keys
    assertTrue(withoutCommon > withCommon);
    assertEquals(4, withCommon - SplitFileSegmentKeys.storedKeysLength(3, 2, true));
  }

  @Test
  void ctor_fromStream_invalidCounts_throwStorageFormatException() throws Exception {
    SplitFileFetcherStorage parent = newMinimalParent();

    // dataBlocks < 1
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    dos.writeInt(0); // data
    dos.writeInt(0); // cross-check
    dos.writeInt(0); // check
    dos.close();
    final DataInputStream dis1 = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    final SplitFileFetcherStorage p1 = parent;
    assertThrows(
        StorageFormatException.class,
        () -> {
          SplitFileFetcherSegmentStorage.LoadParams lp =
              new SplitFileFetcherSegmentStorage.LoadParams();
          lp.parent = p1;
          lp.dis = dis1;
          lp.segNo = 0;
          lp.writeRetries = true;
          lp.segmentDataOffset = 0L;
          lp.segmentCrossCheckDataOffset = 0L;
          lp.segmentKeysOffset = 0L;
          lp.segmentStatusOffset = 0L;
          lp.keysFetching = Mockito.mock(KeysFetchingLocally.class);
          new SplitFileFetcherSegmentStorage(lp);
        });

    // crossCheckBlocks < 0
    bos.reset();
    dos = new DataOutputStream(bos);
    dos.writeInt(1); // data
    dos.writeInt(-1); // cross-check
    dos.writeInt(0); // check
    dos.close();
    final DataInputStream dis2 = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    final SplitFileFetcherStorage p2 = parent;
    assertThrows(
        StorageFormatException.class,
        () -> {
          SplitFileFetcherSegmentStorage.LoadParams lp =
              new SplitFileFetcherSegmentStorage.LoadParams();
          lp.parent = p2;
          lp.dis = dis2;
          lp.segNo = 0;
          lp.writeRetries = true;
          lp.segmentDataOffset = 0L;
          lp.segmentCrossCheckDataOffset = 0L;
          lp.segmentKeysOffset = 0L;
          lp.segmentStatusOffset = 0L;
          lp.keysFetching = Mockito.mock(KeysFetchingLocally.class);
          new SplitFileFetcherSegmentStorage(lp);
        });

    // totalBlocks > 256
    bos.reset();
    dos = new DataOutputStream(bos);
    dos.writeInt(200);
    dos.writeInt(0);
    dos.writeInt(200);
    dos.close();
    final DataInputStream dis3 = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    final SplitFileFetcherStorage p3 = parent;
    assertThrows(
        StorageFormatException.class,
        () -> {
          SplitFileFetcherSegmentStorage.LoadParams lp =
              new SplitFileFetcherSegmentStorage.LoadParams();
          lp.parent = p3;
          lp.dis = dis3;
          lp.segNo = 0;
          lp.writeRetries = true;
          lp.segmentDataOffset = 0L;
          lp.segmentCrossCheckDataOffset = 0L;
          lp.segmentKeysOffset = 0L;
          lp.segmentStatusOffset = 0L;
          lp.keysFetching = Mockito.mock(KeysFetchingLocally.class);
          new SplitFileFetcherSegmentStorage(lp);
        });
  }

  @Test
  void chooseRandomKey_whenChooserProvidesIndex_returnsIndex() throws Exception {
    // Arrange: real segment with injected chooser mock
    SplitFileFetcherStorage parent = newMinimalParent();
    SplitFileSegmentKeys keys = newKeys2Data(/*check*/ 1);
    SplitFileFetcherSegmentStorage.InitParams ip = new SplitFileFetcherSegmentStorage.InitParams();
    ip.parent = parent;
    ip.segNumber = 0;
    ip.dataBlocks = 2;
    ip.checkBlocks = 1;
    ip.crossCheckBlocks = 0;
    ip.segmentDataOffset = 0L;
    ip.segmentCrossCheckDataOffset = -1L;
    ip.segmentKeysOffset = 0L;
    ip.segmentStatusOffset = 0L;
    ip.writeRetries = true;
    ip.keys = keys;
    ip.keysFetching = Mockito.mock(KeysFetchingLocally.class);
    SplitFileFetcherSegmentStorage seg = new SplitFileFetcherSegmentStorage(ip);

    SplitFileFetcherSegmentBlockChooser chooser =
        Mockito.mock(SplitFileFetcherSegmentBlockChooser.class);
    Mockito.when(chooser.chooseKey()).thenReturn(1);
    setBlockChooser(seg, chooser);

    // Act
    int chosen = seg.chooseRandomKey();

    // Assert
    assertEquals(1, chosen);
  }

  @Test
  void chooseRandomKey_whenNoEligibleKeys_triggersParentCooldownAndReturnsMinusOne()
      throws Exception {
    SplitFileFetcherStorage parent = newMinimalParent();
    SplitFileSegmentKeys keys = newKeys2Data(0);
    SplitFileFetcherSegmentStorage.InitParams ip2 = new SplitFileFetcherSegmentStorage.InitParams();
    ip2.parent = parent;
    ip2.segNumber = 0;
    ip2.dataBlocks = 2;
    ip2.checkBlocks = 0;
    ip2.crossCheckBlocks = 0;
    ip2.segmentDataOffset = 0L;
    ip2.segmentCrossCheckDataOffset = -1L;
    ip2.segmentKeysOffset = 0L;
    ip2.segmentStatusOffset = 0L;
    ip2.writeRetries = true;
    ip2.keys = keys;
    ip2.keysFetching = Mockito.mock(KeysFetchingLocally.class);
    SplitFileFetcherSegmentStorage seg = new SplitFileFetcherSegmentStorage(ip2);

    SplitFileFetcherSegmentBlockChooser chooser =
        Mockito.mock(SplitFileFetcherSegmentBlockChooser.class);
    long wakeup = System.currentTimeMillis() + 10_000L;
    Mockito.when(chooser.chooseKey()).thenReturn(-1);
    Mockito.when(chooser.overallCooldownTime()).thenReturn(wakeup);
    setBlockChooser(seg, chooser);

    // Act
    int chosen = seg.chooseRandomKey();

    // Assert
    assertEquals(-1, chosen);
    Mockito.verify(parent, Mockito.times(1)).increaseCooldown(wakeup);
  }

  @Test
  void definitelyWantKey_whenKeyPresent_returnsTrue() throws Exception {
    SplitFileFetcherStorage parent = newMinimalParent();
    SplitFileSegmentKeys keys = newKeys2Data(1);
    // Build a segment using the keys cache path (constructor sets a SoftReference)
    SplitFileFetcherSegmentStorage.InitParams ip3 = new SplitFileFetcherSegmentStorage.InitParams();
    ip3.parent = parent;
    ip3.segNumber = 0;
    ip3.dataBlocks = 2;
    ip3.checkBlocks = 1;
    ip3.crossCheckBlocks = 0;
    ip3.segmentDataOffset = 0L;
    ip3.segmentCrossCheckDataOffset = -1L;
    ip3.segmentKeysOffset = 0L;
    ip3.segmentStatusOffset = 0L;
    ip3.writeRetries = true;
    ip3.keys = keys;
    ip3.keysFetching = Mockito.mock(KeysFetchingLocally.class);
    SplitFileFetcherSegmentStorage seg = new SplitFileFetcherSegmentStorage(ip3);

    ClientCHK ck = keys.getKey(0, null, false);
    NodeCHK nk = ck.getNodeCHK();
    assertTrue(seg.definitelyWantKey(nk));
  }

  @Test
  void countAndListUnfetchedKeys_initialState_reportsAll() throws Exception {
    SplitFileFetcherStorage parent = newMinimalParent();
    SplitFileSegmentKeys keys = newKeys2Data(1);
    SplitFileFetcherSegmentStorage.InitParams ip6 = new SplitFileFetcherSegmentStorage.InitParams();
    ip6.parent = parent;
    ip6.segNumber = 0;
    ip6.dataBlocks = 2;
    ip6.checkBlocks = 1;
    ip6.crossCheckBlocks = 0;
    ip6.segmentDataOffset = 0L;
    ip6.segmentCrossCheckDataOffset = -1L;
    ip6.segmentKeysOffset = 0L;
    ip6.segmentStatusOffset = 0L;
    ip6.writeRetries = true;
    ip6.keys = keys;
    ip6.keysFetching = Mockito.mock(KeysFetchingLocally.class);
    SplitFileFetcherSegmentStorage seg = new SplitFileFetcherSegmentStorage(ip6);

    assertEquals(3, seg.countUnfetchedKeys(), "All blocks unfetched at start");
    List<Key> out = new ArrayList<>();
    seg.getUnfetchedKeys(out);
    assertEquals(3, out.size());
  }

  @Test
  @DisplayName("checkAndGetBlockData_whenStoredAndValid_returnsData")
  void checkAndGetBlockData_whenStoredAndValid_returnsData() throws Exception {
    // Parent with in-memory block storage behavior.
    SplitFileFetcherStorage parent = newMinimalParent();

    // Capture writes and serve them back on reads by slot.
    Map<Integer, byte[]> slotData = new HashMap<>();
    Mockito.lenient()
        .doAnswer(
            inv -> {
              int slot = inv.getArgument(1, Integer.class);
              byte[] data = inv.getArgument(2, byte[].class);
              slotData.put(slot, data.clone());
              return null;
            })
        .when(parent)
        .writeBlock(any(SplitFileFetcherSegmentStorage.class), anyInt(), any(byte[].class));
    Mockito.lenient()
        .when(parent.readBlock(any(SplitFileFetcherSegmentStorage.class), anyInt()))
        .thenAnswer(
            inv -> {
              int slot = inv.getArgument(1, Integer.class);
              byte[] buf = slotData.get(slot);
              return buf == null ? null : buf.clone();
            });

    // RAFLock stub used by innerOnGotKey and read paths.
    RAFLock lock = Mockito.mock(RAFLock.class, Answers.RETURNS_DEFAULTS);
    Mockito.lenient().when(parent.lockRAFOpen()).thenReturn(lock);

    // Single valid block key generated from data + crypto for deterministic verification.
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    new SecureRandom(new byte[] {1, 2, 3, 4}).nextBytes(data);
    byte[] crypto = new byte[ClientCHK.CRYPTO_KEY_LENGTH];
    crypto[0] = 7;
    ClientCHKBlock enc = ClientCHKBlock.encodeSplitfileBlock(data, crypto, (byte) 2);
    ClientCHK actualKey = enc.getClientKey();

    // Keys list contains the computed key for block 0 only.
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(1, 0, null, (byte) 2);
    keys.setKey(0, actualKey);

    SplitFileFetcherSegmentStorage.InitParams ip4 = new SplitFileFetcherSegmentStorage.InitParams();
    ip4.parent = parent;
    ip4.segNumber = 0;
    ip4.dataBlocks = 2; // >1 to avoid tryStartDecode immediately
    ip4.checkBlocks = 0;
    ip4.crossCheckBlocks = 0;
    ip4.segmentDataOffset = 0L;
    ip4.segmentCrossCheckDataOffset = -1L;
    ip4.segmentKeysOffset = 0L;
    ip4.segmentStatusOffset = 0L;
    ip4.writeRetries = true;
    ip4.keys = keys;
    ip4.keysFetching = Mockito.mock(KeysFetchingLocally.class);
    SplitFileFetcherSegmentStorage seg = new SplitFileFetcherSegmentStorage(ip4);

    // Simulate storing a fetched block 0 (decoded form) via internal path.
    // Minimal job runner callbacks used in innerOnGotKey.
    Mockito.lenient()
        .doAnswer(
            inv -> {
              PersistentJob job = inv.getArgument(0);
              job.run(Mockito.mock(ClientContext.class));
              return null;
            })
        .when(jobRunner)
        .queueNormalOrDrop(any(PersistentJob.class));

    // innerOnGotKey requires a ClientCHKBlock and decoded bytes.
    boolean saved = seg.innerOnGotKey(actualKey.getNodeCHK(), enc, keys, /*blockNumber*/ 0, data);
    assertTrue(saved, "Block should be written to storage");

    // Act
    byte[] readBack = seg.checkAndGetBlockData(0);

    // Assert
    assertNotNull(readBack);
    assertArrayEquals(data, readBack, "Stored data should be returned and validated against key");
  }

  @Test
  void writeFixedMetadata_writesCountsInOrder() throws Exception {
    SplitFileFetcherStorage parent = newMinimalParent();
    SplitFileSegmentKeys keys = newKeys2Data(1);
    SplitFileFetcherSegmentStorage.InitParams ip5 = new SplitFileFetcherSegmentStorage.InitParams();
    ip5.parent = parent;
    ip5.segNumber = 5;
    ip5.dataBlocks = 2;
    ip5.checkBlocks = 1;
    ip5.crossCheckBlocks = 0;
    ip5.segmentDataOffset = 0L;
    ip5.segmentCrossCheckDataOffset = -1L;
    ip5.segmentKeysOffset = 0L;
    ip5.segmentStatusOffset = 0L;
    ip5.writeRetries = true;
    ip5.keys = keys;
    ip5.keysFetching = Mockito.mock(KeysFetchingLocally.class);
    SplitFileFetcherSegmentStorage seg = new SplitFileFetcherSegmentStorage(ip5);

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    seg.writeFixedMetadata(dos);
    dos.close();
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    assertEquals(2, dis.readInt());
    assertEquals(0, dis.readInt());
    assertEquals(1, dis.readInt());
  }
}
