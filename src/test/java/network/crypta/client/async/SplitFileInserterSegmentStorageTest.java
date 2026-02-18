package network.crypta.client.async;

import java.io.DataInput;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Random;
import network.crypta.client.async.SplitFileInserterSegmentStorage.BlockInsert;
import network.crypta.client.async.SplitFileInserterSegmentStorage.MissingKeyException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.node.KeysFetchingLocally;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100", "java:S3011"})
@ExtendWith(MockitoExtension.class)
class SplitFileInserterSegmentStorageTest {

  @Mock private KeysFetchingLocally keysFetching;

  private static final byte CRYPTO_ALGO = Key.ALGO_AES_CTR_256_SHA256;

  private static final class DummyChecksumChecker extends ChecksumChecker {
    private final int len;

    DummyChecksumChecker(int len) {
      this.len = len;
    }

    @Override
    public int checksumLength() {
      return len;
    }

    @Override
    public OutputStream checksumWriter(OutputStream os, int skipPrefix) {
      // Pass-through writer for tests; we don't rely on it in these tests.
      return os;
    }

    @Override
    public byte[] appendChecksum(byte[] data) {
      byte[] out = new byte[data.length + len];
      System.arraycopy(data, 0, out, 0, data.length);
      // Fill checksum bytes deterministically.
      for (int i = data.length; i < out.length; i++) out[i] = (byte) 0x5A;
      return out;
    }

    @Override
    public boolean checkChecksum(byte[] data, int offset, int length, byte[] checksum) {
      // Not used by tests.
      return true;
    }

    @Override
    public byte[] generateChecksum(byte[] bufToChecksum, int offset, int length) {
      byte[] c = new byte[len];
      Arrays.fill(c, (byte) 0x5A);
      return c;
    }

    @Override
    public void copyAndStripChecksum(InputStream is, OutputStream os, long length) {
      throw new UnsupportedOperationException("not used in these tests");
    }

    @Override
    public void readAndChecksum(DataInput is, byte[] buf, int offset, int length) {
      throw new UnsupportedOperationException("not used in these tests");
    }

    @Override
    public int getChecksumTypeID() {
      return ChecksumChecker.CHECKSUM_CRC;
    }
  }

  private static void setChecker(Object target, ChecksumChecker checker) throws Exception {
    Field f = SplitFileInserterStorage.class.getDeclaredField("checker");
    f.setAccessible(true);
    f.set(target, checker);
  }

  private static SplitFileInserterSegmentStorage newSegment(
      SplitFileInserterStorage parent,
      int segNo,
      int dataBlocks,
      int checkBlocks,
      int crossCheckBlocks,
      int keyLength,
      byte[] splitfileCryptoKey,
      KeysFetchingLocally keysFetching) {
    return new SplitFileInserterSegmentStorage(
        parent,
        segNo,
        new SplitFileInserterSegmentStorage.Params()
            .blocks(dataBlocks, checkBlocks, crossCheckBlocks)
            .keys(keyLength, CRYPTO_ALGO, splitfileCryptoKey)
            .codec(new Random(1234), 3, 0, keysFetching));
  }

  @Test
  void getKeyLength_whenHasSplitfileKeyTrue_returnsExpectedLength() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);

    // Act
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);

    // Assert: 1 (present flag) + 32 (routing key) + 4 (checksum)
    assertEquals(1 + NodeCHK.KEY_LENGTH + checker.checksumLength(), keyLen);
  }

  @Test
  void getKeyLength_whenHasSplitfileKeyFalse_returnsExpectedLength() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(false);

    // Act
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);

    // Assert: 1 (present) + 5 (extra) + 32 (routing) + 32 (crypto) + checksum
    int rawKeyLen = 1 + ClientCHK.EXTRA_LENGTH + NodeCHK.KEY_LENGTH + ClientCHK.CRYPTO_KEY_LENGTH;
    assertEquals(rawKeyLen + checker.checksumLength(), keyLen);
  }

  @Test
  void setKey_whenMissing_thenWritesAndMarksAllKeys() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    lenient().when(parent.hasFinished()).thenReturn(false);
    // Return zeros to simulate missing keys on read
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    when(parent.innerReadSegmentKey(anyInt(), anyInt())).thenReturn(new byte[keyLen]);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);

    byte[] splitfileKey = new byte[32];
    for (int i = 0; i < splitfileKey.length; i++) splitfileKey[i] = (byte) i;
    SplitFileInserterSegmentStorage segment =
        newSegment(
            parent, 0, /*data*/ 2, /*check*/ 1, /*cross*/ 1, keyLen, splitfileKey, keysFetching);

    // Prepare a deterministic block key
    byte[] payload = new byte[CHKBlock.DATA_LENGTH];
    for (int i = 0; i < payload.length; i++) payload[i] = (byte) (i & 0xFF);
    ClientCHKBlock blk = segment.encodeBlock(payload);
    ClientCHK key = blk.getClientKey();

    // Act: set keys for all blocks
    int totalBlocks = 2 + 1 + 1;
    ArgumentCaptor<byte[]> written = ArgumentCaptor.forClass(byte[].class);
    for (int b = 0; b < totalBlocks; b++) {
      segment.setKey(b, key);
    }

    // Assert
    verify(parent, times(totalBlocks)).innerWriteSegmentKey(anyInt(), anyInt(), written.capture());
    for (byte[] buf : written.getAllValues()) {
      assertEquals(keyLen, buf.length);
    }
    assertEquals(keyLen * totalBlocks, segment.storedKeysLength());
    Assertions.assertTrue(segment.hasKeys());
    verify(parent, times(1)).onHasKeys(segment);
  }

  @Test
  void setKey_whenExistingDifferentKey_throwsIOException() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);

    byte[] splitfileKey = new byte[32];
    for (int i = 0; i < splitfileKey.length; i++) splitfileKey[i] = (byte) (255 - i);
    SplitFileInserterSegmentStorage segment =
        newSegment(
            parent, 1, /*data*/ 1, /*check*/ 1, /*cross*/ 0, keyLen, splitfileKey, keysFetching);

    // Write a first key and capture its stored bytes via the parent mock
    ArgumentCaptor<byte[]> cap = ArgumentCaptor.forClass(byte[].class);
    byte[] bufA = new byte[CHKBlock.DATA_LENGTH];
    bufA[0] = 1; // make it different from bufB
    ClientCHK keyA = segment.encodeBlock(bufA).getClientKey();
    segment.writeKey(0, keyA);
    verify(parent).innerWriteSegmentKey(anyInt(), anyInt(), cap.capture());
    byte[] storedKeyA = cap.getValue();
    // Parent will now return the previously written bytes
    when(parent.innerReadSegmentKey(anyInt(), anyInt())).thenReturn(storedKeyA);

    // Act + Assert: setting a different key should throw
    byte[] bufB = new byte[CHKBlock.DATA_LENGTH];
    bufB[0] = 2;
    ClientCHK keyB = segment.encodeBlock(bufB).getClientKey();
    IOException ex = assertThrows(IOException.class, () -> segment.setKey(0, keyB));
    assertNotNull(ex.getMessage());
  }

  @Test
  void readKey_whenMissing_throwsMissingKeyException() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    when(parent.innerReadSegmentKey(anyInt(), anyInt())).thenReturn(new byte[keyLen]);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);

    byte[] splitfileKey = new byte[32];
    SplitFileInserterSegmentStorage segment =
        newSegment(
            parent, 0, /*data*/ 1, /*check*/ 0, /*cross*/ 0, keyLen, splitfileKey, keysFetching);

    // Act + Assert
    assertThrows(MissingKeyException.class, () -> segment.readKey(0));
  }

  @Test
  void encodeBlock_withCryptoKey_returnsClientKeyWithAlgo() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    byte[] splitfileKey = new byte[32];
    for (int i = 0; i < splitfileKey.length; i++) splitfileKey[i] = (byte) (i * 3);
    SplitFileInserterSegmentStorage segment =
        newSegment(
            parent, 0, /*data*/ 1, /*check*/ 0, /*cross*/ 0, keyLen, splitfileKey, keysFetching);

    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0x7F);

    // Act
    ClientCHKBlock block = segment.encodeBlock(data);

    // Assert
    assertNotNull(block);
    ClientCHK key = block.getClientKey();
    assertEquals(CRYPTO_ALGO, key.getCryptoAlgorithm());
    // Ensure the client key carries the provided crypto key material.
    assertEquals(splitfileKey.length, key.getCryptoKey().length);
    for (int i = 0; i < splitfileKey.length; i++) {
      assertEquals(splitfileKey[i], key.getCryptoKey()[i]);
    }
  }

  @Test
  void blockInsert_equalsAndHashCode_basedOnSegmentAndBlock() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    SplitFileInserterSegmentStorage segA =
        newSegment(parent, 0, 1, 0, 0, keyLen, new byte[32], keysFetching);
    SplitFileInserterSegmentStorage segB =
        newSegment(parent, 1, 1, 0, 0, keyLen, new byte[32], keysFetching);

    BlockInsert a1 = new BlockInsert(segA, 0);
    BlockInsert a2 = new BlockInsert(segA, 0);
    BlockInsert b1 = new BlockInsert(segA, 1);
    BlockInsert c1 = new BlockInsert(segB, 0);

    // Act & Assert
    assertEquals(a1, a2);
    assertEquals(a1.hashCode(), a2.hashCode());
    assertNotEquals(a1, b1);
    assertNotEquals(a1, c1);
  }

  @Test
  void storeStatus_whenOpenFails_keepsDirtyAndRetries() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    // Segment params
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    SplitFileInserterSegmentStorage segment =
        newSegment(
            parent, 0, /*data*/ 1, /*check*/ 0, /*cross*/ 0, keyLen, new byte[32], keysFetching);

    // Make storage persistent and unfinished via reflection + stubs
    Field p = SplitFileInserterStorage.class.getDeclaredField("persistent");
    p.setAccessible(true);
    p.setBoolean(parent, true);
    when(parent.hasFinished()).thenReturn(false);
    when(parent.segmentStatusOffset(0)).thenReturn(123L);

    // First attempt: return an OutputStream that throws on write (simulates open/write failure)
    // Second attempt: provide a no-op OutputStream that closes cleanly
    when(parent.writeChecksummedTo(anyLong(), anyInt()))
        .thenReturn(
            new OutputStream() {
              @Override
              public void write(int b) throws IOException {
                throw new IOException("open failed");
              }
            })
        .thenReturn(
            new OutputStream() {
              @Override
              public void write(int b) {
                /* no-op */
              }
            });

    // Mark metadata dirty so storeStatus() will attempt a write
    Field md = SplitFileInserterSegmentStorage.class.getDeclaredField("metadataDirty");
    md.setAccessible(true);
    md.setBoolean(segment, true);

    // Act: first call fails to open; should NOT clear dirty flag
    segment.storeStatus(false);
    // Assert: metadataDirty still true so we will retry
    Assertions.assertTrue(md.getBoolean(segment));

    // Act: second call should retry and successfully open the stream, clearing the flag
    segment.storeStatus(false);
    Assertions.assertFalse(md.getBoolean(segment));
  }

  @Test
  void chooseBlock_afterCancel_returnsNull() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    SplitFileInserterSegmentStorage segment =
        newSegment(parent, 0, 2, 1, 1, keyLen, new byte[32], keysFetching);

    // Act
    segment.cancel();
    SplitFileInserterSegmentStorage.BlockInsert chosen = segment.chooseBlock();

    // Assert
    assertNull(chosen);
  }

  @Test
  void countSendableKeys_reflectsEncodedState() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    int dataBlocks = 3;
    int crossBlocks = 2;
    int checkBlocks = 1;
    SplitFileInserterSegmentStorage segment =
        newSegment(
            parent, 0, dataBlocks, checkBlocks, crossBlocks, keyLen, new byte[32], keysFetching);

    // Act & Assert: countFetchable counts across all blocks by design
    int totalBlocks = dataBlocks + crossBlocks + checkBlocks;
    assertEquals(totalBlocks, segment.countSendableKeys());

    // Flip encoded=true via reflection to simulate post-encode state
    Field f = SplitFileInserterSegmentStorage.class.getDeclaredField("encoded");
    f.setAccessible(true);
    f.set(segment, true);

    assertEquals(totalBlocks, segment.countSendableKeys());
  }

  @Test
  void allocateCrossDataBlock_uniqueUntilExhausted_thenMinusOne() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    int dataBlocks = 3;
    SplitFileInserterSegmentStorage segment =
        newSegment(parent, 0, dataBlocks, 0, 0, keyLen, new byte[32], keysFetching);

    // Act & Assert
    boolean[] seen = new boolean[dataBlocks];
    for (int i = 0; i < dataBlocks; i++) {
      int idx = segment.allocateCrossDataBlock(new Random(42));
      // rotate random to avoid deterministic collision path affecting test; re-seed each time OK
      if (idx >= 0) seen[idx] = true;
    }
    int count = 0;
    for (boolean b : seen) if (b) count++;
    assertEquals(dataBlocks, count);
    // Now exhausted
    assertEquals(-1, segment.allocateCrossDataBlock(new Random(42)));
  }

  @Test
  void allocateCrossCheckBlock_uniqueUntilExhausted_thenMinusOne() throws Exception {
    // Arrange
    SplitFileInserterStorage parent = mock(SplitFileInserterStorage.class);
    DummyChecksumChecker checker = new DummyChecksumChecker(4);
    setChecker(parent, checker);
    when(parent.hasSplitfileKey()).thenReturn(true);
    lenient().when(keysFetching.hasInsert(any())).thenReturn(false);
    int keyLen = SplitFileInserterSegmentStorage.getKeyLength(parent);
    int dataBlocks = 2;
    int crossBlocks = 3;
    SplitFileInserterSegmentStorage segment =
        newSegment(parent, 0, dataBlocks, 0, crossBlocks, keyLen, new byte[32], keysFetching);
    SplitFileInserterCrossSegmentStorage crossSeg =
        mock(SplitFileInserterCrossSegmentStorage.class);

    boolean[] seen = new boolean[crossBlocks];
    for (int i = 0; i < crossBlocks; i++) {
      int idx = segment.allocateCrossCheckBlock(crossSeg, new Random(7), i);
      int rel = idx - dataBlocks;
      if (rel >= 0 && rel < crossBlocks) seen[rel] = true;
    }
    int count = 0;
    for (boolean b : seen) if (b) count++;
    assertEquals(crossBlocks, count);
    // Now exhausted
    assertEquals(-1, segment.allocateCrossCheckBlock(crossSeg, new Random(7), 99));
  }
}
