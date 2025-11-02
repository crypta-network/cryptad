package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class BinaryBlobWriterTest {

  // --- Helpers

  private static ClientKeyBlock mockBlock(
      short keyType, byte[] keyBytes, byte[] headers, byte[] data, byte[] pubkey) {
    Key key = mock(Key.class);
    when(key.getType()).thenReturn(keyType);
    when(key.getKeyBytes()).thenReturn(keyBytes);

    KeyBlock keyBlock = mock(KeyBlock.class);
    when(keyBlock.getKey()).thenReturn(key);
    when(keyBlock.getRawHeaders()).thenReturn(headers);
    when(keyBlock.getRawData()).thenReturn(data);
    when(keyBlock.getPubkeyBytes()).thenReturn(pubkey);

    ClientKeyBlock ckb = mock(ClientKeyBlock.class);
    when(ckb.getKey()).thenReturn(key);
    when(ckb.getBlock()).thenReturn(keyBlock);
    return ckb;
  }

  private static byte[] readAll(Bucket b) throws IOException {
    try (InputStream is = b.getInputStream()) {
      return is.readAllBytes();
    }
  }

  private static void assertParsesSingleBlock(
      byte[] blob,
      short expectedKeyType,
      byte[] expectedKeyBytes,
      byte[] expectedHeaders,
      byte[] expectedData,
      byte[] expectedPubkey)
      throws IOException {
    try (DataInputStream dis = new DataInputStream(new java.io.ByteArrayInputStream(blob))) {
      long magic = dis.readLong();
      assertEquals(BinaryBlob.BINARY_BLOB_MAGIC, magic, "magic");
      short ver = dis.readShort();
      assertEquals(BinaryBlob.BINARY_BLOB_OVERALL_VERSION, ver, "overall version");

      int len = dis.readInt();
      short type = dis.readShort();
      short tver = dis.readShort();
      assertEquals(BinaryBlob.BLOB_BLOCK, type, "record type");
      assertEquals((short) 0, tver, "block version");

      short keyType = dis.readShort();
      int keyLen = dis.readUnsignedByte();
      int headersLen = dis.readUnsignedShort();
      int dataLen = dis.readUnsignedShort();
      int pubkeyLen = dis.readUnsignedShort();

      int expectedLen =
          9
              + expectedKeyBytes.length
              + expectedHeaders.length
              + expectedData.length
              + (expectedPubkey == null ? 0 : expectedPubkey.length);
      assertEquals(expectedLen, len, "payload length");
      assertEquals(expectedKeyType, keyType, "keyType");
      assertEquals(expectedKeyBytes.length, keyLen, "keyLen");
      assertEquals(expectedHeaders.length, headersLen, "headersLen");
      assertEquals(expectedData.length, dataLen, "dataLen");
      assertEquals(expectedPubkey == null ? 0 : expectedPubkey.length, pubkeyLen, "pubkeyLen");

      byte[] key = new byte[keyLen];
      byte[] hdr = new byte[headersLen];
      byte[] dat = new byte[dataLen];
      byte[] pub = new byte[pubkeyLen];
      dis.readFully(key);
      dis.readFully(hdr);
      dis.readFully(dat);
      dis.readFully(pub);

      assertArrayEquals(expectedKeyBytes, key, "key bytes");
      assertArrayEquals(expectedHeaders, hdr, "headers bytes");
      assertArrayEquals(expectedData, dat, "data bytes");
      if (expectedPubkey != null) {
        assertArrayEquals(expectedPubkey, pub, "pubkey bytes");
      } else {
        assertEquals(0, pub.length, "pubkey bytes length");
      }

      // Final record must be END marker
      int endLen = dis.readInt();
      short endType = dis.readShort();
      short endVer = dis.readShort();
      assertEquals(0, endLen, "end payload length");
      assertEquals(BinaryBlob.BLOB_END, endType, "end type");
      assertEquals((short) 0, endVer, "end version");

      // No extra bytes
      assertEquals(-1, dis.read(), "trailing bytes");
    }
  }

  // --- Tests

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void addKey_whenSingleBucket_expectHeaderBlockEnd(boolean withPubkey) throws Exception {
    // Arrange
    ArrayBucket out = new ArrayBucket();
    BinaryBlobWriter writer = new BinaryBlobWriter(out);
    short keyType = (short) 0x1234;
    byte[] keyBytes = new byte[] {0x01, 0x02, 0x03};
    byte[] headers = new byte[] {0x10, 0x20};
    byte[] data = new byte[] {0x55, 0x66, 0x77, 0x00};
    byte[] pubkey = withPubkey ? new byte[] {0x0A, 0x0B} : null;
    ClientKeyBlock ckb = mockBlock(keyType, keyBytes, headers, data, pubkey);

    // Act
    writer.addKey(ckb, /*context*/ null);
    writer.finalizeBucket();

    // Assert
    assertTrue(writer.isFinalized(), "finalized flag");
    Bucket result = writer.getFinalBucket();
    assertEquals(out, result, "single-bucket returns provided bucket");
    byte[] blob = readAll(result);
    assertParsesSingleBlock(blob, keyType, keyBytes, headers, data, pubkey);
  }

  @Test
  void addKey_whenDuplicateKey_expectDeduplicated() throws Exception {
    // Arrange
    ArrayBucket out = new ArrayBucket();
    BinaryBlobWriter writer = new BinaryBlobWriter(out);
    short keyType = (short) 0x2222;
    byte[] keyBytes = new byte[] {0x11};
    byte[] headers = new byte[] {0x01};
    byte[] data = new byte[] {0x02};

    ClientKeyBlock ckb = mockBlock(keyType, keyBytes, headers, data, null);

    // Act
    writer.addKey(ckb, null);
    writer.addKey(ckb, null); // duplicate; should be ignored
    writer.finalizeBucket();

    // Assert – parse and ensure there is exactly 1 block then an END
    byte[] blob = readAll(out);
    try (DataInputStream dis = new DataInputStream(new java.io.ByteArrayInputStream(blob))) {
      dis.readLong(); // magic
      dis.readShort(); // version

      int len1 = dis.readInt();
      short type1 = dis.readShort();
      short ver1 = dis.readShort();
      assertEquals(BinaryBlob.BLOB_BLOCK, type1);
      assertEquals((short) 0, ver1);

      // Skip the block payload
      dis.skipNBytes(len1);

      // Next must be END; no second block allowed
      int endLen = dis.readInt();
      short endType = dis.readShort();
      short endVer = dis.readShort();
      assertEquals(0, endLen);
      assertEquals(BinaryBlob.BLOB_END, endType);
      assertEquals((short) 0, endVer);
      assertEquals(-1, dis.read());
    }
  }

  @Test
  void getFinalBucket_whenNotFinalized_expectIllegalState() {
    ArrayBucket out = new ArrayBucket();
    BinaryBlobWriter writer = new BinaryBlobWriter(out);
    assertThrows(IllegalStateException.class, writer::getFinalBucket);
  }

  @Test
  void finalizeBucket_whenCalledTwice_expectException() throws Exception {
    ArrayBucket out = new ArrayBucket();
    BinaryBlobWriter writer = new BinaryBlobWriter(out);
    // Write minimal content so finalize writes END marker without issues
    ClientKeyBlock ckb =
        mockBlock((short) 0x0101, new byte[] {0x01}, new byte[0], new byte[0], null);
    writer.addKey(ckb, null);
    writer.finalizeBucket();
    assertThrows(BinaryBlobWriter.BinaryBlobAlreadyClosedException.class, writer::finalizeBucket);
  }

  @Test
  void addKey_whenAfterFinalize_expectException() throws Exception {
    ArrayBucket out = new ArrayBucket();
    BinaryBlobWriter writer = new BinaryBlobWriter(out);
    ClientKeyBlock first =
        mockBlock((short) 0x0101, new byte[] {0x01}, new byte[0], new byte[0], null);
    writer.addKey(first, null);
    writer.finalizeBucket();
    // Use a different key so dedupe does not short-circuit before checking finalized state
    // Create a block that exposes only a different key; do not stub getBlock(),
    // because getOutputStream() will throw before it's ever called.
    Key newKey = mock(Key.class); // no stubbing; no methods will be called before exception
    ClientKeyBlock differentKey = mock(ClientKeyBlock.class);
    when(differentKey.getKey()).thenReturn(newKey);
    assertThrows(
        BinaryBlobWriter.BinaryBlobAlreadyClosedException.class,
        () -> writer.addKey(differentKey, null));
  }

  @Test
  void getSnapshot_whenNoData_expectNoOutput() throws Exception {
    BucketFactory bf = new ArrayBucketFactory();
    BinaryBlobWriter writer = new BinaryBlobWriter(bf);
    ArrayBucket snapshot = new ArrayBucket();
    writer.getSnapshot(snapshot); // should no-op because internal list is empty
    assertEquals(0, snapshot.size());
  }

  @Test
  void bucketFactoryMode_snapshot_then_finalize_expectConsistentAndReadOnly() throws Exception {
    // Arrange
    BucketFactory bf = new ArrayBucketFactory();
    BinaryBlobWriter writer = new BinaryBlobWriter(bf);
    ClientKeyBlock b1 =
        mockBlock((short) 0x1111, new byte[] {0x01}, new byte[] {0x11}, new byte[] {0x21}, null);
    ClientKeyBlock b2 =
        mockBlock(
            (short) 0x2222,
            new byte[] {0x02},
            new byte[] {0x12},
            new byte[] {0x22},
            new byte[] {0x32});

    writer.addKey(b1, null);
    writer.addKey(b2, null);

    // Snapshot before finalize
    ArrayBucket snapshot = new ArrayBucket();
    writer.getSnapshot(snapshot);
    byte[] snapBytes = readAll(snapshot);

    // Now finalize and verify final bucket content equals snapshot and is read-only
    writer.finalizeBucket();
    Bucket finalBucket = writer.getFinalBucket();
    assertTrue(finalBucket.isReadOnly(), "final bucket should be read-only");
    byte[] finalBytes = readAll(finalBucket);
    assertArrayEquals(snapBytes, finalBytes, "snapshot must match finalized content");

    // After finalize, getSnapshot should copy without modification
    ArrayBucket copyAfterFinalize = new ArrayBucket();
    writer.getSnapshot(copyAfterFinalize);
    byte[] copied = readAll(copyAfterFinalize);
    assertArrayEquals(finalBytes, copied, "snapshot after finalize should equal final bytes");
  }
}
