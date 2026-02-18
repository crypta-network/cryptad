package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.stream.Stream;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class AEADCryptBucketTest {

  @Mock private FilenameGenerator filenameGenerator;
  @Mock private PersistentFileTracker fileTracker;

  @TempDir File tempDir;

  private static byte[] key(int bytes) {
    byte[] k = new byte[bytes];
    for (int i = 0; i < k.length; i++) k[i] = (byte) (i * 7 + 3);
    return k;
  }

  private static byte[] data(int len) {
    byte[] d = new byte[len];
    for (int i = 0; i < d.length; i++) d[i] = (byte) (i * 31 + 11);
    return d;
  }

  @Test
  void getName_whenUsingArrayUnderlying_prefixesUnderlyingName() {
    ArrayBucket underlying = new ArrayBucket("under");
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(16));
    assertEquals("AEADEncrypted:under", bucket.getName());
  }

  @Test
  void size_whenZeroPlaintext_returnsZeroAndUnderlyingHasOverhead() throws IOException {
    ArrayBucket underlying = new ArrayBucket();
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(16));
    // Write zero bytes – closing triggers nonce+tag write
    bucket.getOutputStreamUnbuffered().close();
    assertEquals(0, bucket.size());
    assertEquals(AEADOutputStream.AES_OVERHEAD, underlying.size());
  }

  static Stream<Integer> lengths() {
    return Stream.of(0, 1, 2, 15, 16, 17, 31, 32, 1000);
  }

  static Stream<Integer> keySizes() {
    return Stream.of(16, 24, 32);
  }

  @ParameterizedTest(name = "roundtrip length={0}")
  @MethodSource("lengths")
  void writeThenRead_roundTripMatchesOriginal(int length) throws IOException {
    ArrayBucket underlying = new ArrayBucket();
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(16));

    byte[] input = data(length);
    try (var os = bucket.getOutputStreamUnbuffered()) {
      os.write(input);
    }

    assertEquals(length + AEADCryptBucket.OVERHEAD, underlying.size());
    assertEquals(length, bucket.size());

    byte[] roundtrip = BucketTools.toByteArray(bucket);
    assertArrayEquals(input, roundtrip);
  }

  @ParameterizedTest(name = "keySize={0} roundtrip")
  @MethodSource("keySizes")
  void writeThenRead_withDifferentKeySizes_roundTrip(int keySize) throws IOException {
    ArrayBucket underlying = new ArrayBucket();
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(keySize));
    byte[] input = data(123);
    try (var os = bucket.getOutputStreamUnbuffered()) {
      os.write(input);
    }
    assertEquals(input.length + AEADCryptBucket.OVERHEAD, underlying.size());
    assertArrayEquals(input, BucketTools.toByteArray(bucket));
  }

  @Test
  void copy_toAnotherBucket_preservesPlaintext() throws IOException {
    int length = 902; // not divisible by 16
    ArrayBucket underlying = new ArrayBucket();
    AEADCryptBucket src = new AEADCryptBucket(underlying, key(16));
    byte[] input = data(length);
    try (var os = src.getOutputStreamUnbuffered()) {
      os.write(input);
    }
    ArrayBucket dst = new ArrayBucket();
    BucketTools.copy(src, dst);
    assertEquals(length, src.size());
    assertEquals(length, dst.size());
    assertTrue(BucketTools.equalBuckets(src, dst));
  }

  @Test
  void getInputStream_whenWrongKey_failsOnClose() throws IOException {
    ArrayBucket underlying = new ArrayBucket();
    AEADCryptBucket writer = new AEADCryptBucket(underlying, key(24));
    try (var os = writer.getOutputStreamUnbuffered()) {
      os.write(data(128));
    }
    // Same underlying ciphertext, but wrong key
    byte[] wrongKey = key(24);
    wrongKey[0] ^= 0x55;
    AEADCryptBucket reader = new AEADCryptBucket(underlying, wrongKey);

    InputStream is = reader.getInputStreamUnbuffered();
    // Without reading to EOF, close() must authenticate and fail
    assertThrows(AEADVerificationFailedException.class, is::close);
  }

  @Test
  void setReadOnly_thenGetOutputStreamUnbuffered_throwsIOException() {
    ArrayBucket underlying = new ArrayBucket();
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(16));
    bucket.setReadOnly();
    assertTrue(bucket.isReadOnly());
    assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
  }

  @Test
  void free_thenFurtherReadsFail() {
    ArrayBucket underlying = new ArrayBucket();
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(16));
    bucket.free();
    assertThrows(IOException.class, bucket::getInputStreamUnbuffered);
  }

  @Test
  void createShadow_whenUnderlyingSupports_returnsReadOnlyShadow() throws IOException {
    File backing = new File(tempDir, "aead-shadow.bin");
    FileBucket fileBucket = new FileBucket(backing, false, false, false, true);
    AEADCryptBucket bucket = new AEADCryptBucket(fileBucket, key(32));

    byte[] input = data(257);
    try (var os = bucket.getOutputStreamUnbuffered()) {
      os.write(input);
    }

    Bucket shadow = bucket.createShadow();
    assertTrue(shadow.isReadOnly());
    assertInstanceOf(AEADCryptBucket.class, shadow);
    assertEquals(input.length, shadow.size());
    assertArrayEquals(input, BucketTools.toByteArray(shadow));
  }

  @Test
  @DisplayName("storeTo + restoreFrom round-trip preserves data and flags")
  void storeAndRestore_roundTrip_ok() throws Exception {
    File backing = new File(tempDir, "aead-store.bin");
    FileBucket fileBucket = new FileBucket(backing, false, false, false, false);
    byte[] k = key(24);
    AEADCryptBucket bucket = new AEADCryptBucket(fileBucket, k);
    byte[] input = data(513);
    try (var os = bucket.getOutputStreamUnbuffered()) {
      os.write(input);
    }
    bucket.setReadOnly();

    // Serialize
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      bucket.storeTo(dos);
    }

    // Restore via dispatcher
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      Bucket restored =
          BucketTools.restoreFrom(dis, filenameGenerator, fileTracker, new MasterSecret());

      assertInstanceOf(AEADCryptBucket.class, restored);
      assertTrue(restored.isReadOnly());
      assertEquals(input.length, restored.size());
      assertArrayEquals(input, BucketTools.toByteArray(restored));
    }
  }

  @Test
  void restore_whenUnknownVersion_throwsStorageFormatException() throws Exception {
    FileBucket underlying =
        new FileBucket(new File(tempDir, "aead-badver.bin"), false, false, false, false);
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(16));
    // Build a valid store first, then patch the version field (offset 4..7)
    byte[] stored = serialize(bucket);
    ByteBuffer bb = ByteBuffer.wrap(stored).order(ByteOrder.BIG_ENDIAN);
    // MAGIC (0..3) | VERSION (4..7) | keyLen (8)
    bb.putInt(4, 999); // invalid version

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(stored))) {
      assertThrows(
          StorageFormatException.class,
          () -> BucketTools.restoreFrom(dis, filenameGenerator, fileTracker, new MasterSecret()));
    }
  }

  @Test
  void restore_whenInvalidKeyLength_throwsStorageFormatException() throws Exception {
    FileBucket fileBucket =
        new FileBucket(new File(tempDir, "aead-keylen.bin"), false, false, false, false);
    AEADCryptBucket bucket = new AEADCryptBucket(fileBucket, key(16));
    try (var os = bucket.getOutputStreamUnbuffered()) {
      os.write(data(9));
    }

    byte[] stored = serialize(bucket);
    // Overwrite the single key-length byte at position 8
    stored[8] = (byte) 17; // invalid length

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(stored))) {
      assertThrows(
          StorageFormatException.class,
          () -> BucketTools.restoreFrom(dis, filenameGenerator, fileTracker, new MasterSecret()));
    }
  }

  private static byte[] serialize(AEADCryptBucket bucket) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      bucket.storeTo(dos);
    }
    return baos.toByteArray();
  }

  @Test
  @DisplayName("Java serialization round-trip restores underlying and key")
  void javaSerialization_roundTrip_restoresUnderlyingAndKey() throws Exception {
    ArrayBucket underlying = new ArrayBucket("under");
    AEADCryptBucket bucket = new AEADCryptBucket(underlying, key(16));
    byte[] input = data(321);
    try (var os = bucket.getOutputStreamUnbuffered()) {
      os.write(input);
    }
    bucket.setReadOnly();

    // Java-serialize the AEADCryptBucket instance (not the storeTo format)
    byte[] ser;
    try (var baos = new ByteArrayOutputStream();
        var oos = new ObjectOutputStream(baos)) {
      oos.writeObject(bucket);
      oos.flush();
      ser = baos.toByteArray();
    }

    // Deserialize and verify the underlying bucket is restored
    AEADCryptBucket restored;
    try (var bais = new ByteArrayInputStream(ser);
        var ois = new ObjectInputStream(bais)) {
      Object obj = ois.readObject();
      restored = (AEADCryptBucket) obj;
    }

    assertEquals("AEADEncrypted:under", restored.getName());
    assertTrue(restored.isReadOnly());
    assertEquals(input.length, restored.size());
    assertArrayEquals(input, BucketTools.toByteArray(restored));
  }
}
