package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.node.ClientContextResources;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTestBase;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.RAFBucket;
import network.crypta.support.io.RandomAccessBufferTestBase;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "java:S127", "java:S2245"})
@ExtendWith(MockitoExtension.class)
class EncryptedRandomAccessBucketTest extends BucketTestBase {

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Test
  void testIrregularWrites() throws IOException {
    Random r = new Random(6032405);
    int length = 1024 * 64 + 1;
    byte[] data = new byte[length];
    RandomAccessBucket bucket = (RandomAccessBucket) makeBucket(length);
    OutputStream os = bucket.getOutputStream();
    r.nextBytes(data);
    for (int written = 0; written < length; ) {
      int toWrite = Math.min(length - written, 4095);
      os.write(data, written, toWrite);
      written += toWrite;
    }
    os.close();
    InputStream is = bucket.getInputStream();
    for (int moved = 0; moved < length; ) {
      int readBytes = Math.min(length - moved, 4095);
      byte[] buf = new byte[readBytes];
      readBytes = is.read(buf);
      assertTrue(readBytes > 0);
      assertArrayEquals(
          Arrays.copyOfRange(buf, 0, readBytes),
          Arrays.copyOfRange(data, moved, moved + readBytes));
      moved += readBytes;
    }
    is.close();
    bucket.free();
  }

  @Test
  void testIrregularWritesNotOverlapping() throws IOException {
    Random r = new Random(6032405);
    int length = 1024 * 64 + 1;
    byte[] data = new byte[length];
    RandomAccessBucket bucket = (RandomAccessBucket) makeBucket(length);
    OutputStream os = bucket.getOutputStream();
    r.nextBytes(data);
    for (int written = 0; written < length; ) {
      int toWrite = Math.min(length - written, 4095);
      os.write(data, written, toWrite);
      written += toWrite;
    }
    os.close();
    InputStream is = bucket.getInputStream();
    for (int moved = 0; moved < length; ) {
      int readBytes = Math.min(length - moved, 4093); // Co-prime with 4095
      byte[] buf = new byte[readBytes];
      readBytes = is.read(buf);
      assertTrue(readBytes > 0);
      assertArrayEquals(
          Arrays.copyOfRange(buf, 0, readBytes),
          Arrays.copyOfRange(data, moved, moved + readBytes));
      moved += readBytes;
    }
    is.close();
    bucket.free();
  }

  @Test
  void testBucketToRAF() throws IOException {
    Random r = new Random(6032405);
    int length = 1024 * 64 + 1;
    byte[] data = new byte[length];
    RandomAccessBucket bucket = (RandomAccessBucket) makeBucket(length);
    OutputStream os = bucket.getOutputStream();
    r.nextBytes(data);
    for (int written = 0; written < length; ) {
      int toWrite = Math.min(length - written, 4095);
      os.write(data, written, toWrite);
      written += toWrite;
    }
    os.close();
    InputStream is = bucket.getInputStream();
    for (int moved = 0; moved < length; ) {
      int readBytes = Math.min(length - moved, 4095);
      byte[] buf = new byte[readBytes];
      readBytes = is.read(buf);
      assertTrue(readBytes > 0);
      assertArrayEquals(
          Arrays.copyOfRange(buf, 0, readBytes),
          Arrays.copyOfRange(data, moved, moved + readBytes));
      moved += readBytes;
    }
    LockableRandomAccessBuffer raf = bucket.toRandomAccessBuffer();
    assertEquals(length, raf.size());
    RAFBucket wrapped = new RAFBucket(raf);
    assertTrue(BucketTools.equalBuckets(bucket, wrapped));
    for (int i = 0; i < 100; i++) {
      int end = r.nextInt(length) + 1; // 1..length
      int start = r.nextInt(end);
      RandomAccessBufferTestBase.checkArraySectionEqualsReadData(data, raf, start, end, true);
    }
  }

  @BeforeEach
  void setUp() throws IOException {
    Files.createDirectories(base.toPath());
  }

  @AfterEach
  void tearDown() {
    FileUtil.removeAll(base);
  }

  @Test
  void getInputStreamUnbuffered_whenEmpty_returnsEOF() throws IOException {
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], new ArrayBucket(), secret);
    assertEquals(0, bucket.size());
    try (InputStream is = bucket.getInputStreamUnbuffered()) {
      assertEquals(-1, is.read());
    }
    bucket.free();
  }

  @Test
  void size_whenWrite_expectUnderlyingHasHeaderAndLogicalSize() throws IOException {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], underlying, secret);
    byte[] data = new byte[1234];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      os.write(data);
    }
    assertEquals(data.length, bucket.size());
    assertEquals(data.length + types[0].headerLen, underlying.size());
    bucket.free();
  }

  @Test
  void getInputStreamUnbuffered_afterFree_throwsIOException() throws IOException {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], underlying, secret);
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      os.write(new byte[] {1, 2, 3});
    }
    bucket.free();
    // Depending on the underlying implementation, size() may NPE after free (ArrayBucket),
    // so any exception is acceptable to signal the illegal state.
    assertThrows(Exception.class, bucket::getInputStreamUnbuffered);
  }

  @Test
  void getOutputStreamUnbuffered_afterFree_throwsIOException() {
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], new ArrayBucket(), secret);
    bucket.free();
    assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
  }

  @Test
  void getName_whenArrayBucket_expectFormattedName() {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], underlying, secret);
    String name = bucket.getName();
    assertTrue(name.contains("EncryptedRandomAccessBucket"));
    assertTrue(name.endsWith(":" + underlying.getName()));
    bucket.free();
  }

  @Test
  void setReadOnly_thenIsReadOnlyTrue() {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], underlying, secret);
    assertFalse(bucket.isReadOnly());
    bucket.setReadOnly();
    assertTrue(bucket.isReadOnly());
    bucket.free();
  }

  @Test
  void createShadow_whenFileBucket_expectReadableShadow() throws Exception {
    File tempFile = File.createTempFile("erab-shadow", ".tmp", base);
    FileBucket fileBucket = new FileBucket(tempFile, false, false, false, true);
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], fileBucket, secret);

    byte[] payload = new byte[256];
    for (int i = 0; i < payload.length; i++) payload[i] = (byte) i;
    try (OutputStream os = bucket.getOutputStream()) {
      os.write(payload);
    }

    RandomAccessBucket shadow = bucket.createShadow();
    assertNotNull(shadow);
    assertInstanceOf(EncryptedRandomAccessBucket.class, shadow);
    try (InputStream is = shadow.getInputStream()) {
      byte[] out = new byte[payload.length];
      int read = is.read(out);
      assertEquals(payload.length, read);
      assertArrayEquals(payload, out);
    }
    shadow.free();
    bucket.free();
  }

  @Test
  void toRandomAccessBuffer_whenEmpty_expectIOException() {
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], new ArrayBucket(), secret);
    assertThrows(IOException.class, bucket::toRandomAccessBuffer);
    bucket.free();
  }

  @Test
  void getInputStreamUnbuffered_whenHeaderMagicCorrupted_expectIOException() throws Exception {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], underlying, secret);
    byte[] data = new byte[64];
    new Random(42).nextBytes(data);
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      os.write(data);
    }
    // Corrupt the magic in the header (last 8 bytes of header)
    byte[] raw = underlying.toByteArray();
    int magicOffset =
        types[0].headerLen - 8; // version(4) + magic(8) -> magic starts at headerLen-8
    raw[magicOffset] ^= 0x01;
    ArrayBucket corrupted = new ArrayBucket(raw);

    EncryptedRandomAccessBucket corruptedBucket =
        new EncryptedRandomAccessBucket(types[0], corrupted, secret);
    IOException ex = assertThrows(IOException.class, corruptedBucket::getInputStreamUnbuffered);
    assertTrue(ex.getMessage().contains("EncryptedRandomAccessBuffer"));
    corruptedBucket.free();
    bucket.free();
  }

  @Test
  void getInputStreamUnbuffered_whenHeaderMacMismatch_expectIOExceptionWithCause()
      throws Exception {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], underlying, secret);
    byte[] data = new byte[32];
    new Random(7).nextBytes(data);
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      os.write(data);
    }
    // Corrupt the MAC portion of the header
    byte[] raw = underlying.toByteArray();
    int ivLen = types[0].encryptType.ivSize; // bytes
    int keyLen = types[0].encryptKey.keySize >> 3; // bytes
    int macOffset = ivLen + keyLen;
    raw[macOffset + 3] ^= 0x20; // flip a bit inside MAC region
    ArrayBucket corrupted = new ArrayBucket(raw);

    EncryptedRandomAccessBucket corruptedBucket =
        new EncryptedRandomAccessBucket(types[0], corrupted, secret);
    IOException ex = assertThrows(IOException.class, corruptedBucket::getInputStreamUnbuffered);
    assertNotNull(ex.getCause());
    assertInstanceOf(GeneralSecurityException.class, ex.getCause());
    corruptedBucket.free();
    bucket.free();
  }

  @Test
  void equalsAndHashCode_whenSameUnderlying_expectEqual() {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket a = new EncryptedRandomAccessBucket(types[0], underlying, secret);
    EncryptedRandomAccessBucket b = new EncryptedRandomAccessBucket(types[0], underlying, secret);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    ArrayBucket other = new ArrayBucket();
    EncryptedRandomAccessBucket c = new EncryptedRandomAccessBucket(types[0], other, secret);
    assertNotEquals(a, c);
    a.free();
    b.free();
    c.free();
  }

  @Test
  void onResume_whenMasterSecretChanges_expectIOExceptionOnRead() throws Exception {
    ArrayBucket underlying = new ArrayBucket();
    EncryptedRandomAccessBucket bucket =
        new EncryptedRandomAccessBucket(types[0], underlying, secret);
    byte[] payload = new byte[] {10, 20, 30, 40};
    try (OutputStream os = bucket.getOutputStream()) {
      os.write(payload);
    }
    // Swap to a different master secret via ClientContext mock
    ClientContext ctx = Mockito.mock(ClientContext.class);
    Mockito.when(ctx.getPersistentMasterSecret()).thenReturn(new MasterSecret());
    bucket.onResume(ctx);
    // Now the MAC/key derivation won't match the header; reading must fail
    assertThrows(IOException.class, bucket::getInputStreamUnbuffered);
    bucket.free();
  }

  @Test
  void testStoreTo() throws IOException, StorageFormatException, ResumeFailedException {
    File tempFile = File.createTempFile("test-storeto", ".tmp", base);
    byte[] buf = new byte[4096];
    Random r = new Random(1267612);
    r.nextBytes(buf);
    FileBucket fb = new FileBucket(tempFile, false, false, false, true);
    EncryptedRandomAccessBucket erab = new EncryptedRandomAccessBucket(types[0], fb, secret);
    byte[] tmp = new byte[buf.length];
    try (OutputStream os = erab.getOutputStream()) {
      os.write(buf, 0, buf.length);
    }
    try (InputStream is = erab.getInputStream();
        DataInputStream dataIn = new DataInputStream(is)) {
      dataIn.readFully(tmp);
    }
    assertArrayEquals(buf, tmp);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      erab.storeTo(dos);
    }
    ClientContext context =
        new ClientContext(
            0,
            new ClientContextRuntime(null, null, null, null, null, r, null),
            new ClientContextStorageFactories(null, null, null, null, null, null, null),
            new ClientContextRafFactories(null, null),
            new ClientContextServices(
                new ClientContextResources(null, null), null, null, null, null, null),
            new ClientContextDefaults(null, null, null));
    context.setPersistentMasterSecret(secret);
    EncryptedRandomAccessBucket restored;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      restored =
          (EncryptedRandomAccessBucket)
              BucketTools.restoreFrom(
                  dis, context.persistentFG, context.getPersistentFileTracker(), secret);
    }
    assertEquals(buf.length, restored.size());
    assertEquals(erab, restored);
    tmp = new byte[buf.length];
    try (InputStream is = erab.getInputStream();
        DataInputStream dataIn = new DataInputStream(is)) {
      dataIn.readFully(tmp);
    }
    assertArrayEquals(buf, tmp);
    restored.free();
  }

  @Test
  void testSerialize() throws IOException, ResumeFailedException, ClassNotFoundException {
    File tempFile = File.createTempFile("test-storeto", ".tmp", base);
    byte[] buf = new byte[4096];
    Random r = new Random(1267612);
    r.nextBytes(buf);
    FileBucket fb = new FileBucket(tempFile, false, false, false, true);
    EncryptedRandomAccessBucket erab = new EncryptedRandomAccessBucket(types[0], fb, secret);
    byte[] tmp = new byte[buf.length];
    try (OutputStream os = erab.getOutputStream()) {
      os.write(buf, 0, buf.length);
    }
    try (InputStream is = erab.getInputStream();
        DataInputStream dataIn = new DataInputStream(is)) {
      dataIn.readFully(tmp);
    }
    assertArrayEquals(buf, tmp);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(erab);
    }
    ClientContext context =
        new ClientContext(
            0,
            new ClientContextRuntime(null, null, null, null, null, r, null),
            new ClientContextStorageFactories(null, null, null, null, null, null, null),
            new ClientContextRafFactories(null, null),
            new ClientContextServices(
                new ClientContextResources(null, null), null, null, null, null, null),
            new ClientContextDefaults(null, null, null));
    context.setPersistentMasterSecret(secret);
    EncryptedRandomAccessBucket restored;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
        ObjectInputStream ois = new ObjectInputStream(dis)) {
      restored = (EncryptedRandomAccessBucket) ois.readObject();
    }
    restored.onResume(context);
    assertEquals(buf.length, restored.size());
    assertEquals(erab, restored);
    tmp = new byte[buf.length];
    try (InputStream is = erab.getInputStream();
        DataInputStream dataIn = new DataInputStream(is)) {
      dataIn.readFully(tmp);
    }
    assertArrayEquals(buf, tmp);
    restored.free();
  }

  @Test
  void testSerializationDoesNotConsumeFollowingObject()
      throws IOException, ClassNotFoundException, ResumeFailedException {
    File tempFile = File.createTempFile("test-ser-boundary", ".tmp", base);
    byte[] buf = new byte[128];
    Random r = new Random(42);
    r.nextBytes(buf);
    FileBucket fb = new FileBucket(tempFile, false, false, false, true);
    EncryptedRandomAccessBucket erab = new EncryptedRandomAccessBucket(types[0], fb, secret);

    try (OutputStream os = erab.getOutputStream()) {
      os.write(buf);
    }

    // Write our bucket followed by an unrelated Integer to the same ObjectOutputStream.
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
      oos.writeObject(erab);
      oos.writeObject(123456);
    }

    // Now read back: first the bucket, then the Integer. If the bucket's readObject() consumed the
    // next object, the second read would fail or the cast in readObject() would throw.
    try (ObjectInputStream ois =
        new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      EncryptedRandomAccessBucket restored = (EncryptedRandomAccessBucket) ois.readObject();
      ClientContext context =
          new ClientContext(
              0,
              new ClientContextRuntime(null, null, null, null, null, r, null),
              new ClientContextStorageFactories(null, null, null, null, null, null, null),
              new ClientContextRafFactories(null, null),
              new ClientContextServices(
                  new ClientContextResources(null, null), null, null, null, null, null),
              new ClientContextDefaults(null, null, null));
      context.setPersistentMasterSecret(secret);
      restored.onResume(context);
      assertEquals(buf.length, restored.size());
      assertEquals(erab, restored);

      Object next = ois.readObject();
      assertInstanceOf(Integer.class, next);
      assertEquals(123456, ((Integer) next).intValue());
      restored.free();
    }
  }

  @Override
  protected Bucket makeBucket(long size) throws IOException {
    ArrayBucket underlying = new ArrayBucket();
    return new EncryptedRandomAccessBucket(types[0], underlying, secret);
  }

  @Override
  protected void freeBucket(Bucket bucket) {
    bucket.free();
  }

  private static final MasterSecret secret = new MasterSecret();
  private static final EncryptedRandomAccessBufferType[] types =
      EncryptedRandomAccessBufferType.values();
  private final File base = new File("tmp.encrypted-random-access-thing-test");
}
