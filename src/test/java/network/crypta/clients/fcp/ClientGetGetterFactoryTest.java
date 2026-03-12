package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.async.BinaryBlob;
import network.crypta.client.async.BinaryBlobWriter;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.client.async.ClientGetterOptions;
import network.crypta.client.async.ClientGetterRequest;
import network.crypta.client.async.PersistentClientCallback;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.NullBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientGetGetterFactoryTest {
  @TempDir File tempDir;

  @Test
  void binaryBlobMimeType_whenCalled_returnsBinaryBlobMimeType() {
    String mimeType = ClientGetGetterFactory.binaryBlobMimeType();

    assertEquals(BinaryBlob.MIME_TYPE, mimeType);
  }

  @Test
  void checksummedWriter_whenCalled_usesChecksumWriterWithLength() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataOutputStream target = new DataOutputStream(output);
    RecordingChecksumChecker checker = new RecordingChecksumChecker();

    DataOutputStream writer = ClientGetGetterFactory.checksummedWriter(target, checker);
    writer.writeInt(1234);
    writer.close();

    assertNotNull(writer);
    assertEquals(8, checker.lastSkipPrefix);
    assertSame(target, checker.lastTarget);
  }

  @Test
  void diskReturnBucket_whenCreated_configuresFileBucketFlags() {
    File file = new File(tempDir, "return.bin");

    try (Bucket bucket = ClientGetGetterFactory.diskReturnBucket(file)) {
      assertInstanceOf(FileBucket.class, bucket);
      FileBucket fileBucket = (FileBucket) bucket;
      assertEquals(file.getAbsoluteFile(), fileBucket.getFile());
      assertFalse(fileBucket.isReadOnly());
      assertTrue(readBooleanField(fileBucket, "createFileOnlyFlag"));
      assertFalse(readBooleanField(fileBucket, "deleteOnExitFlag"));
      assertFalse(readBooleanField(fileBucket, "deleteOnFreeFlag"));
    }
  }

  @ParameterizedTest
  @CsvSource({"true", "false"})
  void diskBucket_whenCreated_appliesReadOnlyFlag(boolean readOnly) {
    File file = new File(tempDir, "bucket.bin");

    try (Bucket bucket = ClientGetGetterFactory.diskBucket(file, readOnly)) {
      assertInstanceOf(FileBucket.class, bucket);
      FileBucket fileBucket = (FileBucket) bucket;
      assertEquals(file.getAbsoluteFile(), fileBucket.getFile());
      assertEquals(readOnly, fileBucket.isReadOnly());
      assertFalse(readBooleanField(fileBucket, "createFileOnlyFlag"));
    }
  }

  @Test
  void readExpectedHashes_whenNoHashes_returnsNull() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(output);
    dos.writeInt(0);
    dos.flush();

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(output.toByteArray()));
    ExpectedHashes result = ClientGetGetterFactory.readExpectedHashes(dis, "identifier", true);

    assertNull(result);
  }

  @Test
  void readExpectedHashes_whenHashesPresent_returnsExpectedHashes() throws IOException {
    HashResult[] hashes = new HashResult[] {hashFor(HashType.SHA256, (byte) 7)};
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(output);
    HashResult.write(hashes, dos);
    dos.flush();

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(output.toByteArray()));
    ExpectedHashes result = ClientGetGetterFactory.readExpectedHashes(dis, "id", false);

    assertNotNull(result);
    assertEquals("id", result.messageIdentifier);
    assertFalse(result.global);
    assertNotNull(result.hashes);
    assertEquals(1, result.hashes.length);
    assertEquals(hashes[0], result.hashes[0]);
  }

  @Test
  void writeExpectedHashes_whenNull_writesEmptyHashes() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(output);

    ClientGetGetterFactory.writeExpectedHashes(dos, null);

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(output.toByteArray()));
    ExpectedHashes result = ClientGetGetterFactory.readExpectedHashes(dis, "ignored", false);
    assertNull(result);
  }

  @Test
  void writeExpectedHashes_whenPresent_roundTripsThroughRead() throws IOException {
    HashResult[] hashes = new HashResult[] {hashFor(HashType.SHA1, (byte) 3)};
    ExpectedHashes expected = new ExpectedHashes(hashes, "abc", true);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(output);

    ClientGetGetterFactory.writeExpectedHashes(dos, expected);

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(output.toByteArray()));
    ExpectedHashes result = ClientGetGetterFactory.readExpectedHashes(dis, "abc", true);

    assertNotNull(result);
    assertEquals("abc", result.messageIdentifier);
    assertTrue(result.global);
    assertNotNull(result.hashes);
    assertEquals(hashes[0], result.hashes[0]);
  }

  @Test
  void createGetter_whenBinaryBlobTrueAndReturnBucketProvided_usesBucketWriter() throws Exception {
    ClientGet request = mockRequestWithClient();
    FetchContext fetchContext = mock(FetchContext.class);
    Bucket returnBucket = mock(Bucket.class);

    ClientGetter getter =
        createGetter(
            request,
            mock(FreenetURI.class),
            fetchContext,
            (short) 1,
            returnBucket,
            null,
            null,
            false,
            true,
            false,
            null);

    Bucket storedReturnBucket = (Bucket) readField(getter, "returnBucket");
    BinaryBlobWriter writer = (BinaryBlobWriter) readField(getter, "binaryBlobWriter");

    assertInstanceOf(NullBucket.class, storedReturnBucket);
    assertNotNull(writer);
    assertSame(returnBucket, readField(writer, "out"));
  }

  @Test
  void createGetter_whenBinaryBlobTrueAndReturnBucketNull_requiresCore() {
    ClientGet request = mock(ClientGet.class);
    FetchContext fetchContext = mock(FetchContext.class);

    assertThrows(
        NullPointerException.class,
        () ->
            createGetter(
                request,
                mock(FreenetURI.class),
                fetchContext,
                (short) 1,
                null,
                null,
                null,
                false,
                true,
                false,
                null));
  }

  @Test
  void createGetter_whenBinaryBlobTrueAndReturnBucketNull_allocatesBucket() throws Exception {
    ClientGet request = mockRequestWithClient();
    FetchContext fetchContext = mock(FetchContext.class);
    NodeClientCore core = mock(NodeClientCore.class);
    ClientContext clientContext = mock(ClientContext.class);
    BucketFactory bucketFactory = mock(BucketFactory.class);
    RandomAccessBucket createdBucket = mock(RandomAccessBucket.class);

    when(fetchContext.getMaxOutputLength()).thenReturn(128L);
    when(core.getClientContext()).thenReturn(clientContext);
    when(clientContext.getBucketFactory(true)).thenReturn(bucketFactory);
    when(bucketFactory.makeBucket(128L)).thenReturn(createdBucket);

    ClientGetter getter =
        createGetter(
            request,
            mock(FreenetURI.class),
            fetchContext,
            (short) 1,
            null,
            null,
            null,
            false,
            true,
            true,
            core);

    BinaryBlobWriter writer = (BinaryBlobWriter) readField(getter, "binaryBlobWriter");
    assertNotNull(writer);
    assertSame(createdBucket, readField(writer, "out"));
  }

  @Test
  void createGetter_whenDiscardDataTrue_usesNullBucket() throws Exception {
    ClientGet request = mockRequestWithClient();
    FetchContext fetchContext = mock(FetchContext.class);
    Bucket returnBucket = mock(Bucket.class);

    ClientGetter getter =
        createGetter(
            request,
            mock(FreenetURI.class),
            fetchContext,
            (short) 1,
            returnBucket,
            null,
            null,
            true,
            false,
            false,
            null);

    Bucket storedReturnBucket = (Bucket) readField(getter, "returnBucket");

    assertInstanceOf(NullBucket.class, storedReturnBucket);
  }

  @Test
  void createGetter_whenDiscardDataFalse_preservesReturnBucket() throws Exception {
    ClientGet request = mockRequestWithClient();
    FetchContext fetchContext = mock(FetchContext.class);
    Bucket returnBucket = mock(Bucket.class);

    ClientGetter getter =
        createGetter(
            request,
            mock(FreenetURI.class),
            fetchContext,
            (short) 1,
            returnBucket,
            null,
            null,
            false,
            false,
            false,
            null);

    Bucket storedReturnBucket = (Bucket) readField(getter, "returnBucket");
    BinaryBlobWriter writer = (BinaryBlobWriter) readField(getter, "binaryBlobWriter");

    assertSame(returnBucket, storedReturnBucket);
    assertNull(writer);
  }

  @Test
  void createGetter_whenBinaryBlobFalse_callbackDelegatesToRequest() throws Exception {
    ClientGet request = mock(ClientGet.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RequestClient requestClient = mock(RequestClient.class);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    DataOutputStream dos = new DataOutputStream(new ByteArrayOutputStream());
    ClientContext context = mock(ClientContext.class);
    FetchResult fetchResult = mock(FetchResult.class);
    FetchException fetchException = mock(FetchException.class);

    when(request.getRequestClient()).thenReturn(requestClient);
    doNothing().when(request).getClientDetail(dos, checker);

    ClientGetter getter =
        createGetter(
            request,
            mock(FreenetURI.class),
            fetchContext,
            (short) 1,
            null,
            null,
            null,
            false,
            false,
            false,
            null);

    ClientGetCallback callback = getter.getClientCallback();

    assertInstanceOf(PersistentClientCallback.class, callback);

    callback.onSuccess(fetchResult, getter);
    callback.onFailure(fetchException);
    callback.onResume(context);
    RequestClient resolvedClient = callback.getRequestClient();
    ((PersistentClientCallback) callback).getClientDetail(dos, checker);

    assertSame(requestClient, resolvedClient);
    verify(request).onSuccess(fetchResult, getter);
    verify(request).onFailure(fetchException);
    verify(request).onResume(context);
    verify(request).getClientDetail(dos, checker);
  }

  @Test
  void createGetter_whenBinaryBlobTrueAndBucketProvided_doesNotTouchCore() throws IOException {
    ClientGet request = mockRequestWithClient();
    FetchContext fetchContext = mock(FetchContext.class);
    NodeClientCore core = mock(NodeClientCore.class);
    Bucket returnBucket = mock(Bucket.class);

    createGetter(
        request,
        mock(FreenetURI.class),
        fetchContext,
        (short) 1,
        returnBucket,
        null,
        null,
        false,
        true,
        false,
        core);

    verifyNoInteractions(core);
  }

  private static ClientGetter createGetter(
      ClientGet request,
      FreenetURI uri,
      FetchContext fetchContext,
      short priorityClass,
      Bucket returnBucket,
      Bucket initialMetadata,
      String extensionCheck,
      boolean discardData,
      boolean binaryBlob,
      boolean persistenceForever,
      NodeClientCore core)
      throws IOException {
    ClientGetterRequest getterRequest =
        ClientGetGetterFactory.createGetterRequest(request, uri, fetchContext, priorityClass);
    ClientGetterOptions options =
        new ClientGetterOptions(returnBucket, null, false, initialMetadata, extensionCheck);
    ClientGetGetterFlags flags =
        new ClientGetGetterFlags(discardData, binaryBlob, persistenceForever);
    return ClientGetGetterFactory.createGetter(getterRequest, options, flags, core);
  }

  private static HashResult hashFor(HashType type, byte seed) {
    byte[] bytes = new byte[type.hashLength];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = (byte) (seed + i);
    }
    return new HashResult(type, bytes);
  }

  private static ClientGet mockRequestWithClient() {
    ClientGet request = mock(ClientGet.class);
    RequestClient requestClient = mock(RequestClient.class);
    when(request.getRequestClient()).thenReturn(requestClient);
    return request;
  }

  private static Object readField(Object target, String name) throws Exception {
    Field field = target.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static boolean readBooleanField(Object target, String name) {
    try {
      Field field = target.getClass().getDeclaredField(name);
      field.setAccessible(true);
      return field.getBoolean(target);
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final class RecordingChecksumChecker extends ChecksumChecker {
    private int lastSkipPrefix = -1;
    private OutputStream lastTarget;

    @Override
    public int checksumLength() {
      return 0;
    }

    @Override
    public OutputStream checksumWriter(OutputStream os, int skipPrefix) {
      lastSkipPrefix = skipPrefix;
      lastTarget = os;
      return os;
    }

    @Override
    public byte[] appendChecksum(byte[] data) {
      return data;
    }

    @Override
    public boolean checkChecksum(byte[] data, int offset, int length, byte[] checksum) {
      return true;
    }

    @Override
    public byte[] generateChecksum(byte[] bufToChecksum, int offset, int length) {
      return new byte[0];
    }

    @Override
    public int getChecksumTypeID() {
      return 0;
    }

    @Override
    public void copyAndStripChecksum(InputStream is, OutputStream os, long length) {
      throw new UnsupportedOperationException("Not used in tests");
    }

    @Override
    public void readAndChecksum(DataInput is, byte[] buf, int offset, int length) {
      throw new UnsupportedOperationException("Not used in tests");
    }
  }
}
