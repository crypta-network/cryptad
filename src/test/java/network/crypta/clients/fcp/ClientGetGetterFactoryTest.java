package network.crypta.clients.fcp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.async.BinaryBlob;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.FileBucket;
import network.crypta.support.io.PrependLengthOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ClientGetGetterFactoryTest {
  @TempDir File tempDir;

  @Test
  void binaryBlobMimeType_whenCalled_returnsBinaryBlobMimeType() {
    assertEquals(BinaryBlob.MIME_TYPE, ClientGetGetterFactory.binaryBlobMimeType());
  }

  @Test
  void checksummedWriter_whenCalled_usesChecksumWriterWithLength() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    DataOutputStream target = new DataOutputStream(output);
    ChecksumChecker checker = mock(ChecksumChecker.class);
    PrependLengthOutputStream prependLengthOutputStream = mock(PrependLengthOutputStream.class);
    when(checker.checksumWriterWithLength(org.mockito.ArgumentMatchers.eq(target), any()))
        .thenReturn(prependLengthOutputStream);

    DataOutputStream writer = ClientGetGetterFactory.checksummedWriter(target, checker);

    assertNotNull(writer);
  }

  @Test
  void applyAllowedMimeTypes_whenConfigured_updatesDetachedFetchConfig() {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();

    ClientGetGetterFactory.applyAllowedMimeTypes(
        fetchConfig, new String[] {"text/plain", "image/png"});

    assertNotNull(fetchConfig.getAllowedMimeTypes());
    assertTrue(fetchConfig.getAllowedMimeTypes().contains("text/plain"));
    assertTrue(fetchConfig.getAllowedMimeTypes().contains("image/png"));
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

  @Test
  void diskBucket_whenCreated_appliesReadOnlyFlag() {
    File file = new File(tempDir, "bucket.bin");

    try (Bucket bucket = ClientGetGetterFactory.diskBucket(file, true)) {
      assertInstanceOf(FileBucket.class, bucket);
      FileBucket fileBucket = (FileBucket) bucket;
      assertEquals(file.getAbsoluteFile(), fileBucket.getFile());
      assertTrue(fileBucket.isReadOnly());
      assertFalse(readBooleanField(fileBucket, "createFileOnlyFlag"));
    }
  }

  @Test
  void readAndWriteExpectedHashes_whenHashesPresent_roundTrip() throws IOException {
    HashResult[] hashes = new HashResult[] {sampleSha256Hash()};
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
  void buildStatus_whenDetachedFetchConfigCarriesOverrides_usesThemInStatus() {
    ClientGetFetchConfig fetchConfig = new ClientGetFetchConfig();
    fetchConfig.setFilterData(true);
    fetchConfig.setOverrideMime("text/html");
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            "req",
            ClientRequest.Persistence.REBOOT,
            true,
            true,
            true,
            1,
            1,
            1,
            java.time.Instant.now(),
            0,
            0,
            null,
            true,
            (short) 1);
    DownloadProgressSnapshot progressSnapshot = new DownloadProgressSnapshot(null, null);
    DownloadDataSnapshot dataSnapshot =
        new DownloadDataSnapshot("text/plain", 9L, new File("target.bin"), mock(Bucket.class));
    DownloadContextSnapshot contextSnapshot =
        new DownloadContextSnapshot(
            fetchConfig,
            new CompatibilityMode[] {CompatibilityMode.COMPAT_1250},
            new byte[] {1, 2, 3},
            FreenetURI.EMPTY_CHK_URI,
            false);

    RequestStatus status =
        ClientGetGetterFactory.buildStatus(
            new ClientGetStatusSnapshot(
                statusSnapshot, progressSnapshot, dataSnapshot, contextSnapshot));

    assertInstanceOf(DownloadRequestStatus.class, status);
  }

  private static boolean readBooleanField(FileBucket bucket, String fieldName) {
    try {
      Field field = FileBucket.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.getBoolean(bucket);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  private static HashResult sampleSha256Hash() {
    byte[] digest = new byte[HashType.SHA256.hashLength];
    java.util.Arrays.fill(digest, (byte) 7);
    return new HashResult(HashType.SHA256, digest);
  }
}
