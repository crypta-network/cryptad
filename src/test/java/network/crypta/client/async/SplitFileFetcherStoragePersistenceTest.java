package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.DocumentType;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashType;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileFetcherStoragePersistenceTest {
  private static final String WANNA_CHK_1 =
      "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml";
  private static final String WANNA_USK_1 =
      "USK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search/17/index_d51.xml";

  private static Stream<Arguments> generalProgressFlagCases() {
    return Stream.of(
        Arguments.of(true, SplitFileFetcherStorage.HAS_CHECKED_DATASTORE_FLAG),
        Arguments.of(false, 0L));
  }

  @Test
  void preparedMetadata_whenSameContent_expectEqualsHashCodeAndToString() throws IOException {
    BucketFactory bucketFactory = new ArrayBucketFactory();
    Bucket sharedBucket = bucketFactory.makeBucket(-1);
    byte[] encodedFirst = new byte[] {1, 2, 3};
    byte[] encodedSecond = new byte[] {1, 2, 3};

    SplitFileFetcherStoragePersistence.PreparedMetadata first =
        new SplitFileFetcherStoragePersistence.PreparedMetadata(
            sharedBucket, encodedFirst, 10L, 20L);
    SplitFileFetcherStoragePersistence.PreparedMetadata second =
        new SplitFileFetcherStoragePersistence.PreparedMetadata(
            sharedBucket, encodedSecond, 10L, 20L);

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
    assertTrue(first.toString().contains("offsetOriginalDetails=10"));
    assertTrue(first.toString().contains("offsetBasicSettings=20"));
    assertTrue(first.toString().contains(Arrays.toString(encodedFirst)));

    Bucket differentBucket = bucketFactory.makeBucket(-1);
    SplitFileFetcherStoragePersistence.PreparedMetadata different =
        new SplitFileFetcherStoragePersistence.PreparedMetadata(
            differentBucket, encodedFirst, 10L, 20L);

    assertNotEquals(first, different);
  }

  @ParameterizedTest
  @MethodSource("generalProgressFlagCases")
  void encodeGeneralProgress_whenHasCheckedDatastoreFlagMatches_expectPayloadRoundTrip(
      boolean hasCheckedDatastore, long expectedFlags) throws Exception {
    ChecksumChecker checksumChecker = new CRCChecksumChecker();
    FailureCodeTracker errors = new FailureCodeTracker(false);
    errors.inc(FetchExceptionMode.DATA_NOT_FOUND);
    errors.inc(FetchExceptionMode.INTERNAL_ERROR);

    byte[] encoded =
        SplitFileFetcherStoragePersistence.encodeGeneralProgress(
            checksumChecker, hasCheckedDatastore, errors);

    long expectedPayloadLength = 8L + FailureCodeTracker.getFixedLength(false);
    try (DataInputStream lengthStream = new DataInputStream(new ByteArrayInputStream(encoded))) {
      assertEquals(expectedPayloadLength, lengthStream.readLong());
    }
    assertEquals(8 + expectedPayloadLength + checksumChecker.checksumLength(), encoded.length);

    try (InputStream payloadStream =
            checksumChecker.checksumReaderWithLength(
                new ByteArrayInputStream(encoded),
                new ArrayBucketFactory(),
                expectedPayloadLength);
        DataInputStream dis = new DataInputStream(payloadStream)) {
      assertEquals(expectedFlags, dis.readLong());
      FailureCodeTracker decoded = new FailureCodeTracker(false, dis);
      assertEquals(1, decoded.getErrorCount(FetchExceptionMode.DATA_NOT_FOUND));
      assertEquals(1, decoded.getErrorCount(FetchExceptionMode.INTERNAL_ERROR));
      assertEquals(-1, payloadStream.read());
    }
  }

  @Test
  void encodeGeneralProgress_whenChecksumWriterFails_expectIllegalStateException()
      throws IOException {
    ChecksumChecker checksumChecker = Mockito.mock(ChecksumChecker.class);
    FailureCodeTracker errors = new FailureCodeTracker(false);
    IOException ioException = new IOException("boom");
    doThrow(ioException)
        .when(checksumChecker)
        .checksumWriterWithLength(any(OutputStream.class), any(BucketFactory.class));

    IllegalStateException thrown =
        assertThrows(
            IllegalStateException.class,
            () ->
                SplitFileFetcherStoragePersistence.encodeGeneralProgress(
                    checksumChecker, true, errors));

    assertSame(ioException, thrown.getCause());
  }

  private static Stream<Arguments> preparePersistentCases() {
    return Stream.of(Arguments.of(true, 5, 3, 1234L, 64L), Arguments.of(false, 2, 1, 50L, 128L));
  }

  @ParameterizedTest
  @MethodSource("preparePersistentCases")
  void preparePersistent_whenMetadataWrites_expectOffsetsAndEncodedDetails(
      boolean isFinalFetch, int maxRetries, int cooldownTries, long cooldownLength, long offset)
      throws Exception {
    ChecksumChecker checksumChecker = new CRCChecksumChecker();
    BucketFactory bucketFactory = new ArrayBucketFactory();
    Metadata metadata =
        new Metadata(
            DocumentType.SIMPLE_REDIRECT,
            null,
            null,
            new FreenetURI(WANNA_CHK_1),
            new ClientMetadata("text/plain"));
    FreenetURI thisKey = new FreenetURI(WANNA_CHK_1);
    FreenetURI origKey = new FreenetURI(WANNA_USK_1);
    byte[] clientDetails = "client-details".getBytes(StandardCharsets.UTF_8);

    SplitFileFetcherStoragePersistence.PreparedMetadata prepared =
        SplitFileFetcherStoragePersistence.preparePersistent(
            metadata,
            bucketFactory,
            thisKey,
            origKey,
            clientDetails,
            isFinalFetch,
            offset,
            checksumChecker,
            maxRetries,
            cooldownTries,
            cooldownLength);

    byte[] metadataBytes = serializeMetadata(metadata);
    byte[] bucketBytes = BucketTools.toByteArray(prepared.metadataTemp());
    int checksumLength = checksumChecker.checksumLength();
    assertEquals(
        metadataBytes.length + HashType.SHA256.hashLength + checksumLength, bucketBytes.length);

    MessageDigest digest = HashType.SHA256.get();
    byte[] expectedHash = digest.digest(metadataBytes);
    byte[] actualHash =
        Arrays.copyOfRange(
            bucketBytes, metadataBytes.length, metadataBytes.length + HashType.SHA256.hashLength);
    assertArrayEquals(expectedHash, actualHash);

    assertEquals(offset + bucketBytes.length, prepared.offsetOriginalDetails());
    assertEquals(
        prepared.offsetOriginalDetails() + prepared.encodedURI().length,
        prepared.offsetBasicSettings());

    verifyEncodedOriginalDetails(
        prepared.encodedURI(),
        checksumChecker,
        thisKey,
        origKey,
        isFinalFetch,
        clientDetails,
        maxRetries,
        cooldownTries,
        cooldownLength);
  }

  @Test
  void preparePersistent_whenMetadataUnresolved_expectFetchExceptionInternalError()
      throws Exception {
    ChecksumChecker checksumChecker = new CRCChecksumChecker();
    BucketFactory bucketFactory = new ArrayBucketFactory();
    Metadata metadata = Mockito.mock(Metadata.class);
    MetadataUnresolvedException unresolved =
        new MetadataUnresolvedException(new Metadata[0], "unresolved");
    doThrow(unresolved).when(metadata).writeTo(any(DataOutputStream.class));

    FetchException thrown =
        assertThrows(
            FetchException.class,
            () ->
                SplitFileFetcherStoragePersistence.preparePersistent(
                    metadata,
                    bucketFactory,
                    new FreenetURI(WANNA_CHK_1),
                    new FreenetURI(WANNA_USK_1),
                    new byte[] {9},
                    false,
                    12L,
                    checksumChecker,
                    1,
                    1,
                    5L));

    assertEquals(FetchExceptionMode.INTERNAL_ERROR, thrown.getMode());
    assertSame(unresolved, thrown.getCause());
  }

  @Test
  void writePersistentMetadata_whenCalled_writesSectionsAndFooter() throws Exception {
    ChecksumChecker checksumChecker = new CRCChecksumChecker();
    BucketFactory bucketFactory = new ArrayBucketFactory();
    Metadata metadata =
        new Metadata(
            DocumentType.SIMPLE_REDIRECT,
            null,
            null,
            new FreenetURI(WANNA_CHK_1),
            new ClientMetadata("text/plain"));
    SplitFileFetcherStoragePersistence.PreparedMetadata prepared =
        SplitFileFetcherStoragePersistence.preparePersistent(
            metadata,
            bucketFactory,
            new FreenetURI(WANNA_CHK_1),
            new FreenetURI(WANNA_USK_1),
            "client-details".getBytes(StandardCharsets.UTF_8),
            true,
            32L,
            checksumChecker,
            2,
            1,
            99L);

    byte[] metadataBytes = BucketTools.toByteArray(prepared.metadataTemp());
    byte[] basicPayload = "basic-settings".getBytes(StandardCharsets.UTF_8);
    byte[] encodedBasicSettings = checksumChecker.appendChecksum(basicPayload);
    int checksumLength = checksumChecker.checksumLength();
    int versionBytesLength = 10;
    long totalLength =
        prepared.offsetBasicSettings()
            + encodedBasicSettings.length
            + Integer.BYTES
            + checksumLength
            + versionBytesLength
            + Long.BYTES;
    LockableRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer((int) totalLength);

    SplitFileFetcherStoragePersistence.writePersistentMetadata(
        raf, 32L, prepared, encodedBasicSettings, checksumChecker, totalLength);

    byte[] buffer = new byte[(int) totalLength];
    raf.pread(0, buffer, 0, buffer.length);

    assertArrayEquals(metadataBytes, slice(buffer, 32L, metadataBytes.length));
    assertArrayEquals(
        prepared.encodedURI(),
        slice(buffer, prepared.offsetOriginalDetails(), prepared.encodedURI().length));
    assertArrayEquals(
        encodedBasicSettings,
        slice(buffer, prepared.offsetBasicSettings(), encodedBasicSettings.length));

    int footerOffset = (int) (prepared.offsetBasicSettings() + encodedBasicSettings.length);
    try (DataInputStream dis =
        new DataInputStream(
            new ByteArrayInputStream(buffer, footerOffset, buffer.length - footerOffset))) {
      int lengthWithoutChecksum = dis.readInt();
      assertEquals(encodedBasicSettings.length - checksumLength, lengthWithoutChecksum);
      byte[] checksum = dis.readNBytes(checksumLength);
      byte[] versionBytes = new byte[versionBytesLength];
      dis.readFully(versionBytes);

      byte[] expectedVersionBytes = buildVersionBytes(checksumChecker);
      assertArrayEquals(expectedVersionBytes, versionBytes);

      byte[] expectedChecksum =
          checksumChecker.generateChecksum(
              concat(intToBytes(lengthWithoutChecksum), expectedVersionBytes));
      assertArrayEquals(expectedChecksum, checksum);

      long endMagic = dis.readLong();
      assertEquals(SplitFileFetcherStorage.END_MAGIC, endMagic);
      assertEquals(-1, dis.read());
    }
  }

  private static byte[] serializeMetadata(Metadata metadata)
      throws IOException, MetadataUnresolvedException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      metadata.writeTo(dos);
    }
    return baos.toByteArray();
  }

  @SuppressWarnings("java:S107")
  private static void verifyEncodedOriginalDetails(
      byte[] encoded,
      ChecksumChecker checksumChecker,
      FreenetURI thisKey,
      FreenetURI origKey,
      boolean isFinalFetch,
      byte[] clientDetails,
      int maxRetries,
      int cooldownTries,
      long cooldownLength)
      throws IOException {
    int checksumLength = checksumChecker.checksumLength();
    byte[] payload = Arrays.copyOf(encoded, encoded.length - checksumLength);
    byte[] checksum = Arrays.copyOfRange(encoded, payload.length, encoded.length);
    assertTrue(checksumChecker.checkChecksum(payload, 0, payload.length, checksum));

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payload))) {
      assertEquals(thisKey.toASCIIString(), dis.readUTF());
      assertEquals(origKey.toASCIIString(), dis.readUTF());
      assertEquals(isFinalFetch, dis.readBoolean());
      int detailsLength = dis.readInt();
      byte[] details = new byte[detailsLength];
      dis.readFully(details);
      assertArrayEquals(clientDetails, details);
      assertEquals(maxRetries, dis.readInt());
      assertEquals(cooldownTries, dis.readInt());
      assertEquals(cooldownLength, dis.readLong());
      assertEquals(-1, dis.read());
    }
  }

  private static byte[] slice(byte[] source, long offset, int length) {
    return Arrays.copyOfRange(source, (int) offset, (int) offset + length);
  }

  private static byte[] buildVersionBytes(ChecksumChecker checksumChecker) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(0);
      dos.writeShort(checksumChecker.getChecksumTypeID());
      dos.writeInt(SplitFileFetcherStorage.VERSION);
    }
    return baos.toByteArray();
  }

  private static byte[] intToBytes(int value) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(value);
    }
    return baos.toByteArray();
  }

  private static byte[] concat(byte[] left, byte[] right) {
    byte[] combined = Arrays.copyOf(left, left.length + right.length);
    System.arraycopy(right, 0, combined, left.length, right.length);
    return combined;
  }
}
