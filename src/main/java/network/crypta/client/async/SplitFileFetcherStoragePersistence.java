package network.crypta.client.async;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.Metadata;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.HashType;
import network.crypta.crypt.MultiHashOutputStream;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import org.jetbrains.annotations.NotNull;

/**
 * Encapsulates persistence-related encoding and I/O for splitfile storage.
 *
 * <p>Owns bucket-based staging, checksum handling, and footer writes so the main storage class can
 * focus on orchestration.
 */
final class SplitFileFetcherStoragePersistence {
  /** Prepared metadata buffers and offsets for a persistent layout. */
  record PreparedMetadata(
      Bucket metadataTemp,
      byte[] encodedURI,
      long offsetOriginalDetails,
      long offsetBasicSettings) {
    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (!(o
          instanceof
          PreparedMetadata(
              Bucket otherMetadataTemp,
              byte[] otherEncodedURI,
              long otherOffsetOriginalDetails,
              long otherOffsetBasicSettings))) {
        return false;
      }
      return offsetOriginalDetails == otherOffsetOriginalDetails
          && offsetBasicSettings == otherOffsetBasicSettings
          && Objects.equals(metadataTemp, otherMetadataTemp)
          && Arrays.equals(encodedURI, otherEncodedURI);
    }

    @Override
    public int hashCode() {
      int result = Objects.hash(metadataTemp, offsetOriginalDetails, offsetBasicSettings);
      result = 31 * result + Arrays.hashCode(encodedURI);
      return result;
    }

    @Override
    public @NotNull String toString() {
      return "PreparedMetadata[metadataTemp="
          + metadataTemp
          + ", encodedURI="
          + Arrays.toString(encodedURI)
          + ", offsetOriginalDetails="
          + offsetOriginalDetails
          + ", offsetBasicSettings="
          + offsetBasicSettings
          + "]";
    }
  }

  static byte[] encodeGeneralProgress(
      ChecksumChecker checksumChecker, boolean hasCheckedDatastore, FailureCodeTracker errors) {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (OutputStream ccos =
            checksumChecker.checksumWriterWithLength(baos, new ArrayBucketFactory());
        DataOutputStream dos = new DataOutputStream(ccos)) {
      long flags = hasCheckedDatastore ? SplitFileFetcherStorage.HAS_CHECKED_DATASTORE_FLAG : 0;
      dos.writeLong(flags);
      errors.writeFixedLengthTo(dos);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  static PreparedMetadata preparePersistent(
      Metadata metadata,
      BucketFactory tempBucketFactory,
      FreenetURI thisKey,
      FreenetURI origKey,
      byte[] clientDetails,
      boolean isFinalFetch,
      long offsetOriginalMetadata,
      ChecksumChecker checksumChecker,
      int maxRetries,
      int cooldownTries,
      long cooldownLength)
      throws FetchException, IOException {
    Bucket metadataTemp = tempBucketFactory.makeBucket(-1);
    try (OutputStream os = metadataTemp.getOutputStream();
        OutputStream cos = checksumChecker.checksumWriter(os);
        BufferedOutputStream bos = new BufferedOutputStream(cos)) {
      MultiHashOutputStream mos = new MultiHashOutputStream(bos, HashType.SHA256.bitmask);
      metadata.writeTo(new DataOutputStream(mos));
      mos.getResults()[0].writeTo(bos);
    } catch (MetadataUnresolvedException e) {
      throw new FetchException(
          FetchExceptionMode.INTERNAL_ERROR,
          "Metadata not resolved starting splitfile fetch?!: " + e,
          e);
    }
    long metadataLength = metadataTemp.size();
    long computedOffsetOriginalDetails = offsetOriginalMetadata + metadataLength;

    byte[] encodedURI =
        encodeAndChecksumOriginalDetails(
            thisKey,
            origKey,
            clientDetails,
            isFinalFetch,
            checksumChecker,
            maxRetries,
            cooldownTries,
            cooldownLength);
    long computedOffsetBasicSettings = computedOffsetOriginalDetails + encodedURI.length;

    return new PreparedMetadata(
        metadataTemp, encodedURI, computedOffsetOriginalDetails, computedOffsetBasicSettings);
  }

  static void writePersistentMetadata(
      LockableRandomAccessBuffer raf,
      long offsetOriginalMetadata,
      PreparedMetadata prepared,
      byte[] encodedBasicSettings,
      ChecksumChecker checksumChecker,
      long totalLength)
      throws IOException {
    try (Bucket metadataTemp = prepared.metadataTemp()) {
      BucketTools.copyTo(metadataTemp, raf, offsetOriginalMetadata, -1);
    }
    raf.pwrite(
        prepared.offsetOriginalDetails(), prepared.encodedURI(), 0, prepared.encodedURI().length);
    raf.pwrite(
        prepared.offsetBasicSettings(), encodedBasicSettings, 0, encodedBasicSettings.length);

    int checksumLength = checksumChecker.checksumLength();
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeInt(encodedBasicSettings.length - checksumLength);
    byte[] bufToWrite = baos.toByteArray();
    baos = new ByteArrayOutputStream();
    dos = new DataOutputStream(baos);
    dos.writeInt(0);
    dos.writeShort(checksumChecker.getChecksumTypeID());
    dos.writeInt(SplitFileFetcherStorage.VERSION);
    byte[] versionBytes = baos.toByteArray();
    byte[] bufToChecksum = Arrays.copyOf(bufToWrite, bufToWrite.length + versionBytes.length);
    System.arraycopy(versionBytes, 0, bufToChecksum, bufToWrite.length, versionBytes.length);
    byte[] checksum = checksumChecker.generateChecksum(bufToChecksum);
    raf.pwrite(
        prepared.offsetBasicSettings() + encodedBasicSettings.length,
        bufToWrite,
        0,
        bufToWrite.length);
    raf.pwrite(
        prepared.offsetBasicSettings() + encodedBasicSettings.length + bufToWrite.length,
        checksum,
        0,
        checksum.length);
    raf.pwrite(
        prepared.offsetBasicSettings()
            + encodedBasicSettings.length
            + bufToWrite.length
            + checksum.length,
        versionBytes,
        0,
        versionBytes.length);
    baos = new ByteArrayOutputStream();
    dos = new DataOutputStream(baos);
    dos.writeLong(SplitFileFetcherStorage.END_MAGIC);
    byte[] buf = baos.toByteArray();
    raf.pwrite(totalLength - 8, buf, 0, 8);
  }

  private static byte[] encodeAndChecksumOriginalDetails(
      FreenetURI thisKey,
      FreenetURI origKey,
      byte[] clientDetails,
      boolean isFinalFetch,
      ChecksumChecker checksumChecker,
      int maxRetries,
      int cooldownTries,
      long cooldownLength)
      throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeUTF(thisKey.toASCIIString());
    dos.writeUTF(origKey.toASCIIString());
    dos.writeBoolean(isFinalFetch);
    dos.writeInt(clientDetails.length);
    dos.write(clientDetails);
    dos.writeInt(maxRetries);
    dos.writeInt(cooldownTries);
    dos.writeLong(cooldownLength);
    return checksumChecker.appendChecksum(baos.toByteArray());
  }

  private SplitFileFetcherStoragePersistence() {}
}
