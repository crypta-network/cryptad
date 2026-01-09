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
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import org.jetbrains.annotations.NotNull;

/**
 * Encapsulates persistence-related encoding and I/O for splitfile storage.
 *
 * <p>This utility centralizes the byte-level layout used by {@link SplitFileFetcherStorage} when it
 * persists splitfile fetch state. It stages metadata into a temporary {@link Bucket}, appends an
 * SHA-256 digest, encodes original request details with checksum framing, and emits the footer
 * fields that complete the on-disk structure. The methods are intentionally narrow and
 * side-effect-free beyond writing to caller-supplied buffers, which keeps higher-level
 * orchestration focused on scheduling and recovery rather than serialization minutiae. The class is
 * stateless and therefore thread-safe as long as callers do not share the same buffers
 * concurrently.
 *
 * <p>Notable responsibilities include:
 *
 * <ul>
 *   <li>Prepare staged metadata and offsets for later persistent writes.
 *   <li>Serialize progress flags and error trackers into a checksum-framed blob.
 *   <li>Write encoded settings, checksums, and end markers to a random-access buffer.
 * </ul>
 *
 * @see SplitFileFetcherStorage
 * @see ChecksumChecker
 */
final class SplitFileFetcherStoragePersistence {
  /**
   * Holds staged metadata bytes and computed offsets for the persistent layout.
   *
   * <p>The record is produced by {@link #preparePersistent} after metadata is serialized and the
   * original request details are encoded with checksum framing. Offsets are byte positions relative
   * to the same base used when writing the final layout, so callers should treat them as immutable
   * coordinates. The {@link Bucket} is intentionally left open so it can be copied later; callers
   * should either close it directly or pass the record to {@link #writePersistentMetadata}, which
   * closes it after copying.
   *
   * @param metadataTemp temporary bucket containing encoded metadata and appended hash
   * @param encodedURI encoded original details plus checksum for persistent layout
   * @param offsetOriginalDetails byte offset of encoded original details within storage layout
   * @param offsetBasicSettings byte offset of basic settings block within storage layout
   */
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

  /**
   * Serializes general fetch progress and error tracking into a checksum-framed byte array.
   *
   * <p>The method wraps a {@link DataOutputStream} in the {@link ChecksumChecker} framing returned
   * by {@link ChecksumChecker#checksumWriterWithLength(OutputStream, BucketFactory)}. It writes a
   * single flag word that currently records whether the datastore has been checked, followed by the
   * fixed length representation of the {@link FailureCodeTracker}. Closing the stream finalizes the
   * framing, and the resulting byte array is ready for persistence in the progress section.
   *
   * <pre>{@code
   * byte[] payload = SplitFileFetcherStoragePersistence.encodeGeneralProgress(
   *     checksumChecker, true, errorTracker);
   * }</pre>
   *
   * @param checksumChecker non-null checksum provider used to frame the output bytes
   * @param hasCheckedDatastore true when datastore validation already completed for this fetch
   * @param errors non-null tracker written in fixed-length binary form
   * @return byte array containing framed flags and serialized error data
   * @throws IllegalStateException if the checksum writer reports an I/O failure
   */
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

  /**
   * Stages metadata and computes offsets for a persistent splitfile layout.
   *
   * <p>The method serializes {@code metadata} into a temporary {@link Bucket}, appends the SHA-256
   * digest produced by {@link MultiHashOutputStream}, and then computes where the original request
   * details and basic settings should be written relative to {@code offsetOriginalMetadata}. It
   * also encodes the original keys and client details with checksum framing so the caller can later
   * write a contiguous structure without recomputing hashes. The returned record carries both the
   * staged bucket and the computed offsets; the bucket remains open until it is copied.
   *
   * <pre>{@code
   * SplitFileFetchOriginalDetails details =
   *     new SplitFileFetchOriginalDetails(thisKey, origKey, clientDetails, isFinalFetch);
   * SplitFileFetchRetryPolicy retryPolicy =
   *     new SplitFileFetchRetryPolicy(maxRetries, cooldownTries, cooldownLength);
   * PreparedMetadata prepared =
   *     SplitFileFetcherStoragePersistence.preparePersistent(
   *         metadata,
   *         tempBucketFactory,
   *         details,
   *         offsetOriginalMetadata,
   *         checksumChecker,
   *         retryPolicy);
   * }</pre>
   *
   * @param metadata resolved metadata to serialize into the persistent layout
   * @param tempBucketFactory factory used to allocate the temporary metadata bucket
   * @param originalDetails original fetch request details persisted alongside metadata
   * @param offsetOriginalMetadata base byte offset for metadata placement in storage
   * @param checksumChecker checksum provider used for metadata and details framing
   * @param retryPolicy retry and cooldown settings persisted for future resume logic
   * @return prepared metadata with staged bytes and computed offset positions
   * @throws FetchException if metadata is unresolved or encoding fails internally
   * @throws IOException if bucket I/O or checksum output cannot complete
   */
  static PreparedMetadata preparePersistent(
      Metadata metadata,
      BucketFactory tempBucketFactory,
      SplitFileFetchOriginalDetails originalDetails,
      long offsetOriginalMetadata,
      ChecksumChecker checksumChecker,
      SplitFileFetchRetryPolicy retryPolicy)
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
        encodeAndChecksumOriginalDetails(originalDetails, checksumChecker, retryPolicy);
    long computedOffsetBasicSettings = computedOffsetOriginalDetails + encodedURI.length;

    return new PreparedMetadata(
        metadataTemp, encodedURI, computedOffsetOriginalDetails, computedOffsetBasicSettings);
  }

  /**
   * Writes prepared metadata and footer fields into the persistent buffer.
   *
   * <p>The method copies the staged metadata bucket into {@code raf} at {@code
   * offsetOriginalMetadata}, writes the encoded original details and the provided basic settings at
   * the offsets held by {@code prepared}, and then appends a short footer that records the
   * basic-settings length, checksum bytes, and version information. Finally, it writes the end
   * marker at {@code totalLength - 8}. The prepared bucket is closed after the copy completes.
   *
   * @param raf non-null random access buffer that receives the persisted bytes
   * @param offsetOriginalMetadata byte offset where metadata bytes are written
   * @param prepared non-null staging record containing offsets and encoded details
   * @param encodedBasicSettings non-null basic settings payload written verbatim
   * @param checksumChecker checksum provider used to generate the footer checksum
   * @param totalLength total byte length of the persistent layout buffer
   * @throws IOException if any random-access writes or bucket copies fail
   */
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

  /**
   * Encodes original keys and retry settings, then appends a checksum.
   *
   * <p>The payload includes the current key, original key, a final-fetch flag, the client detail
   * bytes with a length prefix, and the retry/cooldown settings in the order expected by the
   * persistence layout. The returned byte array contains the encoded payload followed by the
   * checksum bytes produced by {@link ChecksumChecker#appendChecksum(byte[])}.
   *
   * @param originalDetails original fetch request details persisted alongside metadata
   * @param checksumChecker checksum provider used to append checksum bytes
   * @param retryPolicy retry and cooldown settings persisted for future resume logic
   * @return encoded payload followed by checksum bytes for persistence
   * @throws IOException if an unexpected stream write fails
   */
  private static byte[] encodeAndChecksumOriginalDetails(
      SplitFileFetchOriginalDetails originalDetails,
      ChecksumChecker checksumChecker,
      SplitFileFetchRetryPolicy retryPolicy)
      throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);
    dos.writeUTF(originalDetails.thisKey().toASCIIString());
    dos.writeUTF(originalDetails.origKey().toASCIIString());
    dos.writeBoolean(originalDetails.isFinalFetch());
    dos.writeInt(originalDetails.clientDetails().length);
    dos.write(originalDetails.clientDetails());
    dos.writeInt(retryPolicy.maxRetries());
    dos.writeInt(retryPolicy.cooldownTries());
    dos.writeLong(retryPolicy.cooldownLength());
    return checksumChecker.appendChecksum(baos.toByteArray());
  }

  /** Prevents instantiation; this class exposes only static helpers. */
  private SplitFileFetcherStoragePersistence() {}
}
