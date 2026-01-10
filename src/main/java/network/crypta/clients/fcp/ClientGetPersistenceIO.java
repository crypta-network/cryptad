package network.crypta.clients.fcp;

import java.io.DataInputStream;
import java.io.IOException;
import network.crypta.client.FetchContext;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles persistent I/O for {@link ClientGet} instances.
 *
 * <p>The helper encapsulates checksummed input streams, bucket restoration, and failure recovery so
 * {@link ClientGet} can delegate persistence logic without increasing coupling.
 */
final class ClientGetPersistenceIO {
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetPersistenceIO.class);

  private static final String COMPLETED_DOWNLOAD_RESTORE_FAILURE =
      "Failed to restore completed download-to-temp-space request, restarting instead";
  private static final String FETCH_SETTINGS_FALLBACK_MESSAGE =
      "Unable to read fetch settings, will use default settings";

  private ClientGetPersistenceIO() {}

  /**
   * Creates a checksummed reader that wraps the supplied stream.
   *
   * @param dis input stream positioned at the checksummed payload.
   * @param context client context providing a temporary bucket factory.
   * @param checker checksum helper used to verify the payload.
   * @return a {@link DataInputStream} that validates checksums on close.
   * @throws IOException if the reader cannot be created.
   * @throws ChecksumFailedException if checksum verification fails.
   */
  static DataInputStream checksummedReader(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws IOException, ChecksumFailedException {
    return new DataInputStream(
        checker.checksumReaderWithLength(dis, context.tempBucketFactory, 65536));
  }

  /**
   * Restores the {@link FetchContext}, or returns defaults when recovery fails.
   *
   * @param dis input stream positioned at the fetch context data.
   * @param context client context providing default fetch settings.
   * @param checker checksum helper used to verify the serialized block.
   * @return restored {@link FetchContext} or the default when recovery fails.
   */
  static FetchContext readFetchContextOrDefault(
      DataInputStream dis, ClientContext context, ChecksumChecker checker) {
    try (DataInputStream inner = checksummedReader(dis, context, checker)) {
      return new FetchContext(inner);
    } catch (StorageFormatException | IOException e) {
      LOG.error(FETCH_SETTINGS_FALLBACK_MESSAGE, e);
    } catch (ChecksumFailedException _) {
      LOG.error(FETCH_SETTINGS_FALLBACK_MESSAGE);
    }
    return context.getDefaultPersistentFetchContext();
  }

  /**
   * Restores an initial metadata bucket for the request, if present.
   *
   * @param dis input stream positioned at the metadata bucket marker.
   * @param context client context owning persistent bucket services.
   * @param checker checksum helper used to verify the bucket metadata.
   * @return restored bucket or {@code null} when no metadata marker was set.
   * @throws IOException if the underlying stream cannot be read.
   * @throws StorageFormatException if metadata integrity checks fail.
   * @throws ResumeFailedException if bucket restoration fails.
   */
  static Bucket readInitialMetadata(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    if (!dis.readBoolean()) {
      return null;
    }
    try (DataInputStream metadataStream = checksummedReader(dis, context, checker)) {
      return BucketTools.restoreFrom(
          metadataStream,
          context.persistentFG,
          context.getPersistentFileTracker(),
          context.getPersistentMasterSecret());
    } catch (ChecksumFailedException e) {
      StorageFormatException sfe = new StorageFormatException("Unable to restore initial metadata");
      sfe.initCause(e);
      throw sfe;
    }
  }

  /**
   * Restores a completed direct bucket from persistent storage.
   *
   * @param dis input stream positioned at the bucket payload.
   * @param context client context owning persistent bucket services.
   * @param checker checksum helper used to verify the bucket metadata.
   * @return restored bucket, or {@code null} when restoration failed.
   * @throws ResumeFailedException if bucket restoration fails.
   */
  static Bucket restoreCompletedDirectBucketOrNull(
      DataInputStream dis, ClientContext context, ChecksumChecker checker)
      throws ResumeFailedException {
    try (DataInputStream inner = checksummedReader(dis, context, checker)) {
      return BucketTools.restoreFrom(
          inner,
          context.persistentFG,
          context.getPersistentFileTracker(),
          context.getPersistentMasterSecret());
    } catch (IOException | ChecksumFailedException | StorageFormatException e) {
      LOG.error(COMPLETED_DOWNLOAD_RESTORE_FAILURE, e);
      return null;
    }
  }

  /**
   * Restores the failure message for a finished request.
   *
   * @param dis input stream positioned at the failure message payload.
   * @param reqID request identifier used to populate the failure message.
   * @param foundDataLength recorded data length for the request.
   * @param foundDataMimeType recorded MIME type for the request.
   * @param context client context providing checksum helpers.
   * @param checker checksum helper used to verify the payload.
   * @return restored {@link GetFailedMessage} or {@code null} when recovery fails.
   */
  static GetFailedMessage restoreFailureMessageOrNull(
      DataInputStream dis,
      RequestIdentifier reqID,
      long foundDataLength,
      String foundDataMimeType,
      ClientContext context,
      ChecksumChecker checker) {
    try (DataInputStream inner = checksummedReader(dis, context, checker)) {
      return new GetFailedMessage(inner, reqID, foundDataLength, foundDataMimeType);
    } catch (IOException | ChecksumFailedException | StorageFormatException e) {
      LOG.error("Unable to restore reason for failure, restarting request", e);
      return null;
    }
  }

  /**
   * Restores in-progress getter state along with transient progress fields.
   *
   * @param dis input stream positioned at the progress data block.
   * @param context client context used to resume the getter.
   * @param checker checksum helper used to validate the block.
   * @param inProgressGetter getter instance to resume.
   * @param request request instance for restoring transient fields.
   * @throws StorageFormatException if the serialized state is invalid.
   */
  static void restoreInProgressState(
      DataInputStream dis,
      ClientContext context,
      ChecksumChecker checker,
      ClientGetter inProgressGetter,
      ClientGet request)
      throws StorageFormatException {
    try (DataInputStream inner = checksummedReader(dis, context, checker)) {
      if (inProgressGetter.resumeFromTrivialProgress(inner, context)) {
        request.readTransientProgressFields(inner);
      }
    } catch (IOException e) {
      LOG.error("Unable to restore splitfile, restarting: {}", e.toString());
    } catch (ChecksumFailedException _) {
      LOG.error("Unable to restore splitfile, restarting (checksum failed)");
    }
  }
}
