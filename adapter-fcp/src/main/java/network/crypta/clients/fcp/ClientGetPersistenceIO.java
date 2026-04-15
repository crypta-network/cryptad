package network.crypta.clients.fcp;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.FetchException;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.support.api.Bucket;
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

  private static final long CHECKSUMMED_BLOCK_MAX_LENGTH = 65536L;
  private static final String COMPLETED_DOWNLOAD_RESTORE_FAILURE =
      "Failed to restore completed download-to-temp-space request, restarting instead";
  private static final String FETCH_SETTINGS_FALLBACK_MESSAGE =
      "Unable to read fetch settings, will use default settings";

  private ClientGetPersistenceIO() {}

  /**
   * Creates a checksummed reader that wraps the supplied stream.
   *
   * @param dis input stream positioned at the checksummed payload.
   * @param fetchRuntimeSupport fetch runtime support providing temporary bucket services.
   * @param checker checksum helper used to verify the payload.
   * @param maxLength maximum length accepted for the checksummed payload.
   * @return a {@link DataInputStream} that validates checksums on close.
   * @throws IOException if the reader cannot be created.
   * @throws StorageFormatException if checksum verification fails.
   */
  static DataInputStream openChecksummed(
      DataInputStream dis,
      FcpFetchRuntimeSupport fetchRuntimeSupport,
      ChecksumChecker checker,
      long maxLength)
      throws IOException, StorageFormatException {
    return fetchRuntimeSupport.openChecksummed(dis, checker, maxLength);
  }

  private static boolean isChecksumFailure(StorageFormatException exception) {
    return exception.getCause() instanceof ChecksumFailedException;
  }

  /**
   * Restores detached fetch configuration or returns defaults when recovery fails.
   *
   * @param dis input stream positioned at the fetch context data.
   * @param fetchRuntimeSupport fetch runtime support providing default fetch settings.
   * @param checker checksum helper used to verify the serialized block.
   * @return restored detached fetch configuration or the default when recovery fails.
   */
  static ClientGetFetchConfig readFetchConfigOrDefault(
      DataInputStream dis, FcpFetchRuntimeSupport fetchRuntimeSupport, ChecksumChecker checker) {
    try (DataInputStream inner =
        openChecksummed(dis, fetchRuntimeSupport, checker, CHECKSUMMED_BLOCK_MAX_LENGTH)) {
      return fetchRuntimeSupport.decodeFetchConfig(inner);
    } catch (IOException e) {
      LOG.error(FETCH_SETTINGS_FALLBACK_MESSAGE, e);
    } catch (StorageFormatException e) {
      if (isChecksumFailure(e)) {
        LOG.error(FETCH_SETTINGS_FALLBACK_MESSAGE);
      } else {
        LOG.error(FETCH_SETTINGS_FALLBACK_MESSAGE, e);
      }
    }
    return fetchRuntimeSupport.defaultPersistentFetchConfig();
  }

  /**
   * Restores a bucket from a checksummed payload.
   *
   * @param dis input stream positioned at the bucket payload.
   * @param fetchRuntimeSupport fetch runtime support owning persistent bucket services.
   * @param checker checksum helper used to verify the bucket metadata.
   * @return restored bucket from the checksummed payload.
   * @throws IOException if the underlying stream cannot be read.
   * @throws StorageFormatException if checksum validation fails.
   * @throws ResumeFailedException if bucket restoration fails.
   */
  static Bucket restoreBucketFromChecksummedBlock(
      DataInputStream dis, FcpFetchRuntimeSupport fetchRuntimeSupport, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    try (DataInputStream inner =
        openChecksummed(dis, fetchRuntimeSupport, checker, CHECKSUMMED_BLOCK_MAX_LENGTH)) {
      return fetchRuntimeSupport.restorePersistentBucket(inner);
    }
  }

  /**
   * Restores an initial metadata bucket for the request, if present.
   *
   * @param dis input stream positioned at the metadata bucket marker.
   * @param fetchRuntimeSupport fetch runtime support owning persistent bucket services.
   * @param checker checksum helper used to verify the bucket metadata.
   * @return restored bucket or {@code null} when no metadata marker was set.
   * @throws IOException if the underlying stream cannot be read.
   * @throws StorageFormatException if metadata integrity checks fail.
   * @throws ResumeFailedException if bucket restoration fails.
   */
  static Bucket readInitialMetadata(
      DataInputStream dis, FcpFetchRuntimeSupport fetchRuntimeSupport, ChecksumChecker checker)
      throws IOException, StorageFormatException, ResumeFailedException {
    if (!dis.readBoolean()) {
      return null;
    }
    try {
      return restoreBucketFromChecksummedBlock(dis, fetchRuntimeSupport, checker);
    } catch (StorageFormatException e) {
      if (isChecksumFailure(e)) {
        StorageFormatException storageFormatException =
            new StorageFormatException("Unable to restore initial metadata");
        Throwable cause = e.getCause() == null ? e : e.getCause();
        storageFormatException.initCause(cause);
        throw storageFormatException;
      }
      throw e;
    }
  }

  /**
   * Restores a completed direct bucket from persistent storage.
   *
   * @param dis input stream positioned at the bucket payload.
   * @param fetchRuntimeSupport fetch runtime support owning persistent bucket services.
   * @param checker checksum helper used to verify the bucket metadata.
   * @return restored bucket, or {@code null} when restoration failed.
   * @throws ResumeFailedException if bucket restoration fails.
   */
  static Bucket restoreCompletedDirectBucketOrNull(
      DataInputStream dis, FcpFetchRuntimeSupport fetchRuntimeSupport, ChecksumChecker checker)
      throws ResumeFailedException {
    try {
      return restoreBucketFromChecksummedBlock(dis, fetchRuntimeSupport, checker);
    } catch (IOException | StorageFormatException e) {
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
   * @param fetchRuntimeSupport fetch runtime support providing checksum helpers.
   * @param checker checksum helper used to verify the payload.
   * @return restored {@link GetFailedMessage} or {@code null} when recovery fails.
   */
  static GetFailedMessage restoreFailureMessageOrNull(
      DataInputStream dis,
      RequestIdentifier reqID,
      long foundDataLength,
      String foundDataMimeType,
      FcpFetchRuntimeSupport fetchRuntimeSupport,
      ChecksumChecker checker) {
    try (DataInputStream inner =
        openChecksummed(dis, fetchRuntimeSupport, checker, CHECKSUMMED_BLOCK_MAX_LENGTH)) {
      return new GetFailedMessage(inner, reqID, foundDataLength, foundDataMimeType);
    } catch (IOException | StorageFormatException e) {
      LOG.error("Unable to restore reason for failure, restarting request", e);
      return null;
    }
  }

  /**
   * Restores in-progress getter state along with transient progress fields.
   *
   * @param dis input stream positioned at the progress data block.
   * @param fetchRuntimeSupport fetch runtime support used to resume the execution.
   * @param checker checksum helper used to validate the block.
   * @param execution execution handle to resume.
   * @param request the request instance for restoring transient fields.
   * @throws StorageFormatException if the serialized state is invalid.
   */
  static void restoreInProgressState(
      DataInputStream dis,
      FcpFetchRuntimeSupport fetchRuntimeSupport,
      ChecksumChecker checker,
      ClientGetExecution execution,
      ClientGet request)
      throws StorageFormatException {
    try (DataInputStream inner =
        openChecksummed(dis, fetchRuntimeSupport, checker, CHECKSUMMED_BLOCK_MAX_LENGTH)) {
      if (execution.resumeFromTrivialProgress(inner)) {
        ClientGetPersistenceCodec.readTransientProgressFields(request, inner);
      }
    } catch (IOException e) {
      LOG.error("Unable to restore splitfile, restarting: {}", e.toString());
    } catch (StorageFormatException e) {
      if (isChecksumFailure(e)) {
        LOG.error("Unable to restore splitfile, restarting (checksum failed)");
      } else {
        throw e;
      }
    }
  }

  static FcpFetchRuntimeSupport resolveRuntimeFetchSupport(ClientGet request) {
    FcpFetchRuntimeSupport runtimeFetchSupport = request.requestProfile().runtimeFetchSupport();
    if (runtimeFetchSupport != null) {
      return runtimeFetchSupport;
    }
    PersistentRequestClient persistentClient = request.client;
    if (persistentClient == null) {
      return null;
    }
    FCPConnectionHandler connection = persistentClient.getConnection();
    if (connection != null) {
      return connection.getServer().fetchRuntimeSupport();
    }
    PersistentRequestRoot persistentRoot = persistentClient.root;
    return persistentRoot == null ? null : persistentRoot.fetchRuntimeSupport();
  }

  static void prepareForSerialization(ClientGet request) {
    FcpFetchRuntimeSupport fetchRuntimeSupport = resolveRuntimeFetchSupport(request);
    ClientGetFetchConfig fetchConfig = request.requestProfile().fetchConfig();
    if (fetchRuntimeSupport == null || fetchConfig == null) {
      return;
    }
    try (ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream encoded = new DataOutputStream(buffer)) {
      fetchRuntimeSupport.encodeFetchConfig(fetchConfig, encoded);
      request.setPersistedFetchConfigEncoding(buffer.toByteArray());
    } catch (IOException e) {
      LOG.warn(
          "Unable to refresh cached fetch configuration encoding for {}", request.identifier, e);
    }
  }

  static ClientGetExecution recreateExecutionForResume(ClientGet request)
      throws ResumeFailedException {
    FcpFetchRuntimeSupport fetchRuntimeSupport = resolveRuntimeFetchSupport(request);
    if (fetchRuntimeSupport == null) {
      throw new ResumeFailedException("Missing fetch runtime support for GET resume");
    }
    try {
      ClientGetExecution resumedExecution =
          request.makeExecutionForPersistence(request.makePersistenceBucket());
      request.applyDiagnosticIdentifier(resumedExecution.requester());
      return resumedExecution;
    } catch (IOException e) {
      throw new ResumeFailedException(e);
    }
  }

  static void resume(ClientGet request, network.crypta.client.async.ClientContext context)
      throws ResumeFailedException {
    if (request.execution() != null) {
      request.execution().onResume(context);
    } else if (!request.finished) {
      request.setExecution(recreateExecutionForResume(request));
      try {
        request.execution().start();
      } catch (FetchException e) {
        throw new ResumeFailedException(e);
      }
    }
    Bucket returnBucket = request.state().getReturnBucketDirect();
    if (returnBucket != null) {
      returnBucket.onResume(context);
    }
    Bucket initialMetadata = request.requestProfile().initialMetadata();
    if (initialMetadata != null) {
      initialMetadata.onResume(context);
    }
    if (request.execution() != null && request.state().getFoundDataLength() <= 0) {
      request.state().setFoundDataLength(request.execution().expectedSize());
    }
    if (request.execution() != null && request.state().getFoundDataMimeType() == null) {
      request.state().setFoundDataMimeType(request.execution().expectedMime());
    }
  }
}
