package network.crypta.clients.fcp;

import java.io.IOException;
import network.crypta.client.ClientMetadata;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Prepares upload buckets and redirect metadata for {@link ClientPut} requests.
 *
 * <p>This helper centralizes the staging of payload data before a put request is scheduled. Callers
 * use it to translate message or persistent-request inputs into a {@link PreparedData} bundle that
 * records the bucket holding the upload bytes, whether the bucket contains redirect metadata, and
 * the redirect target URI if applicable. The logic is deterministic and avoids mutating the input
 * buckets beyond any work required to serialize redirect metadata.
 *
 * <p>When the upload is a redirect, the factory delegates metadata-bucket construction to the
 * insert runtime seam. For direct uploads the original bucket is returned unchanged. This
 * separation keeps the request constructors focused on lifecycle wiring while ensuring consistent
 * redirect behavior across persistent and connection-scoped flows.
 *
 * <ul>
 *   <li>Builds redirect metadata buckets when {@link ClientPutBase.UploadFrom#REDIRECT} is chosen.
 *   <li>Returns original buckets for direct or disk uploads without extra copying.
 *   <li>Captures the redirect target URI for downstream status reporting.
 * </ul>
 *
 * @see ClientPut
 * @see PreparedData
 */
final class ClientPutPreparedDataFactory {
  /** Logger used for optional debug tracing of upload sources. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutPreparedDataFactory.class);

  /** Template for debug logs that include bucket and upload source information. */
  private static final String DATA_UPLOAD_LOG_TEMPLATE = "data = {}, uploadFrom = {}";

  /** Prevents instantiation; this class exposes only static factories. */
  private ClientPutPreparedDataFactory() {}

  /**
   * Prepares data for persistent inserts, optionally serializing redirect metadata.
   *
   * <p>When the upload source is {@link ClientPutBase.UploadFrom#REDIRECT}, the method asks the
   * insert runtime seam to serialize a redirect metadata document into a new bucket aligned with
   * the request persistence. For all other sources, the original bucket is returned and the target
   * URI is cleared. The method does not modify the contents of the original bucket.
   *
   * @param uploadFrom upload source describing whether this is a redirect or direct upload.
   * @param metadata client metadata used when generating redirect documents; must not be null.
   * @param data bucket holding the raw upload payload; must not be {@code null}.
   * @param redirectTarget redirect target URI used when {@code uploadFrom} is redirect; may be
   *     {@code null} when unused.
   * @param runtimeSupport insert runtime support providing the bucket factory; must not be {@code
   *     null}.
   * @param persistentForever whether to use a forever-persistent bucket factory.
   * @return a {@link PreparedData} bundle describing the bucket to insert and redirect metadata.
   * @throws MetadataUnresolvedException when redirect metadata cannot serialize.
   * @throws IOException when bucket allocation or serialization fails.
   */
  static PreparedData prepareForPersistentUpload(
      ClientPutBase.UploadFrom uploadFrom,
      ClientMetadata metadata,
      RandomAccessBucket data,
      FreenetURI redirectTarget,
      FcpInsertRuntimeSupport runtimeSupport,
      boolean persistentForever)
      throws MetadataUnresolvedException, IOException {
    if (uploadFrom == ClientPutBase.UploadFrom.REDIRECT) {
      RandomAccessBucket redirectData =
          runtimeSupport.createRedirectMetadataBucket(metadata, redirectTarget, persistentForever);
      return new PreparedData(redirectData, true, redirectTarget);
    }
    return new PreparedData(data, false, null);
  }

  /**
   * Prepares to upload data for a live FCP message, translating redirects when requested.
   *
   * <p>The method reads the bucket supplied by {@link ClientPutMessage} and emits a debug trace of
   * the upload source. For redirect uploads, it asks the insert runtime seam to serialize redirect
   * metadata into a new bucket. Any metadata serialization failure is reported as a protocol error,
   * so the client receives a deterministic failure response.
   *
   * @param message parsed FCP message containing the data bucket; must not be {@code null}.
   * @param metadata client metadata attached to the upload; must not be {@code null}.
   * @param runtimeSupport insert runtime support providing bucket allocation; must not be {@code
   *     null}.
   * @param persistentForever whether to use a forever-persistent bucket factory.
   * @param uploadFrom upload source describing whether this is a redirect or direct upload.
   * @param identifier request identifier used for error reporting; must not be {@code null}.
   * @param global whether the request is in the global queue for error context reporting.
   * @return a {@link PreparedData} bundle with the bucket to insert and redirect metadata details.
   * @throws MessageInvalidException when metadata serialization fails and a protocol error is used.
   * @throws IOException when the message bucket cannot be accessed or serialized.
   */
  static PreparedData prepareForMessage(
      ClientPutMessage message,
      ClientMetadata metadata,
      FcpInsertRuntimeSupport runtimeSupport,
      boolean persistentForever,
      ClientPutBase.UploadFrom uploadFrom,
      String identifier,
      boolean global)
      throws MessageInvalidException, IOException {
    RandomAccessBucket tempData = message.getRandomAccessBucket();
    if (LOG.isDebugEnabled()) LOG.debug(DATA_UPLOAD_LOG_TEMPLATE, tempData, uploadFrom);
    if (uploadFrom == ClientPutBase.UploadFrom.REDIRECT) {
      FreenetURI redirectTarget = message.redirectTarget;
      try {
        RandomAccessBucket redirectData =
            runtimeSupport.createRedirectMetadataBucket(
                metadata, redirectTarget, persistentForever);
        return new PreparedData(redirectData, true, redirectTarget);
      } catch (MetadataUnresolvedException e) {
        throw new MessageInvalidException(
            ProtocolErrorMessage.INTERNAL_ERROR,
            "Impossible: metadata unresolved: " + e,
            identifier,
            global);
      }
    }
    return new PreparedData(tempData, false, null);
  }
}

/**
 * Bundles the prepared upload bucket and redirect metadata details.
 *
 * <p>The bucket contains either raw upload bytes or serialized redirect metadata. The {@code
 * metadata} flag signals whether the bucket should be treated as metadata (redirect) by downstream
 * components. The optional {@code targetUri} preserves the redirect target for reporting and
 * persistence.
 *
 * @param bucket bucket containing upload data or redirect metadata; never {@code null}.
 * @param metadata {@code true} when the bucket holds redirect metadata rather than raw bytes.
 * @param targetUri redirect target URI, or {@code null} when not applicable.
 */
record PreparedData(RandomAccessBucket bucket, boolean metadata, FreenetURI targetUri) {
  /**
   * Reports whether the prepared bucket contains redirect metadata.
   *
   * @return {@code true} when the bucket should be treated as metadata for an insert.
   */
  boolean isMetadata() {
    return metadata;
  }
}
