package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.async.BinaryBlob;
import network.crypta.keys.FreenetURI;

/**
 * Resolves and validates MIME types for {@link ClientPut} requests.
 *
 * <p>This helper centralizes MIME selection for single-file puts, so callers do not duplicate
 * validation logic across constructors and message handlers. The resolver first considers the
 * explicit {@code Metadata.ContentType} provided by the client, then falls back to filename-based
 * inference when the client omitted a type. It enforces the binary-blob rule that forbids arbitrary
 * content types and rejects implausible MIME strings before they reach deeper metadata pipelines.
 *
 * <p>All logic is deterministic and side-effect free. The method returns a normalized MIME string
 * or {@code null} when no type should be attached. It does not alter the {@link ClientPutMessage};
 * it only inspects its already-parsed fields. The helper is safe to call from any thread because it
 * reads immutable inputs and performs no I/O.
 *
 * <ul>
 *   <li>Enforces the binary blob constraint defined by {@link BinaryBlob#MIME_TYPE}.
 *   <li>Infers MIME types from filenames using {@link DefaultMIMETypes} heuristics.
 *   <li>Rejects empty or implausible MIME values before request creation.
 * </ul>
 *
 * @see ClientPut
 * @see DefaultMIMETypes
 */
final class ClientPutMimeResolver {
  /** Prevents instantiation; this class only exposes static helpers. */
  private ClientPutMimeResolver() {}

  /**
   * Resolves the effective MIME type for a put request and validates its plausibility.
   *
   * <p>The method respects explicit client input first and only performs filename inference when no
   * content type was supplied. If the request is flagged as a binary blob, only {@link
   * BinaryBlob#MIME_TYPE} is accepted, and any other non-null value triggers a protocol error. When
   * the resulting MIME string is empty, the method normalizes it to {@code null} so downstream
   * metadata handling can treat the absence of a type consistently.
   *
   * <p>Use this during request construction to ensure that invalid MIME strings are rejected before
   * any insert work is scheduled. The method is idempotent for the same inputs and does not mutate
   * the supplied message or filenames.
   *
   * @param message parsed {@link ClientPutMessage} holding the optional content type; must not be
   *     {@code null} and should already contain validated fields.
   * @param origFilename original disk filename, used for inference when content type is absent; may
   *     be {@code null} when the upload did not originate from disk.
   * @param targetFilename optional target filename hint used when no content type or disk filename
   *     is available; may be {@code null}.
   * @param binaryBlob whether the request is a binary blob insert and thus restricts MIME values.
   * @param identifier request identifier used for error reporting; must not be {@code null}.
   * @param global whether the request is in the global queue for error context reporting.
   * @return normalized MIME type string, or {@code null} when no type is applicable.
   * @throws MessageInvalidException when a disallowed or implausible MIME value is supplied.
   */
  static String resolve(
      ClientPutMessage message,
      File origFilename,
      String targetFilename,
      boolean binaryBlob,
      String identifier,
      boolean global)
      throws MessageInvalidException {
    String mimeType = message.contentType;
    if (binaryBlob && mimeType != null && !mimeType.equals(BinaryBlob.MIME_TYPE)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "No MIME type allowed when inserting a binary blob",
          identifier,
          global);
    }
    if (mimeType == null && origFilename != null) {
      mimeType = DefaultMIMETypes.guessMIMEType(origFilename.getName(), true);
    }
    if (mimeType == null && targetFilename != null) {
      mimeType = DefaultMIMETypes.guessMIMEType(targetFilename, true);
    }
    if (mimeType != null && mimeType.isEmpty()) {
      mimeType = null;
    }
    if (mimeType != null && !DefaultMIMETypes.isPlausibleMIMEType(mimeType)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.BAD_MIME_TYPE,
          "Bad MIME type in Metadata.ContentType",
          identifier,
          global);
    }
    if (shouldSuppressMimeForDiskBareChk(message, targetFilename)) {
      // Disk uploads for bare CHK@ without an explicit TargetFilename should follow direct-mode
      // semantics and avoid forcing a two-block metadata wrapper solely for MIME information.
      mimeType = null;
    }
    return mimeType;
  }

  private static boolean shouldSuppressMimeForDiskBareChk(
      ClientPutMessage message, String targetFilename) {
    return message.uploadFromType == ClientPutBase.UploadFrom.DISK
        && targetFilename == null
        && isBareChkInsertUri(message.uri);
  }

  private static boolean isBareChkInsertUri(FreenetURI uri) {
    return uri.getRoutingKey() == null
        && uri.getDocName() == null
        && "CHK".equals(uri.getKeyType());
  }
}
