package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.async.BinaryBlob;

/**
 * Resolves and validates MIME types for {@link ClientPut} requests.
 *
 * <p>The resolver enforces binary blob constraints, applies filename-based MIME inference, and
 * rejects implausible MIME strings to keep FCP validation consistent across request types.
 */
final class ClientPutMimeResolver {
  private ClientPutMimeResolver() {}

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
    return mimeType;
  }
}
