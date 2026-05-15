package network.crypta.platform.api.queue;

import java.io.ByteArrayInputStream;
import java.util.Objects;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.runtime.spi.QueueUploadedFile;

/**
 * Prepares bounded app-supplied document bytes for queue insertion without exposing local paths.
 *
 * <p>The service gives static browser apps a way to publish generated documents without asking the
 * browser to provide a local source path. The caller supplies already-validated bytes; this service
 * detaches those bytes into a queue upload abstraction so the runtime can copy them into its
 * trusted persistent bucket path instead of treating them as an operator-selected disk upload.
 *
 * <p>This class deliberately does less than a general staging subsystem. It does not persist files,
 * allocate caller-visible paths, or retain app data outside the returned upload object. The app id
 * is still normalized so malformed principals fail at the same boundary as other app-scoped
 * Platform API code. Filenames are treated only as queue key hints and upload metadata; they are
 * trimmed, length-bounded, and checked for path separators before they leave this service.
 *
 * <p>Instances are stateless. A handler can keep one service and use it for many requests because
 * each call copies the supplied document bytes into a fresh replayable upload source.
 */
public final class AppGeneratedDocumentStagingService {
  /**
   * Synthetic public source path used when app-document responses mirror local insert summaries.
   *
   * <p>The value is stable on purpose. It lets callers distinguish app-document inserts from local
   * path inserts without learning any server-side implementation detail or filesystem location.
   */
  private static final String REDACTED_SOURCE_PATH = "<redacted>";

  /**
   * Creates the default app-document staging service.
   *
   * <p>The service has no configuration because current app-document inserts use bounded in-memory
   * upload detachment. Future implementations may add storage policy behind this boundary without
   * changing the public route response shape.
   */
  public AppGeneratedDocumentStagingService() {
    // No fields to initialize; each stage call copies request bytes into a fresh upload object.
  }

  /**
   * Prepares one generated document for the queue insert port.
   *
   * <p>The method validates the app id and target filename, copies the document bytes, and returns
   * a {@link QueueUploadedFile} that can open a fresh stream for the copied content. Copying the
   * byte array here prevents later caller mutations from changing the document that the queue
   * backend receives.
   *
   * @param appId authenticated app id from the Platform API principal
   * @param targetFilename caller-supplied key-hint filename, or blank for the profile default
   * @param contentType validated content type associated with the generated document
   * @param document validated document bytes supplied by the app-document route
   * @return detached upload metadata plus the fixed redacted public source placeholder
   * @throws NullPointerException when {@code contentType} or {@code document} is {@code null}
   * @throws PlatformApiException when the app id or filename is not acceptable
   */
  AppGeneratedDocumentStagingResult stage(
      String appId, String targetFilename, String contentType, byte[] document) {
    InstalledAppPaths.normalizeAppId(appId);
    String safeTargetFilename = sanitizeTargetFilename(targetFilename);
    String safeContentType = Objects.requireNonNull(contentType, "contentType");
    byte[] safeDocument = Objects.requireNonNull(document, "document").clone();
    QueueUploadedFile upload =
        new QueueUploadedFile(
            safeTargetFilename,
            safeContentType,
            safeDocument.length,
            () -> new ByteArrayInputStream(safeDocument));
    return new AppGeneratedDocumentStagingResult(upload, REDACTED_SOURCE_PATH);
  }

  /**
   * Converts a caller-supplied target filename into safe upload metadata.
   *
   * <p>Only a single filename component is accepted. The method does not try to interpret platform
   * path syntax beyond separators, dot components, ASCII controls, and a small length bound because
   * the value is not used as a local filesystem path. It is carried forward as upload metadata and
   * as a key hint when the insert URI has no doc name.
   *
   * @param value raw target filename parameter value, possibly blank
   * @return trimmed filename or the default {@code profile.json} filename
   * @throws PlatformApiException when the filename is too long or path-like
   */
  private static String sanitizeTargetFilename(String value) {
    String filename = value == null || value.isBlank() ? "profile.json" : value.trim();
    if (filename.length() > 128) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "Query parameter 'targetFilename' is too long.");
    }
    for (int index = 0; index < filename.length(); index++) {
      char ch = filename.charAt(index);
      if (ch < 0x20 || ch == 0x7f || ch == '/' || ch == '\\') {
        throw new PlatformApiException(
            400,
            "invalid_query_parameter",
            "Query parameter 'targetFilename' must be a filename, not a path.");
      }
    }
    if (".".equals(filename) || "..".equals(filename)) {
      throw new PlatformApiException(
          400,
          "invalid_query_parameter",
          "Query parameter 'targetFilename' must be a filename, not a path.");
    }
    return filename;
  }
}
