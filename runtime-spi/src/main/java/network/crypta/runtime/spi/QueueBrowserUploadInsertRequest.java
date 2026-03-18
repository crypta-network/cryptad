package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Detached request data for creating a new persistent insert from browser-uploaded bytes.
 *
 * <p>Callers usually create this record after the queue UI has parsed a multipart upload and chosen
 * the insert target. The record keeps only JDK-level values plus the detached {@link
 * QueueUploadedFile} stream source that the daemon-side adapter needs to stage the upload into
 * persistent storage. That lets the HTTP layer stay responsible for form handling and user-facing
 * redirects while the runtime layer recreates the legacy insert request.
 *
 * <p>The record is immutable after construction, aside from caller-owned objects referenced by its
 * components. {@code filenameForKey} is optional because not every insert URI needs a filename hint
 * when the legacy daemon rebuilds the final key.
 *
 * @param insertUri validated insert URI string chosen by the caller
 * @param identifier queue identifier that should remain stable for this insert attempt
 * @param upload detached uploaded-file payload that can reopen the browser data
 * @param options detached insert options mirrored from queue form controls
 * @param filenameForKey optional filename hint for key types that embed one
 */
public record QueueBrowserUploadInsertRequest(
    String insertUri,
    String identifier,
    QueueUploadedFile upload,
    QueueInsertOptions options,
    String filenameForKey) {

  /** Validates the required detached values before the request crosses the runtime boundary. */
  public QueueBrowserUploadInsertRequest {
    Objects.requireNonNull(insertUri, "insertUri");
    Objects.requireNonNull(identifier, "identifier");
    Objects.requireNonNull(upload, "upload");
    Objects.requireNonNull(options, "options");
  }

  /**
   * Returns the detached compression preference for the insert.
   *
   * @return {@code true} when the legacy adapter should request compression
   */
  public boolean compress() {
    return options.compress();
  }

  /**
   * Returns the compatibility mode selected for the insert.
   *
   * @return compatibility-mode name understood by the legacy daemon adapter
   */
  public String compatibilityMode() {
    return options.compatibilityMode();
  }

  /**
   * Returns the optional override splitfile crypto key.
   *
   * @return caller-supplied splitfile key bytes, or {@code null} when no override was chosen
   */
  public byte[] overrideSplitfileCryptoKey() {
    return options.overrideSplitfileCryptoKey();
  }
}
