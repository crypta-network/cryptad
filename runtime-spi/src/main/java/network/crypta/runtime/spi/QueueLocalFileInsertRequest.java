package network.crypta.runtime.spi;

import java.io.File;
import java.util.Objects;

/**
 * Detached request data for creating a new persistent insert from a local file.
 *
 * <p>This request represents the queue flow where the user chooses one local file from the file
 * browser. It carries the selected source file, the caller-chosen insert metadata, and the detached
 * option values the daemon-side adapter needs to rebuild the existing persistent insert request.
 *
 * <p>The request intentionally avoids FCP and HTTP-owned types. The HTTP layer stays responsible
 * for request parsing and user-facing mapping, while the runtime adapter consumes this value to
 * perform access checks and start the insert.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class QueueLocalFileInsertRequest {
  private final File sourceFile;
  private final String insertUri;
  private final String identifier;
  private final String contentType;
  private final QueueInsertOptions options;
  private final String targetFilename;

  /**
   * Creates a detached local-file insert request.
   *
   * @param sourceFile selected local file that should be inserted
   * @param insertUri validated insert URI string chosen by the caller
   * @param identifier queue identifier that should remain stable for this insert attempt
   * @param contentType optional MIME type to expose to the legacy insert path
   * @param options detached insert options mirrored from queue form controls
   * @param targetFilename optional filename hint stored with the legacy request
   */
  public QueueLocalFileInsertRequest(
      File sourceFile,
      String insertUri,
      String identifier,
      String contentType,
      QueueInsertOptions options,
      String targetFilename) {
    this.sourceFile = Objects.requireNonNull(sourceFile, "sourceFile");
    this.insertUri = Objects.requireNonNull(insertUri, "insertUri");
    this.identifier = Objects.requireNonNull(identifier, "identifier");
    this.contentType = contentType;
    this.options = Objects.requireNonNull(options, "options");
    this.targetFilename = targetFilename;
  }

  /**
   * Returns the selected local source file.
   *
   * @return file that the runtime adapter should reopen for the insert
   */
  public File sourceFile() {
    return sourceFile;
  }

  /**
   * Returns the detached insert URI string.
   *
   * @return validated insert URI string chosen by the caller
   */
  public String insertUri() {
    return insertUri;
  }

  /**
   * Returns the caller-selected queue identifier.
   *
   * @return identifier that distinguishes this insert attempt in the persistent queue
   */
  public String identifier() {
    return identifier;
  }

  /**
   * Returns the optional MIME type for the file insert.
   *
   * @return caller-supplied MIME type, or {@code null} when no type was selected
   */
  public String contentType() {
    return contentType;
  }

  /**
   * Returns the detached insert-option bundle.
   *
   * @return shared option values used when rebuilding the legacy insert request
   */
  public QueueInsertOptions options() {
    return options;
  }

  /**
   * Returns the detached compression preference.
   *
   * @return {@code true} when the file insert should request compression
   */
  public boolean compress() {
    return options.compress();
  }

  /**
   * Returns the requested compatibility mode.
   *
   * @return compatibility-mode name understood by the legacy adapter
   */
  public String compatibilityMode() {
    return options.compatibilityMode();
  }

  /**
   * Returns the optional override splitfile crypto key.
   *
   * @return caller-supplied splitfile key bytes, or {@code null} when absent
   */
  public byte[] overrideSplitfileCryptoKey() {
    return options.overrideSplitfileCryptoKey();
  }

  /**
   * Returns the optional target filename for the insert.
   *
   * @return filename hint stored with the legacy request, or {@code null} when absent
   */
  public String targetFilename() {
    return targetFilename;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof QueueLocalFileInsertRequest other)) {
      return false;
    }
    return Objects.equals(sourceFile, other.sourceFile)
        && Objects.equals(insertUri, other.insertUri)
        && Objects.equals(identifier, other.identifier)
        && Objects.equals(contentType, other.contentType)
        && Objects.equals(options, other.options)
        && Objects.equals(targetFilename, other.targetFilename);
  }

  @Override
  public int hashCode() {
    return Objects.hash(sourceFile, insertUri, identifier, contentType, options, targetFilename);
  }

  @Override
  public String toString() {
    return "QueueLocalFileInsertRequest[sourceFile="
        + sourceFile
        + ", insertUri="
        + insertUri
        + ", identifier="
        + identifier
        + ", contentType="
        + contentType
        + ", compress="
        + options.compress()
        + ", compatibilityMode="
        + options.compatibilityMode()
        + ", targetFilename="
        + targetFilename
        + ']';
  }
}
