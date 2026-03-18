package network.crypta.runtime.spi;

import java.io.File;
import java.util.Objects;

/**
 * Detached request data for creating a new persistent insert from a local directory tree.
 *
 * <p>This request represents the queue flow where the user chooses a local directory for a
 * manifest-style insert. It keeps only the selected root directory, the caller-chosen insert
 * metadata, and the detached option values the legacy adapter needs to rebuild the older
 * directory-insert path.
 *
 * <p>The HTTP layer remains responsible for URI parsing, redirects, and user-facing error pages.
 * The runtime adapter consumes this value to perform access checks, rebuild the legacy {@code
 * ClientPutDir}, and start the request on the persistent queue.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class QueueLocalDirectoryInsertRequest {
  private final File sourceDirectory;
  private final String insertUri;
  private final String identifier;
  private final QueueInsertOptions options;

  /**
   * Creates a detached local-directory insert request.
   *
   * @param sourceDirectory selected local directory that should be inserted
   * @param insertUri validated insert URI string chosen by the caller
   * @param identifier queue identifier that should remain stable for this insert attempt
   * @param options detached insert options mirrored from queue form controls
   */
  public QueueLocalDirectoryInsertRequest(
      File sourceDirectory, String insertUri, String identifier, QueueInsertOptions options) {
    this.sourceDirectory = Objects.requireNonNull(sourceDirectory, "sourceDirectory");
    this.insertUri = Objects.requireNonNull(insertUri, "insertUri");
    this.identifier = Objects.requireNonNull(identifier, "identifier");
    this.options = Objects.requireNonNull(options, "options");
  }

  /**
   * Returns the selected source directory.
   *
   * @return local directory that the runtime adapter should scan and enqueue
   */
  public File sourceDirectory() {
    return sourceDirectory;
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
   * @return {@code true} when the directory insert should request compression
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

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof QueueLocalDirectoryInsertRequest other)) {
      return false;
    }
    return Objects.equals(sourceDirectory, other.sourceDirectory)
        && Objects.equals(insertUri, other.insertUri)
        && Objects.equals(identifier, other.identifier)
        && Objects.equals(options, other.options);
  }

  @Override
  public int hashCode() {
    return Objects.hash(sourceDirectory, insertUri, identifier, options);
  }

  @Override
  public String toString() {
    return "QueueLocalDirectoryInsertRequest[sourceDirectory="
        + sourceDirectory
        + ", insertUri="
        + insertUri
        + ", identifier="
        + identifier
        + ", compress="
        + options.compress()
        + ", compatibilityMode="
        + options.compatibilityMode()
        + ']';
  }
}
