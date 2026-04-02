package network.crypta.clients.fcp;

import java.io.File;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.FileBucket;

/**
 * DiskDirPutFile models a directory upload element whose bytes live on the local filesystem rather
 * than streaming over the FCP connection.
 *
 * <p>Instances are typically constructed while parsing {@code UploadFrom=disk} manifests. They
 * store the canonical manifest-relative name inherited from {@link DirPutFile} along with a {@link
 * File} reference that points to the caller-specified source path. No bytes are copied during
 * construction; instead, the {@link #getData()} method opens a {@link FileBucket} on demand, which
 * keeps memory usage low even for very large files. The caller is responsible for ensuring that the
 * referenced file remains accessible for the lifetime of the enclosing request and that concurrent
 * modifications do not violate integrity expectations.
 *
 * <p>Because the file contents reside on disk, the class excels when directories include
 * preexisting artifacts that should be re-used verbatim, such as site assets or archival exports.
 * It avoids the latency of restreaming those bytes through the FCP socket and allows directories to
 * mix disk-based and direct uploads seamlessly. Thread safety mirrors {@link FileBucket}: each
 * instance should be confined to the request thread orchestrating the manifest build to prevent
 * parallel access to the same {@link File} handle.
 *
 * <ul>
 *   <li>Defers I/O until manifest serialization needs the bytes.
 *   <li>Provides MIME inference that honors both manifest hints and actual file extensions.
 *   <li>Surfaces missing file declarations as {@link MessageInvalidException} for client clarity.
 * </ul>
 *
 * @see DirectDirPutFile
 * @see FileBucket
 */
public class DiskDirPutFile extends DirPutFile {

  final File file;

  /**
   * Builds a {@link DiskDirPutFile} representing a manifest entry sourced from disk.
   *
   * <p>The factory verifies that the {@code Filename} field exists in the {@link SimpleFieldSet},
   * then captures both the {@link File} reference and the effective MIME type. MIME determination
   * prefers an explicit {@code Metadata.ContentType} supplied earlier, falling back to {@link
   * #guessMIME(String, File)} when unspecified. Any missing required field triggers a {@link
   * MessageInvalidException} carrying the caller-provided identifier so protocol clients receive
   * actionable error responses.
   *
   * <pre>{@code
   * DiskDirPutFile entry = DiskDirPutFile.create(
   *     "images/logo.png", null, subset, requestId, false);
   * FileBucket bucket = (FileBucket) entry.getData();
   * }</pre>
   *
   * @param name manifest-relative identifier for the entry, including optional subdirectories.
   * @param contentTypeOverride explicit MIME token or {@code null} to enable automatic detection.
   * @param subset parsed message subset containing {@code Filename} and metadata from the client.
   * @param identifier caller-supplied token echoed in failure messages for correlation.
   * @param global whether errors should be flagged as global broadcast messages on the connection.
   * @return immutable {@code DiskDirPutFile} bound to the referenced file path.
   * @throws MessageInvalidException if the {@code Filename} field is missing or unusable.
   */
  public static DiskDirPutFile create(
      String name,
      String contentTypeOverride,
      SimpleFieldSet subset,
      String identifier,
      boolean global)
      throws MessageInvalidException {
    String s = subset.get("Filename");
    if (s == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Missing field: Filename on " + name,
          identifier,
          global);
    File file = new File(s);
    String mimeType;
    if (contentTypeOverride == null) mimeType = guessMIME(name, file);
    else mimeType = contentTypeOverride;
    return new DiskDirPutFile(name, mimeType, file);
  }

  /**
   * Creates a disk-backed directory entry with a fixed name, MIME type, and source file.
   *
   * <p>The constructor merely stores references; it does not validate whether the file exists or is
   * readable, leaving that responsibility to the caller and later {@link #getData()} invocations.
   * Supplying an absolute or manifest-relative path is acceptable, but the chosen location must
   * remain stable until the upload finalizes so retries see identical bytes. Use {@link
   * #guessMIME(String, File)} to align MIME selection with the factory when creating instances
   * manually. FileHash metadata is not currently used for disk-backed directory entries.
   *
   * @param name manifest-relative entry name recorded inside the directory manifest.
   * @param mimeType MIME declaration already validated by callers, never {@code null}.
   * @param f source file on disk whose contents will be streamed into the manifest output.
   */
  public DiskDirPutFile(String name, String mimeType, File f) {
    super(name, mimeType);
    this.file = f;
  }

  /**
   * Derives a MIME type for disk uploads by consulting both manifest metadata and file extensions.
   *
   * <p>The method starts with {@link DirPutFile#guessMIME(String)} to honor manifest naming, then
   * falls back to {@link DefaultMIMETypes#guessMIMEType(String, boolean)} using the actual file
   * system name if the manifest guess was inconclusive. This two-step approach keeps directory
   * manifests consistent with direct uploads while still respecting cases where the manifest name
   * omits an extension but the underlying file retains one.
   *
   * @param name manifest-relative path supplied by the client; may omit extensions.
   * @param file filesystem {@link File} whose name may expose a more accurate MIME hint.
   * @return non-null MIME type string best matching the available hints.
   */
  protected static String guessMIME(String name, File file) {
    String mime = DirPutFile.guessMIME(name);
    if (mime == null) {
      mime = DefaultMIMETypes.guessMIMEType(file.getName(), false);
    }
    return mime;
  }

  /**
   * Opens a {@link FileBucket} over the referenced disk file so callers can stream the contents.
   *
   * <p>Each invocation returns a fresh bucket that reads lazily from disk, honoring the {@code
   * random-access} contract required by {@link DirPutFile}. The bucket is configured to keep the
   * backing file available ({@code deleteOnFree=false}) so retries or multiple manifest passes can
   * reuse the same bytes. Callers must ensure that the file remains stable and readable until the
   * returned bucket is freed.
   *
   * @return newly allocated {@code FileBucket} exposing the on-disk payload.
   */
  @Override
  public RandomAccessBucket getData() {
    return new FileBucket(file, true, false, false, false);
  }

  /**
   * Returns the underlying {@link File} referenced by this manifest entry for inspection or
   * verification.
   *
   * <p>The file object is the same instance provided at construction time and may be absolute or
   * relative. Callers may inspect it to check size, timestamps, or permissions before initiating
   * uploads, but any mutations should occur before {@link #getData()} is called to avoid race
   * conditions with readers.
   *
   * @return immutable {@link File} reference representing the upload source path.
   */
  public File getFile() {
    return file;
  }
}
