package network.crypta.clients.fcp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.node.Node;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.io.FileBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Inserts a directory tree from local storage as an FCP manifest upload request.
 *
 * <p>The message is queued by {@link FCPConnectionHandler} when a user submits a {@code
 * ClientPutDiskDir} command, meaning the node must serialize the current on-disk layout into a
 * manifest structure. The implementation mirrors the wizard-style internal directory upload flow so
 * that automated tooling and GUI clients observe consistent MIME detection rules, hidden-file
 * handling, and recursive traversal semantics. Every directory level is unfolded eagerly to size
 * files, attach {@link DefaultMIMETypes}, and guard against unreadable paths before the actual
 * network transfer begins. Callers typically instantiate this message during request construction,
 * then rely on {@link #run(FCPConnectionHandler, Node)} to build the manifest map and hand it to
 * the node core. The class is thread-confined: each instance is used by a single connection
 * handler, but the generated bucket map may be consumed by asynchronous upload workers. Error
 * reporting is immediate, so missing directories or unreadable files fail fast instead of producing
 * partial manifests.
 *
 * <p><strong>Responsibilities</strong>
 *
 * <ul>
 *   <li>Validate source directories against node upload policies.
 *   <li>Create {@link ManifestElement} entries for every file and subdirectory.
 *   <li>Respect client flags governing hidden and unreadable files while preserving legacy
 *       behavior.
 * </ul>
 */
public final class ClientPutDiskDirMessage extends ClientPutDirMessage {
  private static final Logger LOG = LoggerFactory.getLogger(ClientPutDiskDirMessage.class);

  /**
   * Canonical message name emitted to peers and logs so that protocol consumers can match the
   * {@code ClientPutDiskDir} verb without inspecting implementation details.
   */
  public static final String NAME = "ClientPutDiskDir";

  final File dirname;
  final boolean allowUnreadableFiles;
  final boolean includeHiddenFiles;

  // Legacy threshold callback removed.

  /**
   * Creates a message from the raw {@link SimpleFieldSet} received over FCP.
   *
   * <p>The constructor extracts required flags immediately so that later validation has fixed
   * semantics even if the caller mutates the field set. The {@code Filename} field must resolve to
   * a directory on the local filesystem; the path is not normalized here because upload policy
   * checks may rely on the original representation.
   *
   * @param fs parsed field set containing {@code Filename}, {@code AllowUnreadableFiles}, and
   *     optional {@code includeHiddenFiles} entries; must not be {@code null}.
   * @throws MessageInvalidException if the {@code Filename} field is absent.
   */
  public ClientPutDiskDirMessage(SimpleFieldSet fs) throws MessageInvalidException {
    String filename = requireFilename(fs);
    super(parseCommonFields(fs));
    allowUnreadableFiles = fs.getBoolean("AllowUnreadableFiles", false);
    includeHiddenFiles = fs.getBoolean("includeHiddenFiles", false);
    dirname = new File(filename);
  }

  /**
   * Returns the wire-level name {@code ClientPutDiskDir} so protocol handlers can identify the
   * request type.
   *
   * @return constant message identifier understood by the node core.
   */
  @Override
  public String getName() {
    return NAME;
  }

  /**
   * Validates the requested directory and starts the manifest-building upload sequence.
   *
   * <p>The method checks whether the node configuration allows reading from the requested path,
   * performs a full recursive traversal via {@link #makeBucketsByName(File, String)}, and hands the
   * resulting manifest tree to {@link FCPConnectionHandler#startClientPutDir}. Errors are raised
   * immediately if the directory is blocked or if the traversal encounters unreadable entries when
   * such failures are not allowed by the client flag. This call is synchronous for traversal, but
   * the returned buckets may be consumed asynchronously by upload workers.
   *
   * @param handler connection handler owning this message; must be non-null and connected.
   * @param node legacy execution parameter retained by the message API; unused here.
   * @throws MessageInvalidException if the directory is not permitted, or traversal fails under the
   *     configured validation rules.
   */
  @Override
  public void run(FCPConnectionHandler handler, Node node) throws MessageInvalidException {
    if (!handler.getServer().runtime().transferAccess().allowUploadFrom(dirname))
      throw new MessageInvalidException(
          ProtocolErrorMessage.ACCESS_DENIED,
          "Not allowed to upload from " + dirname,
          identifier,
          global);
    // Create a directory listing of Buckets of data, mapped to ManifestElement's.
    // Directories are sub-HashMap's.
    Map<String, Object> buckets = makeBucketsByName(dirname, "");
    handler.startClientPutDir(this, buckets, true);
  }

  /**
   * Recursively converts the provided directory into a tree of manifest entries keyed by local
   * filenames.
   *
   * @param thisdir directory whose immediate children are inspected; must already exist on disk.
   * @param prefix a logical path prefix appended to every discovered file or directory name for the
   *     manifest.
   * @return mutable map where keys are child names and values are {@link ManifestElement} instances
   *     or nested maps representing subdirectories.
   * @throws MessageInvalidException if a directory does not exist, or a child violates the
   *     configured readability rules.
   */
  private Map<String, Object> makeBucketsByName(File thisdir, String prefix)
      throws MessageInvalidException {

    if (LOG.isDebugEnabled()) {
      LOG.debug("Listing directory: {}", thisdir);
    }

    Map<String, Object> ret = new HashMap<>();

    File[] filelist = thisdir.listFiles();
    if (filelist == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.FILE_NOT_FOUND, "No such directory!", identifier, global);
    for (File child : filelist) {
      if (shouldSkipEntry(child)) {
        continue;
      }
      addEntry(ret, prefix, child);
    }
    return ret;
  }

  private boolean shouldSkipHidden(File child) {
    return child.isHidden() && !includeHiddenFiles;
  }

  private boolean shouldSkipEntry(File child) throws MessageInvalidException {
    if (shouldSkipHidden(child)) {
      return true;
    }
    return skipUnreadableEntry(child);
  }

  private boolean skipUnreadableEntry(File child) throws MessageInvalidException {
    if (child.canRead() && child.exists()) {
      return false;
    }
    if (!allowUnreadableFiles) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FILE_NOT_FOUND,
          "Not readable or doesn't exist: " + child,
          identifier,
          global);
    }
    return true;
  }

  private void addEntry(Map<String, Object> ret, String prefix, File child)
      throws MessageInvalidException {
    if (child.isFile()) {
      addFileEntry(ret, prefix, child);
    } else if (child.isDirectory()) {
      Map<String, Object> subdir = makeBucketsByName(child, prefix + child.getName() + '/');
      ret.put(child.getName(), subdir);
    } else {
      handleUnknownEntry(child);
    }
  }

  private void addFileEntry(Map<String, Object> ret, String prefix, File file) {
    FileBucket bucket = new FileBucket(file, true, false, false, false);
    ret.put(
        file.getName(),
        new ManifestElement(
            file.getName(),
            prefix + file.getName(),
            bucket,
            DefaultMIMETypes.guessMIMEType(file.getName(), true),
            file.length()));
  }

  private void handleUnknownEntry(File child) throws MessageInvalidException {
    if (!allowUnreadableFiles) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.FILE_NOT_FOUND,
          "Not directory and not file: " + child,
          identifier,
          global);
    }
  }

  @Override
  long dataLength() {
    return 0;
  }

  String getIdentifier() {
    return identifier;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This message derives all payload information from the supplied {@link SimpleFieldSet}, so no
   * additional data is streamed from the request body.
   *
   * @param is ignored because {@code ClientPutDiskDir} has no binary payload.
   * @param bf ignored; manifests are built directly from the filesystem.
   * @param server ignored; included for API symmetry with other messages.
   * @throws IOException never thrown because no I/O occurs here.
   * @throws MessageInvalidException never thrown because parsing already completed in the
   *     constructor.
   */
  @Override
  public void readFrom(InputStream is, BucketFactory bf, FCPServer server)
      throws IOException, MessageInvalidException {
    // Do nothing
  }

  /**
   * {@inheritDoc}
   *
   * <p>No additional data is written because the entire manifest content is produced from the local
   * filesystem instead of a pre-serialized buffer.
   *
   * @param os ignored the output stream provided by the protocol framework.
   * @throws IOException never thrown because the method writes nothing.
   */
  @Override
  protected void writeData(OutputStream os) throws IOException {
    // Do nothing
  }

  private static String requireFilename(SimpleFieldSet fs) throws MessageInvalidException {
    String filename = fs.get("Filename");
    if (filename == null) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "Filename missing",
          fs.get("Identifier"),
          fs.getBoolean("Global", false));
    }
    return filename;
  }
}
