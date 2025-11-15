package network.crypta.clients.fcp;

import java.net.MalformedURLException;
import network.crypta.keys.FreenetURI;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a directory entry that redirects to a {@link FreenetURI} instead of embedding data.
 *
 * <p>This implementation is selected when an FCP client issues a multi-file insert with {@code
 * UploadFrom=redirect}. Rather than staging bytes inside a {@link RandomAccessBucket}, the class
 * retains the manifest-relative file name, negotiates a MIME type, and carries the target URI so
 * that manifest serialization can produce a redirect element. Instances are immutable except for
 * the inherited {@link DirPutFile#meta} metadata bundle, which is still scoped to the request that
 * owns the directory builder.
 *
 * <p>Callers typically obtain instances through {@link #create(String, String, SimpleFieldSet,
 * String, boolean)} while parsing an incoming {@link SimpleFieldSet}. Once constructed, the object
 * can be attached to a manifest builder and later queried for {@link #getElement()} when the
 * directory is serialized onto the network. Because no payload buckets exist, the type has trivial
 * memory usage and can safely be shared across threads provided the surrounding manifest builder
 * enforces its own synchronization rules.
 *
 * <ul>
 *   <li>Does not allocate disk or memory buckets, relying solely on redirect metadata.
 *   <li>Guarantees that {@link #getData()} always returns {@code null} to signal redirect entries.
 *   <li>Ensures MIME inference mirrors the behavior of other {@link DirPutFile} subclasses.
 * </ul>
 */
public class RedirectDirPutFile extends DirPutFile {
  private static final Logger LOG = LoggerFactory.getLogger(RedirectDirPutFile.class);

  final FreenetURI targetURI;

  // Legacy threshold callback removed.

  /**
   * Creates a {@code RedirectDirPutFile} from the provided FCP field subset.
   *
   * <p>The factory validates that {@code TargetURI} is present, parses it into a {@link FreenetURI}
   * instance, and determines the MIME type either from {@code Metadata.ContentType} or from the
   * manifest-relative name. Errors are surfaced via {@link MessageInvalidException} so the caller
   * can relay precise {@link ProtocolErrorMessage} details back to the client. The returned
   * instance is ready for manifest assembly and contains no buffered payload data.
   *
   * @param name manifest-relative entry name whose extension may influence MIME inference; must not
   *     be {@code null}.
   * @param contentTypeOverride MIME override supplied by the client; {@code null} to trigger the
   *     standard {@link #guessMIME(String)} heuristic.
   * @param subset parsed request fields that include {@code TargetURI}; the object is not mutated
   *     by this method.
   * @param identifier textual identifier echoed in generated protocol errors for traceability.
   * @param global whether the caller expects the error to be flagged as global when thrown back to
   *     the client connection.
   * @return redirect entry that can be added directly to a manifest builder without further setup.
   * @throws MessageInvalidException if {@code TargetURI} is missing, syntactically invalid, or the
   *     MIME override fails validation against {@link ProtocolErrorMessage} rules.
   */
  public static RedirectDirPutFile create(
      String name,
      String contentTypeOverride,
      SimpleFieldSet subset,
      String identifier,
      boolean global)
      throws MessageInvalidException {
    String target = subset.get("TargetURI");
    if (target == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD,
          "TargetURI missing but UploadFrom=redirect",
          identifier,
          global);
    FreenetURI targetURI;
    try {
      targetURI = new FreenetURI(target);
    } catch (MalformedURLException e) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD, "Invalid TargetURI: " + e, identifier, global);
    }
    if (LOG.isDebugEnabled()) LOG.debug("targetURI = {}", targetURI);
    String mimeType;
    if (contentTypeOverride != null) mimeType = contentTypeOverride;
    else mimeType = guessMIME(name);
    return new RedirectDirPutFile(name, mimeType, targetURI);
  }

  /**
   * Builds a redirect entry with a fixed manifest path, MIME declaration, and target URI.
   *
   * <p>This constructor is primarily used by {@link #create(String, String, SimpleFieldSet, String,
   * boolean)} but can also serve tests that want to assemble redirect elements manually. All
   * arguments are stored verbatim and the resulting instance contains no payload data or side
   * effects.
   *
   * @param name manifest-relative entry name; callers should pass the exact value that will appear
   *     in the directory manifest.
   * @param mimeType MIME string associated with the redirect; typically a client override or the
   *     result of {@link #guessMIME(String)}.
   * @param targetURI destination URI to embed in the manifest; must refer to a valid {@link
   *     FreenetURI} instance expected by fetchers.
   */
  public RedirectDirPutFile(String name, String mimeType, FreenetURI targetURI) {
    super(name, mimeType);
    this.targetURI = targetURI;
  }

  /** {@inheritDoc} */
  @Override
  public RandomAccessBucket getData() {
    return null;
  }

  /**
   * Returns a {@link ManifestElement} describing this redirect for manifest serialization.
   *
   * <p>The element contains no backing data bucket and reports a size of {@code -1} per manifest
   * conventions. The {@link ManifestElement#getName()} matches the original manifest-relative path,
   * which is important for directory builders that preserve folder hierarchies.
   *
   * @return manifest element that references {@link #targetURI} and retains the negotiated MIME
   *     type, never {@code null}.
   */
  @Override
  public ManifestElement getElement() {
    return new ManifestElement(name, targetURI, getMIMEType());
  }
}
