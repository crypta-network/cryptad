package network.crypta.clients.fcp;

import network.crypta.client.ClientMetadata;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.ManifestElement;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Represents a single file entry contributed to a multi-file FCP directory upload.
 *
 * <p>The class captures the manifest-relative file name together with the negotiated {@link
 * ClientMetadata} carried through various upload phases. Subclasses decide how the actual bytes are
 * sourced (direct socket streaming, disk references, or redirect instructions), while the base type
 * guarantees that metadata remains available for manifest assembly and size accounting. Callers
 * typically instantiate concrete implementations through {@link #create(SimpleFieldSet, String,
 * boolean, BucketFactory)} after parsing a {@link SimpleFieldSet} received via FCP, then keep the
 * resulting instance attached to a {@code ClientPutComplexDir} manifest builder.
 *
 * <p>Instances behave as request-scoped transfer objects: the file name is immutable, but the
 * {@code ClientMetadata} payload may be enriched by subclasses before manifest serialization. No
 * internal synchronization is provided, so callers should confine each instance to the thread that
 * manages the surrounding request context.
 *
 * <ul>
 *   <li>Provides shared MIME-type inference helpers.
 *   <li>Builds {@link ManifestElement} objects for manifest serialization.
 *   <li>Acts as the polymorphic contract for storage-backed {@link RandomAccessBucket} data.
 * </ul>
 *
 * @see DirectDirPutFile
 */
abstract class DirPutFile {
  private static final Logger LOG = LoggerFactory.getLogger(DirPutFile.class);

  /**
   * Manifest-relative path for the file entry, preserved exactly as supplied by the client request
   * so downstream code can maintain folder structures and friendly names.
   */
  final String name;

  /**
   * Mutable metadata associated with the file, including MIME type and additional header-like
   * attributes that will be serialized alongside the manifest entry.
   */
  ClientMetadata meta;

  // Legacy threshold callback removed.

  /**
   * Creates a new directory entry descriptor with a fixed name and initial MIME declaration.
   *
   * <p>The constructor performs no validation beyond storing the supplied values because subclasses
   * already validated their inputs while parsing the surrounding {@link SimpleFieldSet}. Callers
   * therefore pass canonical manifest paths and MIME tokens that will remain stable for the
   * lifetime of the request. Subclasses may later tweak {@link #meta} to add metadata extensions.
   *
   * @param name canonical manifest-relative identifier, including optional forward-slash segments.
   * @param mimeType initial MIME type string that may be overridden by explicit metadata blocks.
   */
  protected DirPutFile(String name, String mimeType) {
    this.name = name;
    meta = new ClientMetadata(mimeType);
  }

  /**
   * Infers a MIME type from the provided file name when the client does not supply one explicitly.
   *
   * <p>The helper delegates to {@link DefaultMIMETypes#guessMIMEType(String, boolean)} so the
   * returned MIME reflects the same heuristics used elsewhere in the FCP stack. The result is only
   * a best effort guess based on the filename extension and should be overridden when the client or
   * upper layers know more precise content descriptors.
   *
   * @param name file name containing an optional extension that influences MIME guessing logic.
   * @return detected MIME type string; defaults to {@code application/octet-stream} when unknown.
   */
  protected static String guessMIME(String name) {
    // Guess it just from the name
    return DefaultMIMETypes.guessMIMEType(name, true);
  }

  /**
   * Creates a {@code DirPutFile} by interpreting the supplied FCP field set and upload options.
   *
   * <p>This factory understands the {@code UploadFrom} specifier and instantiates concrete
   * implementations that either stream data directly, read from disk, or proxy an external redirect
   * URL. It validates declared MIME overrides using {@link DefaultMIMETypes} and preserves the
   * user-provided identifier for precise error reporting. The returned instance is ready to attach
   * to a directory upload builder and will defer expensive resource acquisition until {@link
   * #getData()} is invoked.
   *
   * <pre>{@code
   * DirPutFile entry = DirPutFile.create(fields, requestId, false, bucketFactory);
   * manifest.add(entry.getElement());
   * }</pre>
   *
   * @param subset parsed message fields containing {@code Name}, {@code UploadFrom}, and metadata.
   * @param identifier request identifier echoed in thrown {@link ProtocolErrorMessage} instances.
   * @param global whether the client connection expects globally broadcast error signaling flags.
   * @param bf bucket factory available to direct uploads for staging in-memory or temp-file data.
   * @return concrete {@code DirPutFile} aligned with the requested upload mechanism, never {@code
   *     null}.
   * @throws MessageInvalidException if required fields are missing or options are syntactically
   *     invalid for the declared upload mode.
   */
  public static DirPutFile create(
      SimpleFieldSet subset, String identifier, boolean global, BucketFactory bf)
      throws MessageInvalidException {
    String name = subset.get("Name");
    if (name == null)
      throw new MessageInvalidException(
          ProtocolErrorMessage.MISSING_FIELD, "Missing field Name", identifier, global);
    String contentTypeOverride = subset.get("Metadata.ContentType");
    if (contentTypeOverride != null
        && !contentTypeOverride.isEmpty()
        && !DefaultMIMETypes.isPlausibleMIMEType(contentTypeOverride)) {
      throw new MessageInvalidException(
          ProtocolErrorMessage.BAD_MIME_TYPE,
          "Bad MIME type in Metadata.ContentType",
          identifier,
          global);
    }
    String type = subset.get("UploadFrom");
    if ((type == null) || type.equalsIgnoreCase("direct")) {
      return DirectDirPutFile.create(name, contentTypeOverride, subset, identifier, global, bf);
    } else if (type.equalsIgnoreCase("disk")) {
      return DiskDirPutFile.create(name, contentTypeOverride, subset, identifier, global);
    } else if (type.equalsIgnoreCase("redirect")) {
      return RedirectDirPutFile.create(name, contentTypeOverride, subset, identifier, global);
    } else {
      throw new MessageInvalidException(
          ProtocolErrorMessage.INVALID_FIELD,
          "Unsupported or unknown UploadFrom: " + type,
          identifier,
          global);
    }
  }

  /**
   * Returns the manifest-relative name originally provided for this file entry.
   *
   * <p>The value may contain forward slashes to express synthetic folders, and is never normalized
   * by this class so downstream callers can preserve user intent. Because the field is final, the
   * result remains stable for the entire request lifecycle and can safely be cached in manifest
   * builders without additional synchronization.
   *
   * @return exact manifest-relative name string describing where the element will appear.
   */
  public String getName() {
    return name;
  }

  /**
   * Reports the MIME type currently attached to this entry's metadata bundle.
   *
   * <p>The MIME value starts with either the constructor argument or the best-effort guess returned
   * by {@link #guessMIME(String)}, and may later be replaced when a {@code Metadata.ContentType}
   * override is parsed. The returned string is owned by {@link ClientMetadata} and should be
   * treated as immutable by callers.
   *
   * @return MIME type describing the payload, such as {@code text/html} or {@code image/png}.
   */
  public String getMIMEType() {
    return meta.getMIMEType();
  }

  /**
   * Provides random-access byte storage backing the upload entry.
   *
   * <p>Subclasses decide when the underlying bucket is materialized; some defer creation until the
   * first read to avoid unnecessary disk I/O. Callers must therefore be prepared for the method to
   * block while allocating buckets or reading from disk. The returned bucket remains owned by the
   * caller, who is responsible for closing it when manifest serialization completes.
   *
   * @return random-access bucket carrying file contents ready for hashing and encryption.
   */
  public abstract RandomAccessBucket getData();

  /**
   * Builds a {@link ManifestElement} snapshot representing this file for inclusion in a manifest.
   *
   * <p>The method ensures the manifest entry name matches the final path component (so directories
   * are flattened per manifest rules), logs the transformation when debug logging is enabled, and
   * pairs the resolved {@link RandomAccessBucket} with MIME and size metadata. Callers typically
   * use the returned element immediately and then release the bucket via the enclosing manifest
   * writer.
   *
   * @return manifest element populated with sanitized name, data bucket, MIME, and byte length.
   */
  public ManifestElement getElement() {
    String n = name;
    int idx = n.lastIndexOf('/');
    if (idx != -1) n = n.substring(idx + 1);
    if (LOG.isDebugEnabled()) LOG.debug("Element name: {} -> {}", name, n);
    return new ManifestElement(n, getData(), getMIMEType(), getData().size());
  }
}
