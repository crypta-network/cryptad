package network.crypta.client;

import java.io.*;

/**
 * Holds lightweight client‑visible metadata for a fetched or inserted item.
 *
 * <p>This type currently models only a single attribute: the content {@code MIME} type. It is
 * intentionally minimal because most metadata in the system is either part of on‑disk structures or
 * is specific to higher‑level protocols. Instances are typically created at the start of a
 * fetch/insert, passed between helpers, and occasionally merged so that known information is not
 * lost when multiple sources contribute partial details.
 *
 * <p><strong>Mutability and thread safety:</strong> instances are mutable and not thread‑safe.
 * Callers should confine an instance to a single thread, clone state by using {@link #copyOf} when
 * sharing across components with different lifecycles, or perform external synchronization when
 * concurrent access is unavoidable.
 *
 * <ul>
 *   <li><em>Responsibilities</em>: store and expose the effective MIME type; provide simple merge
 *       and clear operations; serialize/deserialize to a compact binary form used on internal
 *       queues.
 *   <li><em>Notable behaviors</em>: missing or empty MIME types resolve to the default value
 *       defined by {@link DefaultMIMETypes#DEFAULT_MIME_TYPE}; the textual representation returned
 *       by {@link #toString()} is the effective MIME string.
 * </ul>
 */
public class ClientMetadata implements Serializable {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * The document MIME type.
   *
   * <p>This field may be {@code null} or empty to represent an unknown value. Callers should use
   * {@link #getMIMEType()} for a normalized view that substitutes the default type when the field
   * is not set.
   */
  private String mimeType;

  /**
   * Creates an instance with no MIME type information.
   *
   * <p>The effective type reported by {@link #getMIMEType()} will be {@link
   * DefaultMIMETypes#DEFAULT_MIME_TYPE} until a specific value is provided or merged from another
   * instance.
   */
  public ClientMetadata() {
    mimeType = null;
  }

  /**
   * Creates an instance with an explicit MIME type.
   *
   * <p>The provided value is interned for memory efficiency when non‑{@code null}. The constructor
   * does not validate the string beyond a {@code null} check.
   *
   * @param mime a MIME type string such as {@code "text/plain"}; may be {@code null} to represent
   *     an unknown type.
   */
  public ClientMetadata(String mime) {
    mimeType = (mime == null) ? null : mime.intern();
  }

  private ClientMetadata(DataInputStream dis) throws MetadataParseException, IOException {
    int magic = dis.readInt();
    if (magic != MAGIC) throw new MetadataParseException("Bad magic value in ClientMetadata");
    short version = dis.readShort();
    if (version != VERSION)
      throw new MetadataParseException("Unrecognised version " + version + " in ClientMetadata");
    boolean hasMIMEType = dis.readBoolean();
    if (hasMIMEType) mimeType = dis.readUTF();
    else mimeType = null;
  }

  /**
   * Reads an instance from a {@link DataInputStream} produced by {@link
   * #writeTo(DataOutputStream)}.
   *
   * <p>This method validates a file‑format magic and a small version number before reading the
   * presence flag and MIME payload. The current format writes a boolean ahead of the string so
   * {@code null} can be round‑tripped without sentinel values.
   *
   * @param dis a stream positioned at the start of a serialized {@code ClientMetadata}; must be
   *     readable for at least the fixed header and any subsequent UTF string bytes.
   * @return a newly constructed metadata object populated from the stream contents.
   * @throws MetadataParseException if the magic number or version is not recognized for this
   *     implementation, indicating the bytes are not a {@code ClientMetadata} instance.
   * @throws IOException if the stream cannot be read fully or contains an incomplete UTF value.
   *     <pre>{@code
   * try (var out = new DataOutputStream(new ByteArrayOutputStream())) {
   *   new ClientMetadata("text/plain").writeTo(out);
   * }
   * }</pre>
   */
  public static ClientMetadata construct(DataInputStream dis)
      throws MetadataParseException, IOException {
    return new ClientMetadata(dis);
  }

  /**
   * Creates a defensive copy of the given metadata instance.
   *
   * <p>Use this when an instance must outlive its current owner or thread. The copy contains the
   * same effective MIME string as {@code src} at the time of copying. The returned object shares no
   * mutable state with {@code src}.
   *
   * @param src the source metadata; pass {@code null} to receive {@code null} for convenience in
   *     conditional flows that propagate optional values.
   * @return a new {@code ClientMetadata} with the same MIME value as {@code src}, or {@code null}
   *     when {@code src} is {@code null}.
   */
  public static ClientMetadata copyOf(ClientMetadata src) {
    if (src == null) return null;
    ClientMetadata copy = new ClientMetadata();
    copy.mimeType = src.mimeType;
    return copy;
  }

  /**
   * Returns the effective document MIME type.
   *
   * <p>If the internal value is {@code null} or empty, this method substitutes the default value
   * {@link DefaultMIMETypes#DEFAULT_MIME_TYPE}. Callers that need to distinguish between
   * “unspecified” and “explicit default” should inspect {@link #isTrivial()} instead of the return
   * value alone.
   *
   * @return a non‑empty MIME string; never {@code null}. When the instance has no explicit value,
   *     returns {@code application/octet-stream} as the default.
   */
  public String getMIMEType() {
    if ((mimeType == null) || mimeType.isEmpty()) return DefaultMIMETypes.DEFAULT_MIME_TYPE;
    return mimeType;
  }

  /**
   * Merges information from another instance without overwriting existing values.
   *
   * <p>When this instance is “trivial” (see {@link #isTrivial()}), its MIME value is updated to the
   * other instance’s value. When non‑trivial, this method leaves the current value unchanged. No
   * fields other than the MIME string are currently tracked.
   *
   * @param clientMetadata the source from which to copy missing information; must not be {@code
   *     null}.
   * @throws NullPointerException if {@code clientMetadata} is {@code null}.
   */
  public void mergeNoOverwrite(ClientMetadata clientMetadata) {
    if ((mimeType == null) || mimeType.isEmpty()) mimeType = clientMetadata.mimeType;
  }

  /**
   * Returns whether the instance carries no explicit MIME type.
   *
   * <p>A trivial instance has a {@code null} or empty internal string. Such instances report the
   * default type via {@link #getMIMEType()} but are considered “unknown” for merging and policy
   * decisions.
   *
   * @return {@code true} when the internal MIME is {@code null} or empty; {@code false} otherwise.
   */
  public boolean isTrivial() {
    return ((mimeType == null) || mimeType.isEmpty());
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return getMIMEType();
  }

  /**
   * Clears the explicit MIME type, if any.
   *
   * <p>After calling this method, {@link #isTrivial()} returns {@code true} and {@link
   * #getMIMEType()} yields the default type.
   */
  public void clear() {
    mimeType = null;
  }

  /**
   * Returns the parameter portion of the MIME string when present.
   *
   * <p>Despite the historical name, this method returns:
   *
   * <ul>
   *   <li>{@code null} when the internal MIME is {@code null}.
   *   <li>The original MIME string when it contains no semicolon.
   *   <li>The substring beginning with the first semicolon (that is, the parameters) when present.
   * </ul>
   *
   * Callers seeking only the media type without parameters should derive it from {@link
   * #getMIMEType()} accordingly.
   *
   * @return either {@code null}, the full MIME string with no parameters, or the leading semicolon
   *     plus parameters when a parameter list exists.
   */
  public String getMIMETypeNoParams() {
    String s = mimeType;
    if (s == null) return null;
    int i = s.indexOf(';');
    if (i > -1) {
      s = s.substring(i);
    }
    return s;
  }

  /**
   * Writes this instance in a compact binary form to a {@link DataOutputStream}.
   *
   * <p>The encoding is:
   *
   * <ol>
   *   <li>{@code int} magic number identifying {@code ClientMetadata}
   *   <li>{@code short} format version
   *   <li>{@code boolean} indicating whether a MIME string follows
   *   <li>{@code UTF} string for the MIME value when present
   * </ol>
   *
   * The result is accepted by {@link #construct(DataInputStream)}. This method does not close the
   * provided stream.
   *
   * @param dos the destination stream that receives the serialized form; must be open and writable
   *     through the lifetime of this call.
   * @throws IOException if the destination reports a write failure.
   */
  public void writeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeShort(VERSION);
    if (mimeType == null) dos.writeBoolean(false);
    else {
      dos.writeBoolean(true);
      dos.writeUTF(mimeType);
    }
  }

  private static final int VERSION = 1;
  private static final int MAGIC = 0x021441fe8;
}
