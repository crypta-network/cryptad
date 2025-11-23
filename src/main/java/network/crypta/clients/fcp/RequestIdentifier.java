package network.crypta.clients.fcp;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

/**
 * Immutable handle that uniquely identifies a client request in the FCP bridge and carries enough
 * metadata to serialize the identity across process or JVM boundaries. The identifier is used
 * primarily to detect already-loaded requests and to restart requests when regular serialization
 * fails, so the on-wire layout must remain backward compatible.
 *
 * <p>Instances record whether a request belongs to the node-global queue or a specific client, the
 * user-facing client name when applicable, the stable request identifier string, and the {@link
 * RequestType}. All fields are final. The class is immutable, thread-safe, and performs no I/O
 * outside {@link #writeTo(DataOutput)}.
 *
 * <ul>
 *   <li>Serialization format: magic int {@link #MAGIC}, version {@link #VERSION}, queue flag,
 *       optional client name, identifier string, and request-type ordinal.
 *   <li>Equality includes {@link RequestType}; {@link #sameIdentifier(RequestIdentifier)} ignores
 *       it for deduplication.
 *   <li>Layout changes require a version bump to stay compatible.
 * </ul>
 *
 * @see RequestType
 * @see #writeTo(DataOutput)
 */
public final class RequestIdentifier {

  /**
   * Request category conveyed alongside the identifier to describe how the node should interpret
   * the stored request metadata.
   */
  public enum RequestType {
    /**
     * Fetch operation that retrieves existing network content identified by keys such as CHK or
     * SSK; ordinal position is part of the serialized form.
     */
    GET,
    /**
     * Insertion of a single data item (for example, a file or message) into the network; serialized
     * using the enum ordinal and therefore order must remain stable.
     */
    PUT,
    /**
     * Insertion of a directory or bundle where the identifier refers to a manifest rather than a
     * single block; ordinal stability is required for deserialization.
     */
    PUTDIR
  }

  static final int MAGIC = 0x25ebd38d;
  static final short VERSION = 1;

  final boolean globalQueue;
  final String clientName;
  final String identifier;

  /**
   * Type of request represented by this identifier; immutable and included in {@link
   * #equals(Object)} but not in {@link #sameIdentifier(RequestIdentifier)}. Always non-null after
   * construction.
   */
  public final RequestType type;

  /**
   * Creates a new identifier from discrete components for immediate in-memory use or later
   * serialization. When {@code globalQueue} is {@code true}, {@code clientName} is ignored and may
   * be {@code null}; otherwise {@code clientName} should hold the human-readable name used by the
   * originating client.
   *
   * @param globalQueue true for the node-global queue; otherwise the client queue is used.
   * @param clientName readable client name when {@code globalQueue} is false; non-null then.
   * @param identifier stable string that uniquely identifies the request within its queue.
   * @param type {@link RequestType} describing how the node should process the request; non-null.
   */
  public RequestIdentifier(
      boolean globalQueue, String clientName, String identifier, RequestType type) {
    this.globalQueue = globalQueue;
    this.clientName = clientName;
    this.identifier = identifier;
    this.type = type;
  }

  /**
   * Reconstructs an identifier by consuming its serialized form from a {@link DataInput} stream.
   * The method expects the exact layout produced by {@link #writeTo(DataOutput)}: magic integer,
   * version short, queue flag, optional UTF client name, UTF identifier, and request-type ordinal.
   *
   * @param dis data source positioned at the start of the serialized identifier.
   * @throws IOException if the magic or version differ, type is invalid, or input fails.
   */
  public RequestIdentifier(DataInput dis) throws IOException {
    int magic = dis.readInt();
    if (magic != MAGIC) throw new IOException("Bad magic");
    short version = dis.readShort();
    if (version != VERSION) throw new IOException("Bad version");
    this.globalQueue = dis.readBoolean();
    if (globalQueue) clientName = null;
    else clientName = dis.readUTF();
    identifier = dis.readUTF();
    RequestType[] types = RequestType.values();
    short typeKey = dis.readShort();
    if (typeKey < 0 || typeKey >= types.length) throw new IOException("Bogus type");
    type = types[typeKey];
  }

  /**
   * Serializes this identifier to a {@link DataOutput} using the stable wire format expected by the
   * corresponding {@link #RequestIdentifier(DataInput)} constructor. Callers should treat the
   * output as versioned binary metadata suitable for persistence or interprocess transfer.
   *
   * @param dos destination output that receives all fields in the documented order.
   * @throws IOException if the output stream cannot write any portion of the record.
   */
  public void writeTo(DataOutput dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeShort(VERSION);
    dos.writeBoolean(globalQueue);
    if (!globalQueue) dos.writeUTF(clientName);
    dos.writeUTF(identifier);
    dos.writeShort(type.ordinal());
  }

  /**
   * Determines whether another identifier represents the same queued request while deliberately
   * ignoring {@link #type}. Use this when de-duplicating enqueue attempts that should coalesce
   * based on queue scope, client name, and stable identifier string.
   *
   * @param other candidate identifier compared by queue flag, client name, and identifier string.
   * @return {@code true} when queue scope and identifier match, even if request types differ.
   */
  public boolean sameIdentifier(RequestIdentifier other) {
    if (globalQueue != other.globalQueue) return false;
    if (!globalQueue && !clientName.equals(other.clientName)) return false;
    return identifier.equals(other.identifier);
  }

  /** Hash code aligned with {@link #equals(Object)}; omits {@link #type} by design. */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((clientName == null) ? 0 : clientName.hashCode());
    result = prime * result + (globalQueue ? 1231 : 1237);
    result = prime * result + ((identifier == null) ? 0 : identifier.hashCode());
    // Intentionally don't include the type at all.
    return result;
  }

  /**
   * Compares identifiers for full equality, including queue scope, client name (when applicable),
   * base identifier string, and {@link #type}. Suitable for maps and sets that must distinguish
   * between different request categories.
   *
   * @param obj other object, expected to be another {@code RequestIdentifier}.
   * @return {@code true} when all significant fields match; {@code false} otherwise.
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (!(obj instanceof RequestIdentifier other)) return false;
    if (globalQueue != other.globalQueue) return false;
    if (!globalQueue && !clientName.equals(other.clientName)) return false;
    if (!identifier.equals(other.identifier)) return false;
    return type == other.type;
  }
}
