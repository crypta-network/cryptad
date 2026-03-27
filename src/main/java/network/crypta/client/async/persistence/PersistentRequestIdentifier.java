package network.crypta.client.async.persistence;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

/**
 * Immutable identifier for a durable client request.
 *
 * <p>This value object records the minimum identity needed to find, deduplicate, and restart a
 * durable request. It captures queue scope, client ownership for non-global queues, a stable
 * request identifier string, and the request category that restart logic should apply. Instances
 * are immutable and safe to retain across checkpoint, load, and adapter boundaries.
 *
 * <p>The binary layout intentionally matches the legacy FCP {@code RequestIdentifier} format so
 * existing persistence files remain byte-compatible. Equality includes the request type because the
 * persisted record does, while {@link #sameIdentifier(PersistentRequestIdentifier)} compares only
 * queue scope, client name, and stable identifier string for duplicate detection during startup.
 */
public final class PersistentRequestIdentifier {

  /**
   * Stable request categories embedded in the persistence-file identifier record.
   *
   * <p>The short code assigned to each constant is part of the durable on-disk format and therefore
   * must remain stable across refactoring.
   */
  public enum RequestType {
    /** Durable fetch request that resumes or restarts download-oriented logic. */
    GET((short) 0),
    /** Durable single-item insert request that restarts upload-oriented logic. */
    PUT((short) 1),
    /** Durable directory insert request that restarts manifest-oriented upload logic. */
    PUTDIR((short) 2);

    private final short code;

    RequestType(short code) {
      this.code = code;
    }

    short code() {
      return code;
    }

    private static RequestType fromCode(short code) throws IOException {
      for (RequestType type : values()) {
        if (type.code == code) {
          return type;
        }
      }
      throw new IOException("Bogus type");
    }
  }

  static final int MAGIC = 0x25ebd38d;
  static final short VERSION = 1;

  private final boolean globalQueue;
  private final String clientName;
  private final String identifier;
  private final RequestType type;

  /**
   * Creates an identifier from explicit queue, client, and request-type components.
   *
   * <p>Callers typically use this constructor when adapting an endpoint-owned request identifier
   * into the client-owned persistence seam. For global queues, {@code clientName} is ignored and
   * may be {@code null}. For named queues, callers should pass the stable client name that the
   * runtime uses to locate the owning durable request set.
   *
   * @param globalQueue {@code true} when the request belongs to the node-global durable queue
   * @param clientName stable client name for non-global queues; ignored for global queues
   * @param identifier stable request identifier within the selected queue
   * @param type durable request category used during restart and equality checks
   */
  public PersistentRequestIdentifier(
      boolean globalQueue, String clientName, String identifier, RequestType type) {
    this.globalQueue = globalQueue;
    this.clientName = clientName;
    this.identifier = identifier;
    this.type = type;
  }

  /**
   * Reconstructs an identifier from its byte-compatible on-disk form.
   *
   * <p>The input must be positioned at the start of an identifier record written by {@link
   * #writeTo(DataOutput)} or by the legacy FCP identifier codec. The constructor validates the
   * magic, version, queue layout, and request-type code before exposing the decoded value.
   *
   * @param input data source positioned at the start of the identifier record
   * @throws IOException if the record is truncated, malformed, or uses an unknown format version
   */
  public PersistentRequestIdentifier(DataInput input) throws IOException {
    int magic = input.readInt();
    if (magic != MAGIC) {
      throw new IOException("Bad magic");
    }
    short version = input.readShort();
    if (version != VERSION) {
      throw new IOException("Bad version");
    }
    globalQueue = input.readBoolean();
    clientName = globalQueue ? null : input.readUTF();
    identifier = input.readUTF();
    type = RequestType.fromCode(input.readShort());
  }

  /**
   * Writes this identifier using the stable persistence-file layout.
   *
   * <p>The encoded form is intentionally byte-compatible with the legacy FCP identifier layout, so
   * existing persistence files can still be read during incremental decoupling work. Callers should
   * treat the output as versioned binary metadata rather than a general-purpose serialization
   * format.
   *
   * @param output destination that receives the encoded identifier record
   * @throws IOException if the identifier cannot be written to the destination
   */
  public void writeTo(DataOutput output) throws IOException {
    output.writeInt(MAGIC);
    output.writeShort(VERSION);
    output.writeBoolean(globalQueue);
    if (!globalQueue) {
      output.writeUTF(clientName);
    }
    output.writeUTF(identifier);
    output.writeShort(type.code());
  }

  /**
   * Returns whether another identifier targets the same queued request, ignoring the request type.
   *
   * <p>This comparison is used for duplicate detection during startup replay. It deliberately
   * ignores the request type because the runtime's existing duplicate semantics are based on queue
   * ownership and stable identifier string rather than on the specific restart codec.
   *
   * @param other candidate identifier to compare against this identifier
   * @return {@code true} when queue scope, client, and stable identifier string all match
   */
  public boolean sameIdentifier(PersistentRequestIdentifier other) {
    if (globalQueue != other.globalQueue) {
      return false;
    }
    if (!globalQueue && !clientName.equals(other.clientName)) {
      return false;
    }
    return identifier.equals(other.identifier);
  }

  /**
   * Returns whether the identifier belongs to the global queue.
   *
   * @return {@code true} when this identifier targets the node-global durable queue
   */
  public boolean isGlobalQueue() {
    return globalQueue;
  }

  /**
   * Returns the client name for non-global queues.
   *
   * @return stable non-global client name, or {@code null} when this identifier is global
   */
  public String clientName() {
    return clientName;
  }

  /**
   * Returns the stable request identifier string.
   *
   * @return stable queue-local identifier string used for lookup and duplicate detection
   */
  public String identifier() {
    return identifier;
  }

  /**
   * Returns the request type stored with the identifier.
   *
   * @return durable request category that restart logic should apply to this request
   */
  public RequestType type() {
    return type;
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((clientName == null) ? 0 : clientName.hashCode());
    result = prime * result + (globalQueue ? 1231 : 1237);
    result = prime * result + ((identifier == null) ? 0 : identifier.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof PersistentRequestIdentifier other)) {
      return false;
    }
    if (globalQueue != other.globalQueue) {
      return false;
    }
    if (!globalQueue && !clientName.equals(other.clientName)) {
      return false;
    }
    if (!identifier.equals(other.identifier)) {
      return false;
    }
    return type == other.type;
  }
}
