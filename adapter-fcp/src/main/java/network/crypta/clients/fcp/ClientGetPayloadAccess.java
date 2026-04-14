package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.support.api.Bucket;

/**
 * Read-only payload view and bucket adapter for {@link ClientGet}.
 *
 * <p>This helper pulls the small amount of payload-oriented logic out of {@link ClientGet} so the
 * request class does not need to know how direct-return buckets, disk-return wrappers, and simple
 * payload metadata are exposed to callers. It does not own any durable state beyond a reference to
 * the request. Instead, it interprets the request's current return mode and the state snapshot each
 * time a caller asks for bucket or metadata information.
 *
 * <p>The class also preserves an important distinction in the GET flow: client-facing disk buckets
 * are opened read-only, while persistence and resume code may need a writable wrapper around the
 * same destination path. Serialization-only request instances can have a {@code null} return type,
 * so the bucket-building methods treat that state as "no bucket available" rather than throwing.
 */
final class ClientGetPayloadAccess {
  /** Request whose current return mode and payload state are being exposed. */
  private final ClientGet request;

  /**
   * Creates a payload view for one request.
   *
   * @param request request whose payload-oriented state should be exposed.
   */
  ClientGetPayloadAccess(ClientGet request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  /**
   * Returns whether the request is configured for direct return delivery.
   *
   * @return {@code true} when payload bytes are returned through the direct bucket path.
   */
  boolean isDirect() {
    return request.returnTypeForGetter() == ClientGet.ReturnType.DIRECT;
  }

  /**
   * Returns whether the request is configured for disk return delivery.
   *
   * @return {@code true} when payload bytes are returned to a disk file.
   */
  boolean isToDisk() {
    return request.returnTypeForGetter() == ClientGet.ReturnType.DISK;
  }

  /**
   * Returns the best-known payload size.
   *
   * <p>The request state records the found data length once the runtime has learned it. Until then,
   * this method returns {@code -1} to preserve the existing unknown-size contract.
   *
   * @return payload size in bytes, or {@code -1} when the size is still unknown.
   */
  long getDataSize() {
    if (request.state().getFoundDataLength() > 0) {
      return request.state().getFoundDataLength();
    }
    return -1;
  }

  /**
   * Returns the best-known MIME type recorded on the request state.
   *
   * @return MIME type string, or {@code null} when none is known yet.
   */
  String getMimeType() {
    return request.state().getFoundDataMimeType();
  }

  /**
   * Returns the bucket that should be exposed to ordinary callers.
   *
   * @return direct-return bucket, read-only disk bucket, or {@code null} when the request has no
   *     caller-visible bucket.
   */
  Bucket getBucket() {
    return makeClientBucket();
  }

  /**
   * Builds the caller-facing bucket view for the current request state.
   *
   * <p>Direct-return requests reuse the runtime-populated in-memory bucket under the request lock.
   * Disk-return requests wrap the destination path in a read-only file bucket so callers can
   * inspect the result without gaining write access through this accessor. Requests in
   * serialization-only state or with {@link ClientGet.ReturnType#NONE} simply return {@code null}.
   *
   * @return caller-facing bucket view, or {@code null} when no such bucket exists.
   */
  Bucket makeClientBucket() {
    ClientGet.ReturnType returnType = request.returnTypeForGetter();
    if (returnType == null) {
      return null;
    }
    return switch (returnType) {
      case DIRECT -> {
        synchronized (request.persistenceLock()) {
          yield request.state().getReturnBucketDirect();
        }
      }
      case DISK -> ClientGetGetterFactory.diskBucket(request.getDestFilename(), true);
      default -> null;
    };
  }

  /**
   * Builds the bucket view used by persistence and resume code.
   *
   * <p>This differs from {@link #makeClientBucket()} only for disk-return requests. Persistence
   * must be able to reopen the destination file in writable mode when reconstructing the request
   * state, so the disk wrapper here is not forced to read-only.
   *
   * @return persistence bucket view, or {@code null} when the request has no persisted payload
   *     bucket.
   */
  Bucket makePersistenceBucket() {
    ClientGet.ReturnType returnType = request.returnTypeForGetter();
    if (returnType == null) {
      return null;
    }
    return switch (returnType) {
      case DIRECT -> {
        synchronized (request.persistenceLock()) {
          yield request.state().getReturnBucketDirect();
        }
      }
      case DISK -> ClientGetGetterFactory.diskBucket(request.getDestFilename(), false);
      default -> null;
    };
  }
}
