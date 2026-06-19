package network.crypta.platform.api.consent;

import java.time.Instant;
import java.util.Objects;

/**
 * Process-local consent request bound to one immutable preview snapshot.
 *
 * <p>A request is created when a host/operator client asks for an installation, update, app-data
 * migration, or app-service grant preview. The request id is returned with the preview and must be
 * supplied with the snapshot digest when a later mutation consumes an approval. Requests are not
 * durable across process restarts and do not grant authority by themselves; they are the lookup key
 * used to compare the operator decision with the exact snapshot that was reviewed.
 *
 * <p>Instances are immutable and safe to keep in the in-memory request cache. Expiry and single-use
 * consumption are enforced by {@link ConsentService}, not by this record.
 *
 * @param requestId stable opaque request id returned to the local client
 * @param snapshot immutable preview contents reviewed by the operator
 * @param createdAt time when the request entered the process-local cache
 * @see ConsentDecision
 */
public record ConsentRequest(String requestId, ConsentSnapshot snapshot, Instant createdAt) {
  /**
   * Creates a normalized request record.
   *
   * <p>The request id is trimmed and must remain non-blank. The snapshot and creation timestamp are
   * required because pruning, stale-checking, and decision matching depend on both values.
   *
   * @throws IllegalArgumentException when {@code requestId} is blank
   * @throws NullPointerException when {@code requestId}, {@code snapshot}, or {@code createdAt} is
   *     null
   */
  public ConsentRequest {
    requestId = requireRequestId(requestId);
    Objects.requireNonNull(snapshot, "snapshot");
    Objects.requireNonNull(createdAt, "createdAt");
  }

  private static String requireRequestId(String value) {
    String text = Objects.requireNonNull(value, "requestId").trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException("requestId must not be blank");
    }
    return text;
  }
}
