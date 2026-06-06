package network.crypta.platform.api.appdata;

import java.time.Instant;
import java.util.Objects;

/**
 * Captures one internal app-scoped durable app-data snapshot for update rollback.
 *
 * <p>An update snapshot is a short-lived descriptor around an {@link AppDataExportPayload}. The
 * update lifecycle creates it before a schema-changing bundle is installed, keeps it only while the
 * migration and post-apply checks are in flight, and restores it only for the same app id if the
 * update has to roll back. The type intentionally carries no filesystem location, operator token,
 * command output, or app-data values outside the bounded export payload owned by {@link
 * AppDataService}.
 *
 * <p>The descriptor records the serialized payload size and creation timestamp so callers can make
 * path-free lifecycle decisions and diagnostics. It is not a public backup artifact and does not
 * provide cross-app portability; those concerns belong to a separate user-facing backup contract.
 *
 * @param payload bounded export payload for exactly one normalized app id
 * @param payloadBytes serialized payload size in bytes used for update accounting
 * @param createdAt timestamp captured when the snapshot payload was produced
 * @see AppDataService#createUpdateSnapshot(String)
 * @see AppDataService#restoreUpdateSnapshot(String, AppDataUpdateSnapshot)
 */
public record AppDataUpdateSnapshot(
    AppDataExportPayload payload, int payloadBytes, Instant createdAt) {
  /**
   * Creates an internal update snapshot descriptor.
   *
   * <p>The payload carries bounded app-owned durable data for exactly one app. The descriptor keeps
   * only size and timestamp metadata for update lifecycle accounting; it is not exposed through
   * app-facing backup routes.
   *
   * @param payload bounded app-data export payload with a non-null app owner
   * @param payloadBytes serialized payload size in bytes, never less than zero
   * @param createdAt snapshot creation timestamp used for rollback diagnostics
   */
  public AppDataUpdateSnapshot {
    Objects.requireNonNull(payload, "payload");
    if (payload.appId() == null) {
      throw new IllegalArgumentException("snapshot payload must declare an app id");
    }
    if (payloadBytes < 0) {
      throw new IllegalArgumentException("payloadBytes must be >= 0");
    }
    Objects.requireNonNull(createdAt, "createdAt");
  }

  /**
   * Returns the app id owned by this snapshot.
   *
   * <p>The value comes from the embedded export payload and is the authority boundary for restore
   * operations. Callers use it to reject accidental or malicious cross-app restores before durable
   * data is replaced.
   *
   * @return normalized owner app id associated with the snapshot payload
   */
  public String appId() {
    return payload.appId();
  }
}
