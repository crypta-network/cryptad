package network.crypta.clients.http;

/**
 * Captures the shared metadata for a single FProxy fetch snapshot.
 *
 * <p>The snapshot info records timing, network, and MIME metadata captured when a snapshot is
 * created. It intentionally excludes block counts and payload data so it can be reused for both
 * completed and in-progress fetch results.
 *
 * @param mimeType MIME type recorded for the snapshot; may be null if unknown
 * @param timeStarted epoch milliseconds when the fetch started
 * @param goneToNetwork whether the fetch hit the network
 * @param eta estimated remaining time in milliseconds at snapshot creation
 * @param hasWaited whether the caller was forced to wait before receiving the snapshot
 */
public record FProxyFetchSnapshotInfo(
    String mimeType, long timeStarted, boolean goneToNetwork, long eta, boolean hasWaited) {}
