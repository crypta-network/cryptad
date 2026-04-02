package network.crypta.clients.http;

import network.crypta.runtime.admin.queue.page.QueueCompressionState;

/**
 * Bundles rendering flags needed for queue progress cells.
 *
 * <p>The context captures the request state that is orthogonal to the numeric progress counters,
 * such as whether the queue is in advanced mode, whether the request has started, the current
 * compression state, and whether the request represents an upload. Combined with a {@link
 * network.crypta.client.events.SplitfileProgressCounts} snapshot, this provides all information
 * needed to render progress cells consistently across queue and admin UIs.
 *
 * @param advancedMode {@code true} to render detailed block counts
 * @param started {@code true} once the transfer has started
 * @param compressing current compression state for the request
 * @param upload {@code true} when rendering an upload progress cell
 */
public record ProgressCellContext(
    boolean advancedMode, boolean started, QueueCompressionState compressing, boolean upload) {}
