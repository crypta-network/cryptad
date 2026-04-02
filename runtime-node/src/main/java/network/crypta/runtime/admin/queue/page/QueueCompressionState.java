package network.crypta.runtime.admin.queue.page;

/**
 * Captures the user-visible compression lifecycle for queue-page progress rendering.
 *
 * <p>The legacy queue page does not expose the full FCP compression state machine. It only needs a
 * small status value that explains why an upload progress cell is not yet showing normal block
 * counts. This enum keeps that presentation-oriented state inside the runtime-owned seam so callers
 * can render stable HTML without depending on {@code ClientPut.COMPRESS_STATE}.
 *
 * <p>The values describe what the operator should infer from the queue row at render time. They do
 * not attempt to model every internal insert phase.
 */
public enum QueueCompressionState {
  /** The upload is queued for compression work but has not started compressing yet. */
  WAITING,

  /** The upload is actively compressing data before regular progress counters can advance. */
  COMPRESSING,

  /** The upload is past the compression gate and should render ordinary progress information. */
  WORKING
}
