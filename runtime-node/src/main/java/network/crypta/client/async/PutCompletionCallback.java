package network.crypta.client.async;

import network.crypta.client.InsertException;
import network.crypta.client.Metadata;
import network.crypta.keys.BaseClientKey;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;

/**
 * Callback interface for observing the life cycle of a client "put" (insert) operation.
 *
 * <p>Implementations receive notifications as an insert progresses through encoding, metadata
 * handling, block scheduling, partial fetchability, final success, and failure. The events are
 * delivered by the active {@link ClientPutState} instance and carry the surrounding {@link
 * ClientContext} so listeners can make decisions using project-wide schedulers and persistence
 * policies. Typical usages include updating UI, recording progress, emitting FCP notifications, or
 * chaining follow-up work when a URI is known.
 *
 * <p>Unless documented otherwise, callbacks are invoked at most once per event type for a given
 * state and are non-blocking from the caller’s perspective; long-running work should be offloaded
 * to appropriate executors from the provided context. Implementations should be resilient to
 * restarts when handling persistent requests: after a node restart, {@link
 * #onResume(ClientContext)} is invoked to allow re-scheduling. Ordering reflects the internal state
 * machine and may vary for different insert strategies (single file vs. splitfile).
 *
 * <ul>
 *   <li>Success/failure: {@link #onSuccess(ClientPutState, ClientContext)}, {@link
 *       #onFailure(InsertException, ClientPutState, ClientContext)}
 *   <li>URI known: {@link #onEncode(BaseClientKey, ClientPutState, ClientContext)}
 *   <li>Metadata: {@link #onMetadata(Metadata, ClientPutState, ClientContext)} or {@link
 *       #onMetadata(Bucket, ClientPutState, ClientContext)}
 *   <li>Progress: {@link #onFetchable(ClientPutState)}, {@link #onBlockSetFinished(ClientPutState,
 *       ClientContext)}, {@link #onTransition(ClientPutState, ClientPutState, ClientContext)}
 * </ul>
 *
 * @see ClientPutState
 * @see ClientContext
 * @see Metadata
 * @see Bucket
 */
public interface PutCompletionCallback {

  /**
   * Report that the associated put state completed successfully.
   *
   * <p>This event indicates that the insert finished without error according to the semantics of
   * the underlying state (for example, all required blocks are acknowledged and any optional
   * metadata handling is complete). Implementations typically notify higher layers, persist output
   * details, or release resources that were tied to the insert. The callback should return quickly;
   * expensive processing can be delegated to executors obtained from the {@code context}.
   *
   * @param state the originating {@link ClientPutState} reporting success; never {@code null}; may
   *     contain final metrics, progress indicators, or derived keys.
   * @param context operational context offering schedulers and persistence options; used for
   *     follow-up actions triggered by success; never {@code null}.
   */
  void onSuccess(ClientPutState state, ClientContext context);

  /**
   * Report that the put operation failed with an error.
   *
   * <p>The failure is represented by an {@link InsertException}, which may include specific error
   * categories and diagnostic information. Implementations may log, surface user-visible errors, or
   * decide on retry strategies depending on the exception type and the {@code state}. The callback
   * must not throw in a way that destabilizes the caller; offload heavy handling to background
   * executors if necessary.
   *
   * @param e the cause of the failure; contains details about the insert error; never {@code null}.
   * @param state the {@link ClientPutState} that encountered the failure; can be queried for
   *     partial progress or context; never {@code null}.
   * @param context the {@link ClientContext} available to schedule retries or cleanups; never
   *     {@code null}.
   */
  void onFailure(InsertException e, ClientPutState state, ClientContext context);

  /**
   * Notify that the final URI/key is known for the put state.
   *
   * <p>When the encoder derives the definitive client key or URI for the inserted content, this
   * callback communicates it promptly, often before the entire data set has been transmitted. The
   * event allows higher layers to publish the reference (e.g., via FCP) or update UI, while the
   * insert continues in the background. Delivery precedes or accompanies later success/fetchable
   * notifications depending on insert strategy.
   *
   * @param usk the final client key representing the inserted content; the concrete type may denote
   *     CHK/SSK/USK-style addressing; never {@code null}.
   * @param state the current {@link ClientPutState} that produced the key; never {@code null}.
   * @param context the operational {@link ClientContext} for any follow-up tasks or notifications;
   *     never {@code null}.
   */
  void onEncode(BaseClientKey usk, ClientPutState state, ClientContext context);

  /**
   * Report a state transition within the insert state machine.
   *
   * <p>The callback receives both the prior and next {@link ClientPutState} instances (or
   * representations of state) to enable progress tracking and fine-grained logging. Ordering and
   * specific states depend on the insert implementation; consumers should avoid making assumptions
   * beyond monotonic progression and instead use this for diagnostics or metrics.
   *
   * @param oldState the previous state before the transition; valid only for contextual
   *     information; never {@code null}.
   * @param newState the state entered after the transition; may expose new capabilities; never
   *     {@code null}.
   * @param context the {@link ClientContext} in effect when the transition was observed; never
   *     {@code null}.
   */
  void onTransition(ClientPutState oldState, ClientPutState newState, ClientContext context);

  /**
   * Deliver parsed metadata for the content when explicitly requested.
   *
   * <p>This variant provides a structured {@link Metadata} object. It is only invoked when the
   * caller requested metadata delivery and when metadata exists; many inserts do not store metadata
   * in the network. Implementations might attach metadata to a result record or present it to
   * users. The presence of this callback does not imply that the metadata itself was inserted.
   *
   * @param m the parsed metadata model describing the content; never {@code null} when invoked.
   * @param state the {@link ClientPutState} that produced the metadata; useful for correlating with
   *     progress or keys; never {@code null}.
   * @param context the operational {@link ClientContext} to schedule further processing; never
   *     {@code null}.
   */
  void onMetadata(Metadata m, ClientPutState state, ClientContext context);

  /**
   * Deliver raw metadata bytes via a {@link Bucket} when a size threshold or policy chooses this
   * form.
   *
   * <p>Lower-level inserters (such as splitfile-based implementations) may prefer to pass metadata
   * as a bucket rather than a parsed model. Higher levels either forward this data or call {@link
   * #onEncode(BaseClientKey, ClientPutState, ClientContext)} instead. The callee is responsible for
   * freeing the supplied bucket when done to avoid resource leaks.
   *
   * @param meta the {@link Bucket} containing raw metadata; the callee must free it after
   *     consumption; never {@code null} when invoked.
   * @param state the {@link ClientPutState} associated with the metadata; never {@code null}.
   * @param context the {@link ClientContext} for any asynchronous processing or cleanup; never
   *     {@code null}.
   */
  void onMetadata(Bucket meta, ClientPutState state, ClientContext context);

  /**
   * Indicate that enough data has been inserted to fetch the content successfully.
   *
   * <p>This mid-flight notification applies primarily to splitfiles where redundancy allows early
   * retrieval before all blocks are uploaded. If a full {@link #onSuccess(ClientPutState,
   * ClientContext)} arrives first, listeners should not expect this event. Consumers may start
   * dependent tasks that only require fetchability.
   *
   * @param state the {@link ClientPutState} reporting fetchability; contains progress state needed
   *     to confirm readiness; never {@code null}.
   */
  void onFetchable(ClientPutState state);

  /**
   * Notify that the set of blocks required for the insert has been fully determined.
   *
   * <p>At this point the inserter has discovered all blocks it intends to publish for the current
   * strategy. Implementations can snapshot metrics, update progress UIs, or allocate resources
   * based on the final block count. The insert may still be ongoing; this is a planning milestone
   * rather than completion.
   *
   * @param state the {@link ClientPutState} whose block set is finalized; never {@code null}.
   * @param context the {@link ClientContext} for any follow-on work tied to this milestone; never
   *     {@code null}.
   */
  void onBlockSetFinished(ClientPutState state, ClientContext context);

  /**
   * Resume handling for a persistent insert after a node restart.
   *
   * <p>This callback is invoked during recovery of a previously persistent request so the
   * implementation can re-schedule work, restore observers, and continue progress reporting. The
   * method should be idempotent; callers may attempt resume more than once while rebuilding state.
   *
   * @param context the {@link ClientContext} to use for re-scheduling and resource acquisition;
   *     never {@code null}.
   * @throws InsertException when resubmitting or validating the insert fails due to user-visible
   *     conditions, such as configuration mismatches or input unavailability.
   * @throws ResumeFailedException when the runtime cannot safely resume the request (for example
   *     due to incompatible on-disk state); callers may surface guidance or offer manual recovery.
   */
  void onResume(ClientContext context) throws InsertException, ResumeFailedException;
}
