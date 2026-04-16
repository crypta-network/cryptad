package network.crypta.clients.fcp;

import java.io.DataInputStream;
import network.crypta.client.async.persistence.PersistentRequestRuntimeContext;
import network.crypta.crypt.ChecksumChecker;

/**
 * Bundles the restore-only inputs needed to rebuild a persistent {@link ClientGet}.
 *
 * <p>{@link ClientGet} needs these collaborators only during the narrow replay window where it
 * reconstructs itself from the on-disk client-detail payload. Grouping them into one package-local
 * record keeps the persistence codec in charge of restore orchestration, narrows the request's
 * constructor surface, and avoids leaking stream-oriented concerns onto the normal GET creation
 * path. The record also makes the restore call site easier to audit because the stream, checksum,
 * runtime seam, and request identity travel together instead of being rethreaded through a long
 * positional parameter list.
 *
 * <p>The bundle is deliberately short-lived and immutable. Callers create it immediately before
 * invoking the restore constructor, use it once while replaying the serialized payload, and then
 * discard it. It is not itself part of the persisted request state and does not own any cleanup;
 * stream lifetime and restored object lifetime remain the caller's responsibility.
 *
 * @param input stream already positioned at the serialized client-detail payload for the request;
 *     callers are responsible for the stream lifecycle before and after replay
 * @param requestIdentifier stable identifier tuple describing the restored request owner, queue
 *     scope, and request type used during replay bookkeeping
 * @param fetchRuntimeSupport live fetch runtime bridge used to rebuild getter execution state and
 *     restore persisted buckets or fetch configuration fragments
 * @param runtimeContext detached runtime context used when restoring persistent ownership and other
 *     restart-only request infrastructure
 * @param checker checksum helper used to validate embedded bucket payloads and other protected
 *     segments while the serialized request is replayed
 */
record ClientGetRestoreInput(
    DataInputStream input,
    RequestIdentifier requestIdentifier,
    FcpFetchRuntimeSupport fetchRuntimeSupport,
    PersistentRequestRuntimeContext runtimeContext,
    ChecksumChecker checker) {}
