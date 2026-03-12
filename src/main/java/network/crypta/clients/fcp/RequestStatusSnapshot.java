package network.crypta.clients.fcp;

import java.time.Instant;
import network.crypta.clients.fcp.ClientRequest.Persistence;

/**
 * Parameter bundle describing the core {@link RequestStatus} fields.
 *
 * <p>This snapshot mirrors the inputs required by the {@link RequestStatus} constructor so callers
 * can pass a single value across status implementations. Timestamps are captured as-is and are
 * still defensively cloned by {@link RequestStatus} when applied.
 *
 * @param identifier stable request identifier.
 * @param persistence persistence policy of the request.
 * @param started whether the request has begun.
 * @param finished whether the request is finished.
 * @param success whether the request completed successfully.
 * @param total total number of blocks known so far.
 * @param min minimum required block count.
 * @param fetched number of blocks fetched so far.
 * @param latestSuccess timestamp of the most recent success.
 * @param fatal number of fatal block failures.
 * @param failed number of transient block failures.
 * @param latestFailure timestamp of the most recent failure.
 * @param totalFinalized whether the total block count is final.
 * @param priority scheduler priority class.
 */
public record RequestStatusSnapshot(
    String identifier,
    Persistence persistence,
    boolean started,
    boolean finished,
    boolean success,
    int total,
    int min,
    int fetched,
    Instant latestSuccess,
    int fatal,
    int failed,
    Instant latestFailure,
    boolean totalFinalized,
    short priority) {}
