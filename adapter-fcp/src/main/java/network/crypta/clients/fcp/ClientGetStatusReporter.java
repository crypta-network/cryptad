package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.client.FetchException.FetchExceptionMode;

/**
 * Builds status and failure summaries for {@link ClientGet} without bloating the request class.
 *
 * <p>The reporter reads a cached request state to produce UI-friendly status snapshots, progress
 * metrics, and failure summaries. It is read-only: callers are expected to synchronize on the
 * owning request lock before invoking these methods so that snapshots are consistent with the
 * latest lifecycle updates.
 *
 * <p>The helper keeps status construction logic separate from request orchestration. This makes it
 * easier to evolve the status model without increasing the dependency footprint of {@link
 * ClientGet} itself.
 *
 * <ul>
 *   <li><strong>Failure summaries</strong>: converts failure metadata into user-facing text.
 *   <li><strong>Progress metrics</strong>: exposes block counts and completion percentages.
 *   <li><strong>Status snapshots</strong>: assembles {@link RequestStatus} for UIs and caches.
 * </ul>
 *
 * @see ClientGet
 * @see RequestStatus
 */
final class ClientGetStatusReporter {
  /** The owning request whose cached state is read to build status views. */
  private final ClientGet request;

  /**
   * Creates a reporter bound to a specific {@link ClientGet} instance.
   *
   * <p>The reporter does not capture mutable snapshots at construction time; it only stores the
   * request reference and reads state lazily during each call.
   *
   * @param request owning request to read for status and progress data.
   */
  ClientGetStatusReporter(ClientGet request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  /**
   * Returns a human-readable summary of the most recent failure, if any.
   *
   * <p>The summary is derived from {@link GetFailedMessage} metadata and optionally includes the
   * extended description when {@code longDescription} is {@code true}. If no failure has been
   * recorded, the method returns {@code null}.
   *
   * @param longDescription true to append extended diagnostic detail when available.
   * @return failure summary string, or {@code null} when no failure exists.
   */
  String getFailureReason(boolean longDescription) {
    GetFailedMessage failure = request.state().getFailedMessage();
    if (failure == null) return null;
    String summary = failure.getShortFailedMessage();
    if (longDescription && failure.extraDescription != null) {
      summary += ": " + failure.extraDescription;
    }
    return summary;
  }

  /**
   * Returns the failure classification associated with the last-recorded failure.
   *
   * <p>The classification is derived from the cached {@link GetFailedMessage}. It returns {@code
   * null} when no failure is recorded yet.
   *
   * @return failure classification mode, or {@code null} when no failure exists.
   */
  FetchExceptionMode getFailureReasonCode() {
    GetFailedMessage failure = request.state().getFailedMessage();
    if (failure == null) return null;
    return failure.failureMode;
  }

  /**
   * Reports whether the total block count has been finalized for progress reporting.
   *
   * <p>A {@code true} result indicates either a completed successful request or progress snapshot
   * that has finalized totals. This value is intended for UI percentage calculations.
   *
   * @return {@code true} when the total block count is finalized.
   */
  boolean isTotalFinalized() {
    ClientGetState state = request.state();
    if (request.finished && state.hasSucceeded()) return true;
    SimpleProgressMessage progress = state.getProgressPending();
    if (progress == null) return false;
    return progress.isTotalFinalized();
  }

  /**
   * Returns the current success fraction from the latest progress snapshot.
   *
   * @return fraction in the range {@code 0.0} to {@code 1.0}, or {@code -1} when unknown.
   */
  double getSuccessFraction() {
    SimpleProgressMessage progress = request.state().getProgressPending();
    if (progress != null) {
      return progress.getFraction();
    }
    return -1;
  }

  /**
   * Returns the total block count from the latest progress snapshot.
   *
   * @return total block count, or {@code 1} when unknown.
   */
  double getTotalBlocks() {
    SimpleProgressMessage progress = request.state().getProgressPending();
    if (progress != null) {
      return progress.getTotalBlocks();
    }
    return 1;
  }

  /**
   * Returns the minimum block count required for decoding from the latest snapshot.
   *
   * @return minimum required block count, or {@code 1} when unknown.
   */
  double getMinBlocks() {
    SimpleProgressMessage progress = request.state().getProgressPending();
    if (progress != null) {
      return progress.getMinBlocks();
    }
    return 1;
  }

  /**
   * Returns the non-fatal failed block count from the latest snapshot.
   *
   * @return non-fatal failed block count, or {@code 0} when unknown.
   */
  double getFailedBlocks() {
    SimpleProgressMessage progress = request.state().getProgressPending();
    if (progress != null) {
      return progress.getFailedBlocks();
    }
    return 0;
  }

  /**
   * Returns the fatal failed block count from the latest snapshot.
   *
   * @return fatal failed block count, or {@code 0} when unknown.
   */
  double getFatalyFailedBlocks() {
    SimpleProgressMessage progress = request.state().getProgressPending();
    if (progress != null) {
      return progress.getFatalyFailedBlocks();
    }
    return 0;
  }

  /**
   * Returns the fetched block count from the latest snapshot.
   *
   * @return fetched block count, or {@code 0} when unknown.
   */
  double getFetchedBlocks() {
    SimpleProgressMessage progress = request.state().getProgressPending();
    if (progress != null) {
      return progress.getFetchedBlocks();
    }
    return 0;
  }

  /**
   * Builds a composite {@link RequestStatus} snapshot for UI and cache consumers.
   *
   * <p>The snapshot includes request lifecycle state, progress metrics, payload metadata, and
   * context information such as compatibility modes. The method does not mutate the request and
   * should be called under the request lock to ensure consistent reads.
   *
   * @return fully populated {@link RequestStatus} snapshot for the current request state.
   */
  RequestStatus getStatus() {
    ClientGetState state = request.state();
    RequestStatusSnapshot statusSnapshot =
        ClientGetStatusSnapshot.buildRequestStatusSnapshot(
            request.identifier,
            request.persistence,
            request.started,
            request.finished,
            state.hasSucceeded(),
            state.getProgressPending(),
            request.priorityClass);
    DownloadProgressSnapshot progressSnapshot =
        new DownloadProgressSnapshot(state.getProgressPending(), state.getFailedMessage());
    DownloadDataSnapshot dataSnapshot =
        new DownloadDataSnapshot(
            state.getFoundDataMimeType(),
            state.getFoundDataLength(),
            request.getDestFilename(),
            request.getBucket());
    DownloadContextSnapshot contextSnapshot =
        new DownloadContextSnapshot(
            request.fetchConfig(),
            request.getCompatibilityMode(),
            request.getOverriddenSplitfileCryptoKey(),
            request.getURI(),
            request.getDontCompress());
    return ClientGetGetterFactory.buildStatus(
        new ClientGetStatusSnapshot(
            statusSnapshot, progressSnapshot, dataSnapshot, contextSnapshot));
  }
}
