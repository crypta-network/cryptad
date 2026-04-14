package network.crypta.clients.fcp;

import java.util.Objects;
import network.crypta.client.FetchException;
import network.crypta.keys.FreenetURI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates restart eligibility and redirect handling for {@link ClientGet}.
 *
 * <p>The coordinator encapsulates the restart state machine for GET requests: it checks restart
 * eligibility, clears failure metadata, applies redirect updates, and notifies cache listeners. It
 * does not start or stop the underlying live execution directly; instead, it delegates to the
 * execution handle and then updates the request's bookkeeping fields to reflect the new attempt.
 *
 * <p>The class is intentionally thin and relies on the {@link ClientGet} request lock to guard
 * state changes. Callers should treat the coordinator as request-scoped and not reuse it across
 * different requests.
 *
 * <ul>
 *   <li><strong>Eligibility</strong>: validates finished state and execution restart capability.
 *   <li><strong>State reset</strong>: clears cached failures, progress, and compatibility hints.
 *   <li><strong>Redirects</strong>: applies permanent redirect URIs when available.
 * </ul>
 *
 * @see ClientGet
 * @see ClientGetExecution
 */
final class ClientGetRestartCoordinator {
  /** Logger for restart eligibility and flow diagnostics. */
  private static final Logger LOG = LoggerFactory.getLogger(ClientGetRestartCoordinator.class);

  /** The owning request whose lifecycle state is mutated by this coordinator. */
  private final ClientGet request;

  /**
   * Creates a coordinator bound to a single {@link ClientGet} instance.
   *
   * <p>The coordinator assumes ownership of no resources and performs no side effects during
   * construction. The provided request is stored and used for all state changes and cache
   * notifications.
   *
   * @param request owning request; must be non-null.
   */
  ClientGetRestartCoordinator(ClientGet request) {
    this.request = Objects.requireNonNull(request, "request");
  }

  /**
   * Determines whether the request can be restarted at this time.
   *
   * <p>A request is restartable only after it has finished, has not succeeded, and the underlying
   * execution reports that it supports restart semantics. The method is side-effect-free and logs
   * the reason for non-restartability at debug level.
   *
   * @return {@code true} when the request is finished, failed, and restartable.
   */
  boolean canRestart() {
    if (!request.finished) {
      LOG.debug("Cannot restart because not finished for {}", request.identifier);
      return false;
    }
    if (request.state().hasSucceeded()) {
      LOG.debug("Cannot restart because succeeded for {}", request.identifier);
      return false;
    }
    return request.execution().canRestart();
  }

  /**
   * Attempts to restart the request and update cached state for a new attempt.
   *
   * <p>The method clears failure metadata, optionally disables filtering for the next run, and
   * delegates the restart to the underlying live execution. If a permanent redirect is stored in
   * the failure message, it is applied before restart, so the new attempt uses the redirected URI.
   * Any restart failure is routed through {@link ClientGet#onFailure(FetchException)} to keep error
   * handling consistent with normal fetch errors.
   *
   * @param disableFilterData true to disable filtering for the next attempt.
   * @return {@code true} when the restart is accepted and scheduled by the execution.
   */
  boolean restart(boolean disableFilterData) {
    if (!canRestart()) return false;
    ClientGetFetchConfig fetchConfig = request.requestProfile().fetchConfig();
    if (fetchConfig == null) {
      LOG.warn("Cannot restart because fetch context is missing for {}", request.identifier);
      return false;
    }
    FreenetURI redirect = resetStateForRestart(disableFilterData, fetchConfig);
    notifyCacheAboutRedirect(redirect);
    try {
      if (request.execution().restart(redirect, fetchConfig.getFilterData())) {
        markRestarted(redirect);
      }
      notifyCacheStartedFlag();
      return true;
    } catch (FetchException e) {
      request.onFailure(e);
      return false;
    }
  }

  /**
   * Checks whether the most recent failure recorded a permanent redirect.
   *
   * <p>The method inspects the cached {@link GetFailedMessage} under the request lock and returns
   * {@code true} when a redirect URI is present. It does not perform any network activity.
   *
   * @return {@code true} when a permanent redirect URI is stored in failure state.
   */
  boolean hasPermRedirect() {
    synchronized (request.persistenceLock()) {
      GetFailedMessage failure = request.state().getFailedMessage();
      return failure != null && failure.redirectURI != null;
    }
  }

  /**
   * Resets the request state and returns any stored redirect URI for the next attempt.
   *
   * <p>The method clears cached failures, progress snapshots, compatibility metadata, and expected
   * hashes. It also marks the request as not started/finished and optionally disables filtering in
   * the detached fetch configuration. The returned redirect, if present, should be applied before
   * restarting.
   *
   * @param disableFilterData true to disable filtering for the next attempt.
   * @param fetchConfig detached fetch configuration bound to the request.
   * @return redirect URI to apply, or {@code null} if none was stored.
   */
  private FreenetURI resetStateForRestart(
      boolean disableFilterData, ClientGetFetchConfig fetchConfig) {
    synchronized (request.persistenceLock()) {
      request.finished = false;
      GetFailedMessage failure = request.state().getFailedMessage();
      FreenetURI redirect = failure == null ? null : failure.redirectURI;
      request.state().setFailedMessage(null);
      request.state().setProgressPending(null);
      request.state().resetCompatibilityMode();
      request.state().clearExpectedHashes();
      request.started = false;
      if (disableFilterData) {
        fetchConfig.setFilterData(false);
      }
      return redirect;
    }
  }

  /**
   * Marks the request as started and applies any redirect URI to the request.
   *
   * <p>This helper updates the request's URI and started flag under the request lock after the
   * underlying getter acknowledges a restart. It does not emit any messages itself.
   *
   * @param redirect redirect URI to apply, or {@code null} to keep the existing URI.
   */
  private void markRestarted(FreenetURI redirect) {
    synchronized (request.persistenceLock()) {
      if (redirect != null) {
        request.uri = redirect;
      }
      request.started = true;
    }
  }

  /**
   * Notifies the request status cache about a restart and optional redirect.
   *
   * <p>This update is used by UI surfaces to reflect a redirected restart promptly. If no cache is
   * configured, the method returns without side effects.
   *
   * @param redirect redirect URI used for the restart, or {@code null} if none.
   */
  private void notifyCacheAboutRedirect(FreenetURI redirect) {
    if (request.client == null) {
      return;
    }
    RequestStatusCache cache = request.client.getRequestStatusCache();
    if (cache != null) {
      cache.updateStarted(request.identifier, redirect);
    }
  }

  /**
   * Updates the request status cache to reflect the started flag.
   *
   * <p>The update is emitted after the getter accepts a restart so observers can display the new
   * attempt. If no cache is configured, the method returns without side effects.
   */
  private void notifyCacheStartedFlag() {
    if (request.client == null) {
      return;
    }
    RequestStatusCache cache = request.client.getRequestStatusCache();
    if (cache != null) {
      cache.updateStarted(request.identifier, true);
    }
  }
}
