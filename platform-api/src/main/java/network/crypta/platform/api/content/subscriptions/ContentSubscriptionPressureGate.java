package network.crypta.platform.api.content.subscriptions;

import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueuePort;

/**
 * Conservative runtime-pressure gate for content subscription polls.
 *
 * <p>The gate uses only stable SPI signals. It does not parse queue HTML and does not expose queue
 * contents in summaries or evidence. Unknown pressure is treated as acceptable because the
 * scheduler's per-tick limits already bound network work. Clear shutdown or unavailable signals are
 * converted into safe subscription statuses so due records back off instead of retrying in a tight
 * loop.
 *
 * <p>The class is intentionally stateless. A scheduler tick may create one assessment and apply it
 * to several due subscriptions, but each assessment is based only on the current queue support and
 * request queue ports. If either port throws while being probed, the gate allows the tick to
 * continue under the scheduler's configured limits rather than treating an unknown signal as a
 * permanent outage.
 */
public final class ContentSubscriptionPressureGate {
  private final QueueSupportPort queueSupportPort;
  private final RequestQueuePort requestQueuePort;

  /**
   * Creates a pressure gate from optional queue SPI dependencies.
   *
   * <p>Both ports are optional because not every runtime embedding exposes the same queue-pressure
   * signals. A {@code null} port means that signal is unknown, not that the scheduler should be
   * disabled.
   *
   * @param queueSupportPort optional queue support port for backend and persistence state
   * @param requestQueuePort optional request queue port for database-killed state
   */
  public ContentSubscriptionPressureGate(
      QueueSupportPort queueSupportPort, RequestQueuePort requestQueuePort) {
    this.queueSupportPort = queueSupportPort;
    this.requestQueuePort = requestQueuePort;
  }

  /**
   * Assesses whether a scheduler tick may attempt due subscription polls.
   *
   * <p>The method blocks only on clear signals: disabled queue backend, queue persistence awaiting
   * a password, queue persistence stopping, or a killed persistence database. It does not inspect
   * request details, parse queue pages, or return raw runtime failures. When a probe throws, the
   * result is allowed so the scheduler remains bounded by its per-tick and per-app limits.
   *
   * @return safe pressure assessment for the current scheduler tick
   */
  public PressureAssessment assess() {
    if (queueSupportPort != null) {
      PressureAssessment supportAssessment = assessQueueSupport();
      if (!supportAssessment.allowed()) {
        return supportAssessment;
      }
    }
    if (requestQueuePort != null) {
      try {
        if (requestQueuePort.isPersistenceDatabaseKilled()) {
          return PressureAssessment.blocked(
              ContentSubscriptionStatus.QUEUE_PRESSURE,
              "queue_pressure",
              "Subscription poll skipped because queue persistence is unavailable.");
        }
      } catch (RuntimeException _) {
        return PressureAssessment.allow();
      }
    }
    return PressureAssessment.allow();
  }

  private PressureAssessment assessQueueSupport() {
    try {
      if (!queueSupportPort.isQueueBackendEnabled()) {
        return PressureAssessment.blocked(
            ContentSubscriptionStatus.RUNTIME_UNAVAILABLE,
            "runtime_unavailable",
            "Subscription poll skipped because the queue backend is unavailable.");
      }
      QueuePersistenceStatusSnapshot status = queueSupportPort.persistenceStatus();
      if (status != null && (status.stopping() || status.awaitingPassword())) {
        return PressureAssessment.blocked(
            ContentSubscriptionStatus.QUEUE_PRESSURE,
            "queue_pressure",
            "Subscription poll skipped because queue persistence is not ready.");
      }
    } catch (RuntimeException _) {
      return PressureAssessment.allow();
    }
    return PressureAssessment.allow();
  }

  /**
   * Result from one pressure-gate assessment.
   *
   * <p>When {@link #allowed()} is {@code true}, the status, error code, and message are {@code
   * null}. When it is {@code false}, scheduler code writes the supplied safe values to still-due
   * subscriptions and schedules a bounded retry. The assessment never carries queue HTML, request
   * bodies, store paths, tokens, or raw exception text.
   *
   * @param allowed whether due polls may proceed during this scheduler tick
   * @param status status to record for skipped due subscriptions, or {@code null}
   * @param errorCode stable error code for skipped subscriptions, or {@code null}
   * @param message safe message for skipped subscriptions, or {@code null}
   */
  public record PressureAssessment(
      boolean allowed, ContentSubscriptionStatus status, String errorCode, String message) {
    static PressureAssessment allow() {
      return new PressureAssessment(true, null, null, null);
    }

    static PressureAssessment blocked(
        ContentSubscriptionStatus status, String errorCode, String message) {
      return new PressureAssessment(false, status, errorCode, message);
    }
  }
}
