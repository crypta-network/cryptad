package network.crypta.platform.api.content.subscriptions;

import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueuePort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ContentSubscriptionPressureGateTest {
  @Test
  void assess_whenNoPressurePortsArePresent_expectAllowed() {
    ContentSubscriptionPressureGate gate = new ContentSubscriptionPressureGate(null, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertTrue(assessment.allowed());
    assertNull(assessment.status());
    assertNull(assessment.errorCode());
  }

  @Test
  void assess_whenQueueBackendDisabled_expectRuntimeUnavailable() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(false);
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.RUNTIME_UNAVAILABLE, assessment.status());
    assertEquals("runtime_unavailable", assessment.errorCode());
  }

  @Test
  void assess_whenQueuePersistenceIsAwaitingPassword_expectQueuePressure() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(true, false, null, null));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
  }

  @Test
  void assess_whenQueuePersistenceIsStopping_expectQueuePressure() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(false, true, null, null));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
  }

  @Test
  void assess_whenQueuePersistenceDatabaseIsKilled_expectQueuePressure() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(false, false, null, null));
    RequestQueuePort requestQueuePort = mock(RequestQueuePort.class);
    when(requestQueuePort.isPersistenceDatabaseKilled()).thenReturn(true);
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, requestQueuePort);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
  }

  @Test
  void assess_whenPressurePortsThrow_expectAllowedWithConservativeTickLimits() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenThrow(new IllegalStateException("boom"));
    RequestQueuePort requestQueuePort = mock(RequestQueuePort.class);
    when(requestQueuePort.isPersistenceDatabaseKilled())
        .thenThrow(new IllegalStateException("boom"));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, requestQueuePort);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertTrue(assessment.allowed());
    assertNull(assessment.status());
    assertNull(assessment.errorCode());
  }
}
