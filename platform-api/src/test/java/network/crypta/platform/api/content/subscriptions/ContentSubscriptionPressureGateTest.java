package network.crypta.platform.api.content.subscriptions;

import java.util.List;
import network.crypta.platform.api.networkbudget.RuntimeWorkObservation;
import network.crypta.runtime.spi.ContentFetchObservation;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueuePort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ContentSubscriptionPressureGateTest {
  @Test
  void legacyAssessmentConstructor_whenAllowed_expectUnknownWithoutContention() {
    var assessment = new ContentSubscriptionPressureGate.PressureAssessment(true, null, null, null);

    assertTrue(assessment.allowed());
    assertFalse(assessment.known());
    assertFalse(assessment.contention());
    assertNull(assessment.status());
    assertNull(assessment.errorCode());
    assertNull(assessment.message());
  }

  @Test
  void legacyAssessmentConstructor_whenBlocked_expectKnownAvailabilityDenial() {
    var assessment =
        new ContentSubscriptionPressureGate.PressureAssessment(
            false, ContentSubscriptionStatus.QUEUE_PRESSURE, "queue_pressure", "Unavailable");

    assertFalse(assessment.allowed());
    assertTrue(assessment.known());
    assertFalse(assessment.contention());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
    assertEquals("Unavailable", assessment.message());
  }

  @Test
  void assess_whenOwnerCrossesHighAndLowWater_expectContentionHysteresis() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation()).thenReturn(sample(3), sample(2), sample(1));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 3, 1);

    var high = gate.assess();
    var middle = gate.assess();
    var low = gate.assess();

    assertFalse(high.allowed());
    assertTrue(high.known());
    assertTrue(high.contention());
    assertEquals("content_fetch_contention", high.errorCode());
    assertFalse(middle.allowed());
    assertTrue(low.allowed());
    assertFalse(
        low.known(), "Absent availability ports remain unknown even after contention clears");
  }

  @Test
  void assess_whenOwnerUnavailableOrThrows_expectAllowedButUnknown() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation())
        .thenReturn(ContentFetchObservation.unavailable())
        .thenThrow(new IllegalStateException("private failure"));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 1, 0);

    var missing = gate.assess();
    var failed = gate.assess();

    assertTrue(missing.allowed());
    assertFalse(missing.known());
    assertTrue(failed.allowed());
    assertFalse(failed.known());
  }

  @Test
  void assess_whenPolicyDisabled_expectLegacyAdmissionDespiteOwnerContention() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation()).thenReturn(sample(100));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 0, 0);

    var result = gate.assess();

    assertTrue(result.allowed());
    assertFalse(result.known());
  }

  private static ContentFetchObservation sample(long active) {
    return new ContentFetchObservation(
        true, "00000000-0000-0000-0000-000000000001", 1, 1, active, 10, active, 0, 0, false);
  }

  @Test
  void assess_whenNoPressurePortsArePresent_expectAllowed() {
    ContentSubscriptionPressureGate gate = new ContentSubscriptionPressureGate(null, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertTrue(assessment.allowed());
    assertFalse(assessment.known());
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
    assertFalse(assessment.known());
    assertNull(assessment.status());
    assertNull(assessment.errorCode());
  }

  @ParameterizedTest
  @CsvSource({"-1,0", "1025,0", "1,-1", "1,1", "1,2"})
  void constructor_whenThresholdOutsideDomain_expectRejected(int high, int low) {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentSubscriptionPressureGate(null, null, null, high, low));
  }

  @Test
  void assess_whenEnabledOwnerAbsent_expectAllowedButUnknown() {
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, null, 1, 0);

    var result = gate.assess();

    assertTrue(result.allowed());
    assertFalse(result.known());
    assertEquals(1, gate.configuration().maximumInFlight());
    assertEquals(0, gate.configuration().resumeAtOrBelow());
  }

  @Test
  void assess_whenOwnerReturnsNullOrTruncated_expectUnknownWithoutObservationEvents() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    ContentFetchObservation truncated =
        new ContentFetchObservation(true, "test-epoch", 1, 1, 10, 1, 10, 0, 0, true);
    when(owner.observation()).thenReturn(null, truncated);
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 1, 0);
    RuntimeWorkObservation observation = new RuntimeWorkObservation();
    gate.setObservation(observation);

    var missing = gate.assess();
    var incomplete = gate.assess();

    assertTrue(missing.allowed());
    assertFalse(missing.known());
    assertTrue(incomplete.allowed());
    assertFalse(incomplete.known());
    assertTrue(observation.snapshot().events().isEmpty());
  }

  @Test
  void assess_whenAvailabilityKnownAndContentionClears_expectKnownClearAndCausalEvents() {
    QueueSupportPort support = mock(QueueSupportPort.class);
    when(support.isQueueBackendEnabled()).thenReturn(true);
    when(support.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(false, false, null, null));
    RequestQueuePort requests = mock(RequestQueuePort.class);
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation()).thenReturn(sample(2), sample(0));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(support, requests, owner, 2, 0);
    RuntimeWorkObservation observation = new RuntimeWorkObservation();
    gate.setObservation(observation);

    var blocked = gate.assess();
    var recovered = gate.assess();

    assertFalse(blocked.allowed());
    assertTrue(recovered.allowed());
    assertTrue(recovered.known());
    assertFalse(recovered.contention());
    assertEquals(
        List.of(
            RuntimeWorkObservation.Kind.PRESSURE_CONTENTION_BLOCKED,
            RuntimeWorkObservation.Kind.PRESSURE_KNOWN_CLEAR),
        observation.snapshot().events().stream().map(RuntimeWorkObservation.Event::kind).toList());
  }

  @Test
  void assess_whenUnknownSampleInterruptsContention_expectHysteresisRetainedUntilLowWater() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation())
        .thenReturn(sample(3), ContentFetchObservation.unavailable(), sample(2), sample(1));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 3, 1);

    var blocked = gate.assess();
    var unknown = gate.assess();
    var stillBusy = gate.assess();
    var cleared = gate.assess();

    assertFalse(blocked.allowed());
    assertTrue(unknown.allowed());
    assertFalse(unknown.known());
    assertFalse(stillBusy.allowed());
    assertTrue(stillBusy.contention());
    assertTrue(cleared.allowed());
  }

  @Test
  void assess_whenQueueUnavailable_expectAvailabilityPrecedesContentionProbe() {
    QueueSupportPort support = mock(QueueSupportPort.class);
    ContentFetchPort owner = mock(ContentFetchPort.class);
    RequestQueuePort requests = mock(RequestQueuePort.class);
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(support, requests, owner, 1, 0);

    var result = gate.assess();

    assertFalse(result.allowed());
    assertTrue(result.known());
    assertFalse(result.contention());
    verifyNoInteractions(owner, requests);
  }

  @Test
  void assess_whenQueueStatusMissing_expectAllowedButUnknown() {
    QueueSupportPort support = mock(QueueSupportPort.class);
    when(support.isQueueBackendEnabled()).thenReturn(true);
    RequestQueuePort requests = mock(RequestQueuePort.class);
    ContentSubscriptionPressureGate gate = new ContentSubscriptionPressureGate(support, requests);

    var result = gate.assess();

    assertTrue(result.allowed());
    assertFalse(result.known());
  }
}
